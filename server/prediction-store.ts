/**
 * Persist TGNN inference results to PostgreSQL and fan-out via WebSocket/Redis.
 * Shared by dataset replay API routes and live capture sync.
 */

import { eq } from "drizzle-orm";
import { db } from "./db";
import { alerts, predictions, mlModels } from "@shared/schema";
import { broadcastEvent } from "./websocket";
import { publish, cacheDel } from "./redis";

const ATTACK_STAGES = [
  "normal",
  "reconnaissance",
  "scanning",
  "credential_attack",
  "privilege_escalation",
  "lateral_movement",
  "persistence",
  "data_exfiltration",
  "impact",
] as const;

type AttackStage = (typeof ATTACK_STAGES)[number];
type ThreatLevel = "critical" | "high" | "medium" | "low" | "info";

export type InferenceResult = {
  attack_type: string;
  attack_stage: string;
  predicted_next_stage?: string;
  threat_level: string;
  probability: number;
  confidence: number;
  risk_score: number;
  is_compromised: boolean;
  mitre_tactic?: string;
  mitre_technique?: string;
  explanation?: Record<string, unknown>;
  model?: Record<string, unknown>;
};

function normalizeStage(stage: string | undefined | null): AttackStage {
  if (!stage) return "normal";
  const normalized = stage.toLowerCase().replace(/[\s-]+/g, "_");
  return (ATTACK_STAGES as readonly string[]).includes(normalized)
    ? (normalized as AttackStage)
    : "normal";
}

function normalizeThreatLevel(level: string | undefined | null): ThreatLevel {
  const allowed: ThreatLevel[] = ["critical", "high", "medium", "low", "info"];
  const value = (level || "medium").toLowerCase() as ThreatLevel;
  return allowed.includes(value) ? value : "medium";
}

export async function ensureActiveModel(result: InferenceResult): Promise<string | undefined> {
  const existing = await db
    .select()
    .from(mlModels)
    .where(eq(mlModels.isActive, true))
    .limit(1);

  if (existing.length) {
    return existing[0].id;
  }

  const archRaw = String(result.model?.architecture || "gat");
  const allowedArch = mlModels.architecture.enumValues;
  const architecture = (allowedArch as readonly string[]).includes(archRaw)
    ? (archRaw as typeof allowedArch[number])
    : "gat";

  const [created] = await db
    .insert(mlModels)
    .values({
      name: "TGNN Production",
      version: "1.0.0",
      architecture,
      filePath: "ai/models/tgnn_model.pt",
      hyperparameters: {
        source: "phase2_checkpoint",
        dataset_id: result.model?.dataset_id,
        trained_at: result.model?.trained_at,
      },
      isActive: true,
    })
    .returning();

  return created.id;
}

async function invalidateDashboardCaches() {
  await cacheDel("dashboard:metrics");
  await cacheDel("dashboard:metrics:v2");
  await cacheDel("attack-stage:summary");
}

/** True when a live AI prediction contains enough data to store in PostgreSQL. */
export function isPersistableLivePrediction(
  pred: Record<string, unknown> | undefined | null,
): boolean {
  if (!pred) return false;
  if (pred.message === "Prediction unavailable") return false;
  const attackType = pred.attack_type;
  if (attackType == null || attackType === "") return false;
  if (typeof pred.confidence !== "number" || Number.isNaN(pred.confidence)) return false;
  if (typeof pred.risk_score !== "number" || Number.isNaN(pred.risk_score)) return false;
  return true;
}

/** Map snake_case live inference payload to the shared InferenceResult shape. */
export function livePredictionToInferenceResult(pred: Record<string, unknown>): InferenceResult {
  return {
    attack_type: String(pred.attack_type),
    attack_stage: String(pred.attack_stage ?? "normal"),
    predicted_next_stage: pred.predicted_next_stage
      ? String(pred.predicted_next_stage)
      : undefined,
    threat_level: String(pred.threat_level ?? "low"),
    probability: Number(pred.probability ?? 0),
    confidence: Number(pred.confidence),
    risk_score: Number(pred.risk_score),
    is_compromised: Boolean(pred.is_compromised),
    mitre_tactic: pred.mitre_tactic ? String(pred.mitre_tactic) : undefined,
    mitre_technique: pred.mitre_technique ? String(pred.mitre_technique) : undefined,
    explanation: (pred.explanation as Record<string, unknown> | undefined) ?? {},
    model: (pred.model as Record<string, unknown> | undefined) ?? {},
  };
}

export async function persistPrediction(
  result: InferenceResult,
  features: Record<string, unknown> | undefined,
  opts?: {
    modelId?: string;
    graphSnapshotId?: string;
    userId?: string;
    ipAddress?: string;
    auditLog?: (args: {
      userId: string;
      action: string;
      resource: string;
      resourceId: string;
      ipAddress?: string;
    }) => Promise<void>;
  },
) {
  const attackStage = normalizeStage(result.attack_stage);
  const predictedNextStage = normalizeStage(result.predicted_next_stage);
  const threatLevel = normalizeThreatLevel(result.threat_level);
  const modelId = opts?.modelId ?? (await ensureActiveModel(result));

  const [prediction] = await db
    .insert(predictions)
    .values({
      modelId,
      attackType: result.attack_type,
      attackStage,
      predictedNextStage,
      threatLevel,
      probability: result.probability,
      confidence: result.confidence,
      riskScore: result.risk_score,
      isCompromised: Boolean(result.is_compromised),
      explanation: result.explanation ?? {},
      rawFeatures: features ?? {},
      graphSnapshotId: opts?.graphSnapshotId,
    })
    .returning();

  let alert = null;
  if (threatLevel !== "low" && threatLevel !== "info") {
    const [createdAlert] = await db
      .insert(alerts)
      .values({
        title: `${result.attack_type} detected`,
        description: `Attack stage: ${attackStage}. Confidence: ${(result.confidence * 100).toFixed(1)}%`,
        severity: threatLevel,
        attackType: result.attack_type,
        attackStage,
        mitreTactic: result.mitre_tactic,
        mitreTechnique: result.mitre_technique,
        sourceIp: typeof features?.src_ip === "string" ? features.src_ip : undefined,
        targetIp: typeof features?.dst_ip === "string" ? features.dst_ip : undefined,
        protocol: typeof features?.protocol === "string" ? features.protocol : undefined,
        predictionId: prediction.id,
        metadata: {
          model: result.model ?? {},
          source: features?.source ?? "inference",
        },
      })
      .returning();

    alert = createdAlert;
    broadcastEvent("alert", createdAlert);
    await publish("gnn-ids:events", {
      type: "alert",
      payload: createdAlert,
      timestamp: new Date().toISOString(),
    });
  }

  if (opts?.userId && opts.auditLog) {
    await opts.auditLog({
      userId: opts.userId,
      action: "predict",
      resource: "predictions",
      resourceId: prediction.id,
      ipAddress: opts.ipAddress,
    });
  }

  await invalidateDashboardCaches();

  broadcastEvent("prediction", prediction);
  await publish("gnn-ids:events", {
    type: "prediction",
    payload: prediction,
    timestamp: new Date().toISOString(),
  });

  return { prediction, alert };
}
