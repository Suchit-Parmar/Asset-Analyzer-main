/**
 * Express API routes for the GNN-IDS SOC platform.
 * Phase 3 inference persistence + Phase 4/5 dashboard data endpoints.
 * Contract: do not change path shapes without updating the React api client.
 */
import { Router } from "express";
import os from "os";
import dns from "dns/promises";
import { desc, eq, and, gte, sql } from "drizzle-orm";
import multer from "multer";
import { db } from "../db";
import {
  alerts, predictions, riskScores, networkNodes, networkEdges,
  attackGraphs, datasets, trainingRuns, mlModels, reports,
  auditLogs, systemLogs, users,
} from "@shared/schema";
import { websiteDisplayName } from "@shared/host-identity";
import { authenticate, requirePermission, createAuditLog, PERMISSIONS, type AuthenticatedRequest } from "../auth";
import { aiService } from "../ai-client";
import { broadcastEvent } from "../websocket";
import { publish } from "../redis";
import { cacheGet, cacheSet } from "../redis";
import { resolveDatasetRef } from "../dataset-resolve";
import { getApiLogs, pushApiLog } from "../log-store";
import { startLivePoller, stopLivePoller } from "../live-sync";
import { persistPrediction, ensureActiveModel, type InferenceResult } from "../prediction-store";

const router = Router();
const upload = multer({ dest: "uploads/", limits: { fileSize: 500 * 1024 * 1024 } });

/** Structured backend log helper (Phase 13 — also feeds admin API log viewer). */
function apiLog(scope: string, message: string, meta?: Record<string, unknown>, level: "info" | "warn" | "error" = "info") {
  const stamp = new Date().toISOString();
  if (meta) {
    console.log(`[${stamp}] [api:${scope}] ${message}`, meta);
  } else {
    console.log(`[${stamp}] [api:${scope}] ${message}`);
  }
  pushApiLog(scope, message, meta, level);

  if (level === "error" || level === "warn") {
    void db.insert(systemLogs).values({
      level,
      service: "express-api",
      message: `[${scope}] ${message}`,
      metadata: meta ?? {},
    }).catch((err) => {
      console.error("[apiLog] failed to persist system log", err);
    });
  }
}

function expressSystemMetrics() {
  const total = os.totalmem();
  const free = os.freemem();
  const used = total - free;
  const proc = process.memoryUsage();
  return {
    cpu_count: os.cpus().length,
    load_avg: os.loadavg(),
    memory_total_bytes: total,
    memory_used_bytes: used,
    memory_percent: Math.round((used / Math.max(total, 1)) * 1000) / 10,
    process_rss_bytes: proc.rss,
    process_heap_bytes: proc.heapUsed,
    uptime_sec: Math.round(process.uptime()),
    platform: process.platform,
  };
}

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

// ---------------------------------------------------------------------------
// Public routes (no JWT). Must be registered BEFORE router.use(authenticate).
// Login/register live on /api/auth/* (auth.routes.ts) and are also public.
// ---------------------------------------------------------------------------

router.get("/health", async (_req, res) => {
  let aiHealth: Record<string, unknown> = { status: "unavailable", model_loaded: false };
  try {
    aiHealth = await aiService.health() as Record<string, unknown>;
  } catch {
    // AI service down
  }

  res.json({
    status: "healthy",
    ai: aiHealth,
    api: expressSystemMetrics(),
    timestamp: new Date().toISOString(),
  });
});

router.get("/dashboard/metrics", async (_req, res) => {
  const cacheKey = "dashboard:metrics:v2";
  const cached = await cacheGet<Record<string, unknown>>(cacheKey);
  if (cached) {
    res.json(cached);
    return;
  }

  // Open / severity totals = all currently open alerts (not only last 24h).
  // The Overview Alert Stream and Threat Posture must reflect open SOC alerts
  // even when they were created earlier than the rolling 24h window.
  const [alertStats] = await db
    .select({
      total: sql<number>`count(*)::int`,
      critical: sql<number>`count(*) filter (where severity = 'critical' and status = 'open')::int`,
      high: sql<number>`count(*) filter (where severity = 'high' and status = 'open')::int`,
      open: sql<number>`count(*) filter (where status = 'open')::int`,
      open24h: sql<number>`count(*) filter (where status = 'open' and created_at >= now() - interval '24 hours')::int`,
      total24h: sql<number>`count(*) filter (where created_at >= now() - interval '24 hours')::int`,
    })
    .from(alerts);

  const [nodeStats] = await db
    .select({
      total: sql<number>`count(*)::int`,
      compromised: sql<number>`count(*) filter (where ${networkNodes.status} = 'compromised')::int`,
      suspicious: sql<number>`count(*) filter (where ${networkNodes.status} = 'suspicious')::int`,
      avgRisk: sql<number>`coalesce(avg(${networkNodes.riskScore}), 0)`,
    })
    .from(networkNodes);

  let aiMetrics = {};
  try {
    aiMetrics = await aiService.getMetrics();
  } catch {
    aiMetrics = {};
  }

  const metrics = {
    alerts: alertStats,
    network: nodeStats,
    ai: aiMetrics,
    timestamp: new Date().toISOString(),
  };

  await cacheSet(cacheKey, metrics, 10);
  res.json(metrics);
});

router.get("/model/info", async (_req, res) => {
  try {
    const info = await aiService.modelInfo();
    res.json(info);
  } catch (error) {
    res.status(503).json({ error: error instanceof Error ? error.message : "AI model unavailable" });
  }
});

// Protected routes below this line require a valid Bearer JWT.
router.use(authenticate);

router.post("/predict", requirePermission(PERMISSIONS.PREDICT), async (req: AuthenticatedRequest, res) => {
  try {
    const { features, graphSnapshot, graphSnapshotId } = req.body ?? {};
    if (!features && !graphSnapshot) {
      res.status(400).json({ error: "Provide features and/or graphSnapshot" });
      return;
    }

    apiLog("predict", "inference request", { userId: req.user?.userId, hasGraph: Boolean(graphSnapshot) });
    const result = (await aiService.predict(features ?? {}, graphSnapshot)) as InferenceResult;
    const { prediction, alert } = await persistPrediction(result, features, {
      graphSnapshotId,
      userId: req.user!.userId,
      ipAddress: req.ip,
      auditLog: createAuditLog,
    });

    apiLog("predict", "stored prediction", {
      predictionId: prediction.id,
      attackType: result.attack_type,
      threatLevel: result.threat_level,
      alertId: alert?.id ?? null,
    });

    res.json({
      ...result,
      id: prediction.id,
      alertId: alert?.id ?? null,
      stored: true,
    });
  } catch (error) {
    apiLog("predict", "failed", { error: error instanceof Error ? error.message : String(error) });
    res.status(500).json({ error: error instanceof Error ? error.message : "Prediction failed" });
  }
});

router.post("/predict/batch", requirePermission(PERMISSIONS.PREDICT), async (req: AuthenticatedRequest, res) => {
  try {
    const { records } = req.body ?? {};
    if (!Array.isArray(records) || records.length === 0) {
      res.status(400).json({ error: "records must be a non-empty array" });
      return;
    }

    apiLog("predict/batch", "batch inference", { count: records.length, userId: req.user?.userId });
    const batch = await aiService.predictBatch(records);
    const inferenceResults = (batch.predictions ?? batch) as InferenceResult[];
    const modelId = await ensureActiveModel(inferenceResults[0]);

    const stored = [];
    for (let i = 0; i < inferenceResults.length; i++) {
      const record = records[i] ?? {};
      const features =
        (record.features as Record<string, unknown> | undefined) ??
        (record as Record<string, unknown>);
      const { prediction, alert } = await persistPrediction(inferenceResults[i], features, {
        modelId,
        userId: i === 0 ? req.user!.userId : undefined,
        ipAddress: req.ip,
        auditLog: createAuditLog,
      });
      stored.push({
        ...inferenceResults[i],
        id: prediction.id,
        alertId: alert?.id ?? null,
      });
    }

    apiLog("predict/batch", "batch stored", { count: stored.length });
    res.json({ predictions: stored, count: stored.length });
  } catch (error) {
    apiLog("predict/batch", "failed", { error: error instanceof Error ? error.message : String(error) });
    res.status(500).json({ error: error instanceof Error ? error.message : "Batch prediction failed" });
  }
});

router.post("/predict/dataset", requirePermission(PERMISSIONS.PREDICT), async (req: AuthenticatedRequest, res) => {
  try {
    const { datasetId = "cicids2017", windowSeconds = 30, maxRows = 5000 } = req.body ?? {};
    const dataset = await resolveDatasetRef(datasetId);
    apiLog("predict/dataset", "dataset inference", {
      requested: datasetId,
      uuid: dataset.id,
      source: dataset.source,
      windowSeconds,
      maxRows,
      userId: req.user?.userId,
    });
    const result = (await aiService.predictFromDataset(
      dataset.source,
      windowSeconds,
      maxRows,
    )) as InferenceResult & { graph?: Record<string, unknown>; dataset_id?: string };

    const { prediction, alert } = await persistPrediction(
      result,
      {
        dataset_id: dataset.source,
        dataset_uuid: dataset.id,
        source: "predict_from_dataset",
        graph_summary: result.graph ?? {},
      },
      {
        userId: req.user!.userId,
        ipAddress: req.ip,
        auditLog: createAuditLog,
      },
    );

    apiLog("predict/dataset", "stored", {
      predictionId: prediction.id,
      attackType: result.attack_type,
      alertId: alert?.id ?? null,
    });

    res.json({
      ...result,
      id: prediction.id,
      alertId: alert?.id ?? null,
      stored: true,
      dataset: { id: dataset.id, source: dataset.source, name: dataset.name },
    });
  } catch (error) {
    apiLog("predict/dataset", "failed", { error: error instanceof Error ? error.message : String(error) });
    res.status(500).json({ error: error instanceof Error ? error.message : "Dataset prediction failed" });
  }
});

router.post("/model/reload", requirePermission(PERMISSIONS.TRAIN), async (_req, res) => {
  try {
    const info = await aiService.reloadModel();
    res.json(info);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Model reload failed" });
  }
});

router.get("/alerts", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  const severity = req.query.severity as string | undefined;
  const status = req.query.status as string | undefined;
  const limit = Math.min(parseInt(req.query.limit as string || "50", 10), 200);

  const conditions = [];
  if (severity) conditions.push(eq(alerts.severity, severity as typeof alerts.severity.enumValues[number]));
  if (status) conditions.push(eq(alerts.status, status as typeof alerts.status.enumValues[number]));

  const result = await db
    .select()
    .from(alerts)
    .where(conditions.length ? and(...conditions) : undefined)
    .orderBy(desc(alerts.createdAt))
    .limit(limit);

  res.json({ alerts: result, count: result.length });
});

router.patch("/alerts/:id", requirePermission(PERMISSIONS.MANAGE_ALERTS), async (req: AuthenticatedRequest, res) => {
  const { status } = req.body;
  const [updated] = await db
    .update(alerts)
    .set({
      status,
      assignedTo: req.user!.userId,
      acknowledgedAt: status === "investigating" ? new Date() : undefined,
      resolvedAt: status === "resolved" ? new Date() : undefined,
      updatedAt: new Date(),
    })
    .where(eq(alerts.id, req.params.id))
    .returning();

  if (!updated) {
    res.status(404).json({ error: "Alert not found" });
    return;
  }
  res.json(updated);
});

router.get("/network/nodes", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  const status = req.query.status as string | undefined;
  const limit = Math.min(parseInt(req.query.limit as string || "100", 10), 500);

  const result = await db
    .select()
    .from(networkNodes)
    .where(status ? eq(networkNodes.status, status as typeof networkNodes.status.enumValues[number]) : undefined)
    .orderBy(desc(networkNodes.riskScore))
    .limit(limit);

  res.json({ nodes: result, count: result.length });
});

router.get("/network/edges", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit as string || "200", 10), 1000);
  const result = await db
    .select()
    .from(networkEdges)
    .orderBy(desc(networkEdges.timestamp))
    .limit(limit);

  res.json({ edges: result, count: result.length });
});

router.get("/network/topology", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (_req, res) => {
  const nodes = await db.select().from(networkNodes).orderBy(desc(networkNodes.riskScore)).limit(100);
  const nodeIds = new Set(nodes.map((n) => n.id));
  const edges = nodeIds.size
    ? await db.select().from(networkEdges).orderBy(desc(networkEdges.timestamp)).limit(300)
    : [];

  res.json({
    nodes: nodes.map((n) => {
      const isWebsite =
        (n.vendor ?? "").toLowerCase().includes("website") ||
        (n.externalId ?? "").startsWith("website:");
      const host = n.hostname || (isWebsite ? n.ipAddress : null);
      return {
        id: n.id,
        label: n.hostname || n.ipAddress,
        ip: n.ipAddress,
        type: n.nodeType,
        status: n.status,
        risk: n.riskScore,
        vendor: n.vendor,
        hostname: host,
        websiteName: isWebsite ? websiteDisplayName(host) : null,
        packets: n.packets,
        bytes: n.bytes,
        connectionCount: n.connectionCount,
        firstSeen: n.createdAt,
        lastSeen: n.lastSeenAt,
      };
    }),
    edges: edges
      .filter((e) => nodeIds.has(e.sourceNodeId) && nodeIds.has(e.targetNodeId))
      .map((e) => ({
        id: e.id,
        source: e.sourceNodeId,
        target: e.targetNodeId,
        protocol: e.protocol,
        weight: e.weight,
        packetCount: e.packetCount,
        timestamp: e.timestamp,
      })),
  });
});

router.post("/network/websites", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req: AuthenticatedRequest, res) => {
  try {
    const rawUrl = typeof req.body?.url === "string" ? req.body.url.trim() : "";
    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      res.status(400).json({ error: "Invalid URL" });
      return;
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      res.status(400).json({ error: "Only http(s) URLs are allowed" });
      return;
    }

    const hostname = parsed.hostname.toLowerCase();
    const websiteName = websiteDisplayName(hostname);
    const externalId = `website:${hostname}`;

    // Optional passive DNS A/AAAA lookup for display only (user-initiated URL).
    let resolvedIp: string | null = null;
    try {
      const lookup = await dns.lookup(hostname, { all: false });
      resolvedIp = lookup.address;
    } catch {
      resolvedIp = null;
    }

    const existing = await db
      .select()
      .from(networkNodes)
      .where(eq(networkNodes.externalId, externalId))
      .limit(1);

    if (existing[0]) {
      const [updated] = await db
        .update(networkNodes)
        .set({
          hostname,
          vendor: "website",
          ipAddress: resolvedIp || existing[0].ipAddress || hostname,
          os: "external-host",
          department: "external",
          features: {
            demo_observable: 1,
            scheme: parsed.protocol === "https:" ? 1 : 0,
          },
          lastSeenAt: new Date(),
          updatedAt: new Date(),
        })
        .where(eq(networkNodes.id, existing[0].id))
        .returning();

      res.json({
        node: updated,
        websiteName,
        note: "Website already present — identity refreshed (observable metadata only).",
      });
      return;
    }

    const [created] = await db
      .insert(networkNodes)
      .values({
        externalId,
        ipAddress: resolvedIp || hostname,
        hostname,
        nodeType: "server",
        status: "online",
        vendor: "website",
        os: "external-host",
        department: "external",
        riskScore: 0.15,
        packets: 0,
        bytes: 0,
        connectionCount: 0,
        features: {
          demo_observable: 1,
          scheme: parsed.protocol === "https:" ? 1 : 0,
        },
      })
      .returning();

    await createAuditLog({
      userId: req.user?.userId,
      action: "website_added",
      resource: "network_node",
      resourceId: created.id,
      details: { hostname, websiteName, url: rawUrl, resolvedIp, mode: "observable_only" },
      ipAddress: req.ip,
    });

    res.status(201).json({
      node: created,
      websiteName,
      note: "External website added as an observable graph entity. No port scan or exploitation was performed.",
    });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Failed to add website" });
  }
});

// --- LIVE authorized local capture (feeds existing graph/GNN; replay unchanged) ---

router.get("/live/interfaces", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (_req, res) => {
  try {
    const data = await aiService.liveInterfaces();
    res.json(data);
  } catch (error) {
    res.status(503).json({
      error: error instanceof Error ? error.message : "Live interfaces unavailable",
      interfaces: [],
    });
  }
});

router.post("/live/start", requirePermission(PERMISSIONS.PREDICT), async (req: AuthenticatedRequest, res) => {
  try {
    const interfaceName = typeof req.body?.interface === "string" ? req.body.interface.trim() : "";
    const windowSeconds = Number(req.body?.windowSeconds ?? req.body?.window_seconds ?? 5);
    if (!interfaceName) {
      res.status(400).json({ error: "interface is required" });
      return;
    }
    const data = await aiService.liveStart(interfaceName, windowSeconds);
    startLivePoller(2000);
    await createAuditLog({
      userId: req.user?.userId,
      action: "live_start",
      resource: "live_capture",
      details: { interface: interfaceName, windowSeconds, mode: "authorized_local_only" },
      ipAddress: req.ip,
    });
    res.json(data);
  } catch (error) {
    const err = error as Error & { status?: number };
    const status = err.status === 403 ? 403 : err.status === 409 ? 409 : err.status === 400 ? 400 : 500;
    res.status(status).json({
      error: err.message || "Failed to start live detection",
      message: err.message,
    });
  }
});

router.post("/live/stop", requirePermission(PERMISSIONS.PREDICT), async (req: AuthenticatedRequest, res) => {
  try {
    stopLivePoller();
    const data = await aiService.liveStop();
    await createAuditLog({
      userId: req.user?.userId,
      action: "live_stop",
      resource: "live_capture",
      details: { mode: "authorized_local_only" },
      ipAddress: req.ip,
    });
    res.json(data);
  } catch (error) {
    stopLivePoller();
    res.status(500).json({ error: error instanceof Error ? error.message : "Failed to stop live detection" });
  }
});

router.get("/live/status", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (_req, res) => {
  try {
    const data = await aiService.liveStatus();
    res.json({
      ...data,
      label_live: "LIVE = Authorized Local Network Monitoring",
      label_replay: "DATASET REPLAY = Historical/Demo Traffic",
    });
  } catch (error) {
    res.status(503).json({
      mode: "live",
      status: "error",
      running: false,
      error: error instanceof Error ? error.message : "Live status unavailable",
      message: "Backend disconnected or AI service unavailable",
      stats: { packets: 0, flows: 0, active_nodes: 0, connections: 0, threats: 0, suspicious_nodes: 0 },
      snapshot: null,
      prediction: null,
    });
  }
});

router.get("/live/history", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (_req, res) => {
  try {
    const data = await aiService.liveHistory();
    res.json(data);
  } catch (error) {
    res.status(503).json({ windows: [], count: 0, error: error instanceof Error ? error.message : "Unavailable" });
  }
});

router.get("/risk/scores", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  const entityType = req.query.entity_type as string | undefined;
  const limit = Math.min(parseInt(req.query.limit as string || "50", 10), 200);

  const result = await db
    .select()
    .from(riskScores)
    .where(entityType ? eq(riskScores.entityType, entityType) : undefined)
    .orderBy(desc(riskScores.computedAt))
    .limit(limit);

  res.json({ scores: result });
});

router.post("/risk/compute", requirePermission(PERMISSIONS.PREDICT), async (req, res) => {
  try {
    const { entityType, entityId, graphSnapshot } = req.body;
    const result = await aiService.computeRisk(entityType, entityId, graphSnapshot);

    const [score] = await db.insert(riskScores).values({
      entityType,
      entityId,
      entityName: result.entity_name,
      nodeRisk: result.node_risk,
      subnetRisk: result.subnet_risk,
      departmentRisk: result.department_risk,
      organizationRisk: result.organization_risk,
      propagationRisk: result.propagation_risk,
      businessImpact: result.business_impact,
      factors: result.factors,
    }).returning();

    broadcastEvent("risk_update", score);
    res.json(score);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Risk computation failed" });
  }
});

router.post("/explain", requirePermission(PERMISSIONS.PREDICT), async (req, res) => {
  try {
    const { nodeId, graphSnapshot } = req.body;
    const result = await aiService.explain(nodeId, graphSnapshot);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Explainability failed" });
  }
});

router.get("/predictions", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit as string || "50", 10), 200);
  const result = await db.select().from(predictions).orderBy(desc(predictions.createdAt)).limit(limit);
  res.json({ predictions: result });
});

const ATTACK_STAGE_ORDER = [
  "reconnaissance", "scanning", "credential_attack", "privilege_escalation",
  "lateral_movement", "persistence", "data_exfiltration", "impact", "normal",
] as const;

const STAGE_DESCRIPTIONS: Record<string, string> = {
  reconnaissance: "Initial host and network discovery activity detected in recent TGNN predictions.",
  scanning: "Port and service enumeration patterns observed across monitored nodes.",
  credential_attack: "Brute-force or credential stuffing signals elevated in the prediction stream.",
  privilege_escalation: "Indicators suggest attempts to elevate access on compromised hosts.",
  lateral_movement: "Cross-segment communication patterns consistent with lateral movement.",
  persistence: "Sustained foothold behavior detected on one or more network entities.",
  data_exfiltration: "Outbound transfer anomalies flagged by temporal graph analysis.",
  impact: "Destructive or service-disruption activity predicted at high confidence.",
  normal: "Baseline benign traffic profile within expected operational bounds.",
};

router.get("/attack-stage", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (_req, res) => {
  const cacheKey = "attack-stage:summary";
  const cached = await cacheGet<Record<string, unknown>>(cacheKey);
  if (cached) {
    res.json(cached);
    return;
  }

  const recentPredictions = await db
    .select()
    .from(predictions)
    .where(gte(predictions.createdAt, sql`now() - interval '24 hours'`))
    .orderBy(desc(predictions.createdAt))
    .limit(500);

  const stageCounts: Record<string, { count: number; probSum: number; entities: Set<string> }> = {};
  for (const stage of ATTACK_STAGE_ORDER) {
    stageCounts[stage] = { count: 0, probSum: 0, entities: new Set() };
  }

  let maliciousCount = 0;
  for (const pred of recentPredictions) {
    const stage = pred.attackStage;
    if (stageCounts[stage]) {
      stageCounts[stage].count += 1;
      stageCounts[stage].probSum += pred.probability;
    }
    if (pred.attackStage !== "normal" && pred.threatLevel !== "low" && pred.threatLevel !== "info") {
      maliciousCount += 1;
    }
    const features = pred.rawFeatures as Record<string, unknown> | null;
    const srcIp = features?.src_ip ?? features?.source_ip;
    const dstIp = features?.dst_ip ?? features?.dest_ip;
    if (typeof srcIp === "string") stageCounts[stage]?.entities.add(srcIp);
    if (typeof dstIp === "string") stageCounts[stage]?.entities.add(dstIp);
  }

  const total = Math.max(recentPredictions.length, 1);
  const attackStages = ATTACK_STAGE_ORDER.filter((s) => s !== "normal").map((stage) => {
    const data = stageCounts[stage];
    const probability = data.count > 0
      ? Math.min(0.99, data.probSum / data.count)
      : 0.05;
    return {
      stage: stage.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
      stageKey: stage,
      probability,
      entities: Array.from(data.entities).slice(0, 5),
      description: STAGE_DESCRIPTIONS[stage],
    };
  }).sort((a, b) => b.probability - a.probability);

  const nodes = await db.select().from(networkNodes).orderBy(desc(networkNodes.riskScore)).limit(100);
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  const edges = await db
    .select()
    .from(networkEdges)
    .orderBy(desc(networkEdges.timestamp))
    .limit(50);

  const attackPaths = edges.map((e) => {
    const src = nodeMap.get(e.sourceNodeId);
    const tgt = nodeMap.get(e.targetNodeId);
    return {
      source: src?.ipAddress ?? e.sourceNodeId,
      target: tgt?.ipAddress ?? e.targetNodeId,
      type: e.protocol.toUpperCase(),
      weight: e.weight,
      timestamp: e.timestamp.toISOString(),
    };
  });

  const avgConfidence = recentPredictions.length
    ? recentPredictions.reduce((sum, p) => sum + p.confidence, 0) / recentPredictions.length
    : 0;

  const summary = {
    attackStages,
    edges: attackPaths,
    stats: {
      totalPredictions: recentPredictions.length,
      maliciousShare: maliciousCount / total,
      avgConfidence,
      leadStage: attackStages[0] ?? null,
      stageCount: attackStages.filter((s) => s.probability > 0.1).length,
    },
    timestamp: new Date().toISOString(),
  };

  await cacheSet(cacheKey, summary, 5);
  res.json(summary);
});

router.get("/explain/latest", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (_req, res) => {
  const nodes = await db.select().from(networkNodes).orderBy(desc(networkNodes.riskScore)).limit(100);
  if (!nodes.length) {
    res.status(404).json({ error: "No network nodes available for explainability" });
    return;
  }

  const nodeIds = nodes.map((n) => n.id);
  const edges = nodeIds.length
    ? await db.select().from(networkEdges).orderBy(desc(networkEdges.timestamp)).limit(300)
    : [];

  const targetNode = nodes[0];
  const graphSnapshot = {
    nodes: nodes.map((n, i) => ({
      id: n.externalId || n.id,
      ip: n.ipAddress,
      label: n.hostname || n.ipAddress,
      type: n.nodeType,
      risk: n.riskScore,
      node_index: i,
    })),
    edges: edges
      .filter((e) => nodeIds.includes(e.sourceNodeId) && nodeIds.includes(e.targetNodeId))
      .map((e, i) => {
        const srcIdx = nodes.findIndex((n) => n.id === e.sourceNodeId);
        const tgtIdx = nodes.findIndex((n) => n.id === e.targetNodeId);
        return {
          source: nodes[srcIdx]?.ipAddress ?? e.sourceNodeId,
          target: nodes[tgtIdx]?.ipAddress ?? e.targetNodeId,
          protocol: e.protocol,
          packets: e.packetCount ?? 1,
          bytes: (e.features as Record<string, number> | null)?.bytes ?? 1000,
          edge_index: i,
        };
      }),
  };

  try {
    const result = await aiService.explain(targetNode.externalId || targetNode.ipAddress, graphSnapshot);
    res.json({ ...result, graphSnapshot, targetNodeId: targetNode.id });
  } catch (error) {
    const storedExplanation = await db
      .select({ explanation: predictions.explanation, attackType: predictions.attackType, attackStage: predictions.attackStage })
      .from(predictions)
      .where(sql`${predictions.explanation} is not null`)
      .orderBy(desc(predictions.createdAt))
      .limit(1);

    if (storedExplanation[0]?.explanation) {
      res.json({
        node_id: targetNode.ipAddress,
        target_node: { ip: targetNode.ipAddress, label: targetNode.hostname },
        reasoning: (storedExplanation[0].explanation as Record<string, unknown>)?.reasoning
          ?? `TGNN classified recent activity as ${storedExplanation[0].attackType} at stage ${storedExplanation[0].attackStage}.`,
        node_importance: nodes.slice(0, 8).map((n, i) => ({
          node_index: i,
          ip: n.ipAddress,
          label: n.hostname || n.ipAddress,
          importance: n.riskScore,
        })),
        edge_importance: graphSnapshot.edges.slice(0, 8).map((e, i) => ({
          edge_index: i,
          source: e.source,
          target: e.target,
          importance: 0.5,
        })),
        graphSnapshot,
        targetNodeId: targetNode.id,
        fallback: true,
      });
      return;
    }

    res.status(503).json({ error: error instanceof Error ? error.message : "Explainability unavailable" });
  }
});

/**
 * Sync a non-terminal DB run with the live AI-service status.
 * Training executes on a FastAPI background thread; without this sync a run
 * that fails there (e.g. dataset loader error) stays "running" in PostgreSQL
 * forever and the UI never surfaces the failure.
 */
async function syncTrainingRun(run: typeof trainingRuns.$inferSelect) {
  if (run.status !== "queued" && run.status !== "running") return run;

  let ai: Record<string, unknown> | null;
  try {
    ai = (await aiService.getTrainingStatus(run.id)) as Record<string, unknown> | null;
  } catch {
    return run; // AI service unreachable — keep DB state
  }

  if (ai === null) {
    // Run is unknown to the AI service (in-memory state lost on restart).
    const [orphaned] = await db
      .update(trainingRuns)
      .set({
        status: "failed",
        completedAt: new Date(),
        errorMessage: "Training run lost (AI service restarted before completion)",
      })
      .where(eq(trainingRuns.id, run.id))
      .returning();
    return orphaned ?? run;
  }

  const aiStatus = String(ai.status ?? "");
  const updates: Partial<typeof trainingRuns.$inferInsert> = {
    currentEpoch: Number(ai.current_epoch ?? run.currentEpoch),
    trainLoss: (ai.train_loss as number | null) ?? run.trainLoss,
    valLoss: (ai.val_loss as number | null) ?? run.valLoss,
    trainAccuracy: (ai.train_accuracy as number | null) ?? run.trainAccuracy,
    valAccuracy: (ai.val_accuracy as number | null) ?? run.valAccuracy,
    gpuUtilization: (ai.gpu_utilization as number | null) ?? run.gpuUtilization,
  };

  if (aiStatus === "completed") {
    updates.status = "completed";
    updates.completedAt = new Date();
    updates.metrics = (ai.metrics as Record<string, unknown>) ?? {};
  } else if (aiStatus === "failed") {
    updates.status = "failed";
    updates.completedAt = new Date();
    updates.errorMessage = String(ai.error ?? "Training failed on AI service");
    apiLog("training/sync", "run failed on AI service", { runId: run.id, error: updates.errorMessage });
  } else if (aiStatus === "running") {
    broadcastEvent("training_progress", {
      runId: run.id,
      currentEpoch: updates.currentEpoch,
      trainLoss: updates.trainLoss,
      valLoss: updates.valLoss,
      trainAccuracy: updates.trainAccuracy,
      valAccuracy: updates.valAccuracy,
      etaSeconds: ai.eta_seconds,
      learningRate: ai.learning_rate,
      gpuUtilization: updates.gpuUtilization,
      device: ai.device,
      useAmp: ai.use_amp,
    });
  }

  const [updated] = await db
    .update(trainingRuns)
    .set(updates)
    .where(eq(trainingRuns.id, run.id))
    .returning();
  return updated ?? run;
}

router.get("/training/runs", requirePermission(PERMISSIONS.TRAIN), async (_req, res) => {
  const runs = await db.select().from(trainingRuns).orderBy(desc(trainingRuns.createdAt)).limit(20);
  const synced = await Promise.all(runs.map((run) => syncTrainingRun(run)));
  res.json({ runs: synced });
});

router.post("/training/start", requirePermission(PERMISSIONS.TRAIN), async (req: AuthenticatedRequest, res) => {
  try {
    const { datasetId, architecture, hyperparameters, epochs, graphStrategy, graphParams, featureSet } = req.body;
    if (!datasetId) {
      res.status(400).json({ error: "datasetId is required (UUID or slug such as cicids2017)" });
      return;
    }

    // Clients send slugs (cicids2017); PostgreSQL FKs need UUID. AI loaders need the slug.
    const dataset = await resolveDatasetRef(datasetId);
    apiLog("training/start", "resolved dataset", {
      requested: datasetId,
      uuid: dataset.id,
      source: dataset.source,
      architecture,
    });

    const [run] = await db.insert(trainingRuns).values({
      datasetId: dataset.id,
      architecture,
      hyperparameters: {
        ...(hyperparameters ?? {}),
        ...(graphStrategy ? { graph_strategy: graphStrategy } : {}),
        ...(graphParams ? { graph_params: graphParams } : {}),
        ...(featureSet ? { feature_set: featureSet } : {}),
      },
      epochs: epochs ?? 50,
      status: "queued",
      startedBy: req.user!.userId,
    }).returning();

    const aiResult = await aiService.startTraining({
      run_id: run.id,
      dataset_id: dataset.source,
      architecture,
      hyperparameters,
      epochs,
      graph_strategy: graphStrategy,
      graph_params: graphParams ?? {},
      feature_set: featureSet,
    });

    await db.update(trainingRuns).set({ status: "running", startedAt: new Date() }).where(eq(trainingRuns.id, run.id));

    res.status(202).json({
      run,
      ai: aiResult,
      dataset: { id: dataset.id, source: dataset.source, name: dataset.name },
    });
  } catch (error) {
    apiLog("training/start", "failed", { error: error instanceof Error ? error.message : String(error) });
    res.status(500).json({ error: error instanceof Error ? error.message : "Training start failed" });
  }
});

router.get("/training/runs/:id", requirePermission(PERMISSIONS.TRAIN), async (req, res) => {
  const [run] = await db.select().from(trainingRuns).where(eq(trainingRuns.id, req.params.id)).limit(1);
  if (!run) {
    res.status(404).json({ error: "Training run not found" });
    return;
  }

  const synced = await syncTrainingRun(run);

  let aiStatus = {};
  try {
    aiStatus = await aiService.getTrainingStatus(run.id);
  } catch {
    aiStatus = {};
  }

  res.json({ run: synced, ai: aiStatus });
});

router.get("/metrics", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  try {
    const modelId = req.query.model_id as string | undefined;
    const metrics = await aiService.getMetrics(modelId);
    res.json(metrics);
  } catch (error) {
    res.status(503).json({ error: error instanceof Error ? error.message : "Metrics unavailable" });
  }
});

router.get("/evaluation", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  try {
    const modelId = req.query.model_id as string | undefined;
    const evaluation = await aiService.getMetrics(modelId);
    res.json(evaluation);
  } catch (error) {
    res.status(503).json({ error: error instanceof Error ? error.message : "Evaluation unavailable" });
  }
});

router.get("/datasets", requirePermission(PERMISSIONS.MANAGE_DATASETS), async (_req, res) => {
  const result = await db.select().from(datasets).orderBy(desc(datasets.createdAt));
  res.json({ datasets: result });
});

router.post("/datasets/upload", requirePermission(PERMISSIONS.MANAGE_DATASETS), upload.single("file"), async (req: AuthenticatedRequest, res) => {
  try {
    if (!req.file) {
      res.status(400).json({ error: "No file uploaded" });
      return;
    }

    const fs = await import("fs/promises");
    const fileBuffer = await fs.readFile(req.file.path);

    const formData = new FormData();
    formData.append("file", new Blob([fileBuffer]), req.file.originalname);
    formData.append("source", req.body.source || "upload");
    formData.append("name", req.body.name || req.file.originalname);

    const aiResult = await aiService.ingestDataset(formData);

    const [dataset] = await db.insert(datasets).values({
      name: req.body.name || req.file.originalname,
      source: req.body.source || "upload",
      filePath: aiResult.file_path,
      fileType: req.file.mimetype.includes("csv") ? "csv" : req.file.originalname.split(".").pop() || "unknown",
      recordCount: aiResult.record_count ?? 0,
      status: "processing",
      uploadedBy: req.user!.userId,
      metadata: aiResult,
    }).returning();

    res.status(201).json({ dataset, ai: aiResult });
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Upload failed" });
  }
});

router.post("/graph/build", requirePermission(PERMISSIONS.PREDICT), async (req, res) => {
  try {
    const { datasetId, windowSeconds, graphStrategy, graphParams } = req.body;
    const dataset = await resolveDatasetRef(datasetId ?? "cicids2017");
    apiLog("graph/build", "resolved dataset", {
      requested: datasetId,
      uuid: dataset.id,
      source: dataset.source,
      graphStrategy,
    });

    const result = await aiService.buildGraph(
      dataset.source,
      windowSeconds ?? 30,
      graphStrategy,
      graphParams,
    );

    const [graph] = await db.insert(attackGraphs).values({
      name: `Graph ${result.graph_strategy ?? "temporal"} (${windowSeconds ?? 30}s)`,
      windowSeconds: windowSeconds ?? 30,
      nodeCount: result.node_count,
      edgeCount: result.edge_count,
      snapshotData: result.snapshot,
      datasetId: dataset.id,
    }).returning();

    broadcastEvent("graph_update", graph);
    res.json({ ...graph, graphStrategy: result.graph_strategy, graphParams: result.graph_params });
  } catch (error) {
    apiLog("graph/build", "failed", { error: error instanceof Error ? error.message : String(error) });
    res.status(500).json({ error: error instanceof Error ? error.message : "Graph build failed" });
  }
});

// Available graph construction strategies (Module C) — proxied from the AI service.
router.get("/graph/strategies", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (_req, res) => {
  try {
    const result = await aiService.listGraphStrategies();
    res.json(result);
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : "Graph strategies unavailable" });
  }
});

// Model Studio configuration persistence (graph strategy, params, feature set).
router.get("/config", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (_req, res) => {
  try {
    const config = await aiService.getStudioConfig();
    res.json(config);
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : "Config unavailable" });
  }
});

router.post("/config", requirePermission(PERMISSIONS.TRAIN), async (req, res) => {
  try {
    const config = await aiService.saveStudioConfig(req.body?.config ?? req.body ?? {});
    res.json(config);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Save config failed" });
  }
});

router.get("/models", requirePermission(PERMISSIONS.TRAIN), async (_req, res) => {
  const models = await db.select().from(mlModels).orderBy(desc(mlModels.createdAt));
  res.json({ models });
});

// --- Model Registry (Phase 2): filesystem checkpoints via the AI service ---

router.get("/models/registry", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (_req, res) => {
  try {
    const result = await aiService.listRegistryModels();
    res.json(result);
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : "Model registry unavailable" });
  }
});

router.get("/models/:id/export", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  try {
    const meta = await aiService.getModelMetadata(req.params.id);
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Disposition", `attachment; filename="${req.params.id}.metadata.json"`);
    res.send(JSON.stringify(meta, null, 2));
  } catch (error) {
    res.status(404).json({ error: error instanceof Error ? error.message : "Model metadata unavailable" });
  }
});

router.post("/models/:id/activate", requirePermission(PERMISSIONS.TRAIN), async (req, res) => {
  try {
    const result = await aiService.activateModel(req.params.id);
    broadcastEvent("model_activated", { modelId: req.params.id });
    res.json(result);
  } catch (error) {
    apiLog("models/activate", "failed", { error: error instanceof Error ? error.message : String(error) });
    res.status(500).json({ error: error instanceof Error ? error.message : "Activate model failed" });
  }
});

router.delete("/models/:id", requirePermission(PERMISSIONS.TRAIN), async (req, res) => {
  try {
    const result = await aiService.deleteRegistryModel(req.params.id);
    res.json(result);
  } catch (error) {
    apiLog("models/delete", "failed", { error: error instanceof Error ? error.message : String(error) });
    res.status(500).json({ error: error instanceof Error ? error.message : "Delete model failed" });
  }
});

// ======================================================================
// Phase 12 — Continual Learning System (proxied from the AI service)
// ======================================================================

router.get("/datasets/versions", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  try {
    const name = typeof req.query.name === "string" ? req.query.name : undefined;
    res.json(await aiService.listDatasetVersions(name));
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : "Dataset versions unavailable" });
  }
});

router.get("/datasets/history", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (_req, res) => {
  try {
    res.json(await aiService.datasetHistory());
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : "Dataset history unavailable" });
  }
});

router.post("/datasets/register", requirePermission(PERMISSIONS.TRAIN), async (req, res) => {
  try {
    const result = await aiService.registerDataset(req.body ?? {});
    res.json(result);
  } catch (error) {
    apiLog("datasets/register", "failed", { error: error instanceof Error ? error.message : String(error) });
    res.status(500).json({ error: error instanceof Error ? error.message : "Dataset registration failed" });
  }
});

router.get("/drift", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (_req, res) => {
  try {
    res.json(await aiService.getDrift());
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : "Drift reports unavailable" });
  }
});

router.post("/drift", requirePermission(PERMISSIONS.PREDICT), async (req, res) => {
  try {
    res.json(await aiService.computeDrift(req.body ?? {}));
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Drift computation failed" });
  }
});

router.get("/experiments", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  try {
    const datasetId = typeof req.query.dataset_id === "string" ? req.query.dataset_id : undefined;
    res.json(await aiService.listExperiments(datasetId));
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : "Experiments unavailable" });
  }
});

router.get("/training/history", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  try {
    const datasetId = typeof req.query.dataset_id === "string" ? req.query.dataset_id : undefined;
    res.json(await aiService.trainingHistory(datasetId));
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : "Training history unavailable" });
  }
});

router.post("/retrain", requirePermission(PERMISSIONS.TRAIN), async (req, res) => {
  try {
    const result = await aiService.retrainCandidate(req.body ?? {});
    broadcastEvent("training_progress", { type: "candidate_started", ...result });
    res.json(result);
  } catch (error) {
    apiLog("retrain", "failed", { error: error instanceof Error ? error.message : String(error) }, "error");
    res.status(500).json({ error: error instanceof Error ? error.message : "Retrain failed" });
  }
});

router.post("/compare", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  try {
    res.json(await aiService.compareModels(req.body?.candidateId ?? req.body?.candidate_id));
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Compare failed" });
  }
});

router.get("/approvals", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (_req, res) => {
  try {
    res.json(await aiService.approvalHistory());
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : "Approval history unavailable" });
  }
});

router.post("/approve-model", requirePermission(PERMISSIONS.TRAIN), async (req, res) => {
  try {
    const candidateId = req.body?.candidateId ?? req.body?.candidate_id;
    const result = await aiService.approveModel(candidateId);
    broadcastEvent("model_activated", { modelId: candidateId, approved: true });
    res.json(result);
  } catch (error) {
    apiLog("approve-model", "failed", { error: error instanceof Error ? error.message : String(error) }, "error");
    res.status(500).json({ error: error instanceof Error ? error.message : "Approve model failed" });
  }
});

router.post("/rollback", requirePermission(PERMISSIONS.TRAIN), async (_req, res) => {
  try {
    const result = await aiService.rollbackModel();
    broadcastEvent("model_activated", { modelId: "rollback", approved: false, rolledBack: true });
    res.json(result);
  } catch (error) {
    apiLog("rollback", "failed", { error: error instanceof Error ? error.message : String(error) }, "error");
    res.status(error instanceof Error && error.message.includes("not found") ? 404 : 500).json({
      error: error instanceof Error ? error.message : "Rollback failed",
    });
  }
});

router.get("/rollback/info", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (_req, res) => {
  try {
    res.json(await aiService.rollbackInfo());
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : "Rollback info unavailable" });
  }
});

router.get("/review", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  try {
    const status = typeof req.query.status === "string" ? req.query.status : undefined;
    res.json(await aiService.listReview(status));
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : "Review queue unavailable" });
  }
});

router.post("/review/:id/relabel", requirePermission(PERMISSIONS.TRAIN), async (req, res) => {
  try {
    res.json(await aiService.relabelReview(req.params.id, req.body?.label));
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Relabel failed" });
  }
});

router.post("/review/:id/approve", requirePermission(PERMISSIONS.TRAIN), async (req, res) => {
  try {
    res.json(await aiService.approveReview(req.params.id));
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Approve sample failed" });
  }
});

router.get("/knowledge-base", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (_req, res) => {
  try {
    res.json(await aiService.knowledgeBase());
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : "Knowledge base unavailable" });
  }
});

router.post("/soc/response", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  try {
    res.json(await aiService.socResponse(req.body ?? {}));
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : "SOC response generation failed" });
  }
});

router.get("/reports/evaluation", requirePermission(PERMISSIONS.VIEW_DASHBOARD), async (req, res) => {
  try {
    const format = typeof req.query.format === "string" ? req.query.format : "json";
    const modelId = typeof req.query.model_id === "string" ? req.query.model_id : undefined;
    const { content, contentType } = await aiService.getReport(format, modelId);
    if (format !== "json") {
      const ext = format === "csv" ? "csv" : "html";
      res.setHeader("Content-Disposition", `attachment; filename="evaluation-report.${ext}"`);
    }
    res.setHeader("Content-Type", contentType);
    res.send(content);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : "Report generation failed" });
  }
});

// ---------------------------------------------------------------------------
// Phase 13 — Admin: health monitoring, audit/API/training/prediction logs
// ---------------------------------------------------------------------------

router.get("/admin/health", requirePermission(PERMISSIONS.ADMIN), async (_req, res) => {
  let aiSystem: Record<string, unknown> = {};
  try {
    aiSystem = await aiService.adminSystem();
  } catch {
    aiSystem = { error: "AI system metrics unavailable" };
  }
  res.json({
    api: expressSystemMetrics(),
    ai: aiSystem,
    timestamp: new Date().toISOString(),
  });
});

router.get("/admin/audit-logs", requirePermission(PERMISSIONS.ADMIN), async (req, res) => {
  const limit = Math.min(parseInt(String(req.query.limit ?? "100"), 10) || 100, 500);
  const rows = await db
    .select({
      id: auditLogs.id,
      userId: auditLogs.userId,
      action: auditLogs.action,
      resource: auditLogs.resource,
      resourceId: auditLogs.resourceId,
      details: auditLogs.details,
      ipAddress: auditLogs.ipAddress,
      createdAt: auditLogs.createdAt,
      userEmail: users.email,
    })
    .from(auditLogs)
    .leftJoin(users, eq(auditLogs.userId, users.id))
    .orderBy(desc(auditLogs.createdAt))
    .limit(limit);
  res.json({ logs: rows, count: rows.length });
});

router.get("/admin/api-logs", requirePermission(PERMISSIONS.ADMIN), async (req, res) => {
  const limit = Math.min(parseInt(String(req.query.limit ?? "100"), 10) || 100, 500);
  const level = typeof req.query.level === "string" ? req.query.level : undefined;
  const logs = getApiLogs(limit, level === "error" ? "error" : level === "warn" ? "warn" : undefined);
  res.json({ logs, count: logs.length });
});

router.get("/admin/system-logs", requirePermission(PERMISSIONS.ADMIN), async (req, res) => {
  const limit = Math.min(parseInt(String(req.query.limit ?? "100"), 10) || 100, 500);
  const rows = await db
    .select()
    .from(systemLogs)
    .orderBy(desc(systemLogs.createdAt))
    .limit(limit);
  res.json({ logs: rows, count: rows.length });
});

router.get("/admin/training-logs", requirePermission(PERMISSIONS.ADMIN), async (req, res) => {
  const limit = Math.min(parseInt(String(req.query.limit ?? "50"), 10) || 50, 200);
  const runs = await db
    .select()
    .from(trainingRuns)
    .orderBy(desc(trainingRuns.createdAt))
    .limit(limit);
  res.json({ runs, count: runs.length });
});

router.get("/admin/prediction-logs", requirePermission(PERMISSIONS.ADMIN), async (req, res) => {
  const limit = Math.min(parseInt(String(req.query.limit ?? "50"), 10) || 50, 200);
  const rows = await db
    .select({
      id: predictions.id,
      attackType: predictions.attackType,
      threatLevel: predictions.threatLevel,
      confidence: predictions.confidence,
      riskScore: predictions.riskScore,
      createdAt: predictions.createdAt,
    })
    .from(predictions)
    .orderBy(desc(predictions.createdAt))
    .limit(limit);
  res.json({ predictions: rows, count: rows.length });
});

export default router;
