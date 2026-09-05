/**
 * Sync LIVE capture windows into PostgreSQL + WebSocket fan-out.
 * Dataset replay path is untouched — live nodes use externalId prefix `live:`.
 */

import { eq } from "drizzle-orm";
import { db } from "./db";
import { networkNodes, networkEdges } from "@shared/schema";
import { websiteDisplayName } from "@shared/host-identity";
import { aiService } from "./ai-client";
import { broadcastEvent } from "./websocket";
import {
  isPersistableLivePrediction,
  livePredictionToInferenceResult,
  persistPrediction,
} from "./prediction-store";

type LiveNode = {
  id: string;
  ip: string;
  type?: string;
  packets?: number;
  bytes?: number;
  connections?: number;
  failed_logins?: number;
  ports?: number[];
  hostname?: string | null;
  risk_score?: number;
  status?: string;
  website_hint?: boolean;
};

type LiveEdge = {
  source: string;
  target: string;
  protocol?: string;
  packets?: number;
  bytes?: number;
  timestamp?: string;
  src_port?: number;
  dst_port?: number;
};

let pollTimer: ReturnType<typeof setInterval> | null = null;
let lastWindowTs: string | null = null;

function mapNodeType(type: string): typeof networkNodes.nodeType.enumValues[number] {
  const map: Record<string, typeof networkNodes.nodeType.enumValues[number]> = {
    router: "router",
    server: "server",
    host: "host",
    iot_device: "iot_device",
    ip_address: "ip_address",
    switch: "switch",
    user: "user",
  };
  return map[type] ?? "host";
}

function mapProtocol(proto: string): typeof networkEdges.protocol.enumValues[number] {
  const map: Record<string, typeof networkEdges.protocol.enumValues[number]> = {
    tcp: "tcp",
    udp: "udp",
    http: "http",
    https: "https",
    ssh: "ssh",
    dns: "dns",
    ftp: "ftp",
    smtp: "smtp",
    mqtt: "mqtt",
    icmp: "other",
  };
  return map[(proto || "other").toLowerCase()] ?? "other";
}

function isPrivateIp(ip: string): boolean {
  return (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("127.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)
  );
}

export function startLivePoller(intervalMs = 2000) {
  stopLivePoller();
  lastWindowTs = null;
  pollTimer = setInterval(() => {
    void pollOnce();
  }, intervalMs);
}

export function stopLivePoller() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  lastWindowTs = null;
}

function liveContextFeatures(
  snapshot: { nodes?: LiveNode[]; edges?: LiveEdge[]; timestamp?: string },
  status: Record<string, unknown>,
  prediction: Record<string, unknown>,
) {
  const nodes = snapshot.nodes ?? [];
  const edges = snapshot.edges ?? [];
  const privateNode = nodes.find((n) => isPrivateIp(n.ip));
  const edge = edges[0];
  return {
    source: "live",
    mode: "live_capture",
    interface: status.interface,
    window_seconds: status.window_seconds,
    window_id: prediction.window_id ?? snapshot.timestamp,
    session_id: status.session_id,
    node_count: nodes.length,
    edge_count: edges.length,
    src_ip: privateNode?.ip,
    dst_ip: nodes.find((n) => n.ip !== privateNode?.ip)?.ip,
    protocol: edge?.protocol,
  };
}

async function persistLivePrediction(
  snapshot: { nodes?: LiveNode[]; edges?: LiveEdge[]; timestamp?: string },
  status: Record<string, unknown>,
  rawPrediction: Record<string, unknown>,
) {
  if (!isPersistableLivePrediction(rawPrediction)) {
    return null;
  }

  const result = livePredictionToInferenceResult(rawPrediction);
  const features = liveContextFeatures(snapshot, status, rawPrediction);
  const { prediction } = await persistPrediction(result, features);
  console.log(
    `[live-sync] stored live prediction ${prediction.id} ` +
      `(${prediction.attackType}, conf=${Math.round(prediction.confidence * 100)}%)`,
  );
  return prediction;
}

async function pollOnce() {
  try {
    const status = (await aiService.liveStatus()) as Record<string, unknown>;
    if (!status.running) {
      stopLivePoller();
      return;
    }
    const snapshot = status.snapshot as
      | { timestamp?: string; nodes?: LiveNode[]; edges?: LiveEdge[] }
      | null
      | undefined;
    const ts = snapshot?.timestamp ?? null;
    if (!ts || ts === lastWindowTs) return;
    if (!snapshot?.nodes?.length) {
      lastWindowTs = ts;
      broadcastEvent("network_topology", {
        source: "live",
        waiting: true,
        message: status.message,
        stats: status.stats,
      });
      return;
    }

    lastWindowTs = ts;
    await syncLiveSnapshot(snapshot, status.prediction as Record<string, unknown> | undefined);
    const rawPrediction = status.prediction as Record<string, unknown> | undefined;
    const storedPrediction = rawPrediction
      ? await persistLivePrediction(snapshot, status, rawPrediction)
      : null;

    broadcastEvent("network_topology", {
      source: "live",
      timestamp: ts,
      stats: status.stats,
      prediction: storedPrediction ?? rawPrediction ?? null,
    });
    if (storedPrediction) {
      broadcastEvent("risk_update", {
        source: "live",
        risk_score: storedPrediction.riskScore,
        confidence: storedPrediction.confidence,
        attack_type: storedPrediction.attackType,
      });
    }
  } catch (err) {
    console.warn("[live-sync] poll failed:", err instanceof Error ? err.message : err);
  }
}

export async function syncLiveSnapshot(
  snapshot: { nodes?: LiveNode[]; edges?: LiveEdge[]; timestamp?: string },
  prediction?: Record<string, unknown>,
) {
  const nodeIdMap = new Map<string, string>();
  const windowRisk = typeof prediction?.risk_score === "number" ? Number(prediction.risk_score) : 0.1;

  for (const node of snapshot.nodes ?? []) {
    const externalId = `live:${node.id}`;
    const ip = node.ip;
    const hostFromDns = node.hostname?.trim() || null;
    const isExternal = !isPrivateIp(ip);
    const websiteName = isExternal && hostFromDns ? websiteDisplayName(hostFromDns) : null;
    const hostname =
      hostFromDns ||
      (isExternal ? null : `HOST-${ip.split(".").pop() ?? "x"}`);

    const riskScore = Math.min(1, Math.max(0, Number(node.risk_score ?? windowRisk) || 0));
    const statusRaw = String(node.status || "online");
    const status = (
      statusRaw === "compromised" || statusRaw === "suspicious" || statusRaw === "offline"
        ? statusRaw
        : "online"
    ) as typeof networkNodes.status.enumValues[number];

    const existing = await db
      .select()
      .from(networkNodes)
      .where(eq(networkNodes.externalId, externalId))
      .limit(1);

    const values = {
      ipAddress: ip,
      hostname,
      nodeType: mapNodeType(String(node.type || "host")),
      status,
      riskScore,
      packets: Number(node.packets || 0),
      bytes: Number(node.bytes || 0),
      failedLogins: Number(node.failed_logins || 0),
      connectionCount: Number(node.connections || 0),
      openPorts: node.ports ?? [],
      vendor: isExternal ? "website" : null,
      os: isExternal ? "external-host" : null,
      department: isExternal ? "external" : "local",
      subnet: isPrivateIp(ip) ? `${ip.split(".").slice(0, 3).join(".")}.0/24` : null,
      features: {
        live_capture: 1,
        website_name_code: websiteName && websiteName !== "Unknown" ? 1 : 0,
      },
      lastSeenAt: new Date(),
      updatedAt: new Date(),
    };

    if (existing[0]) {
      await db.update(networkNodes).set(values).where(eq(networkNodes.id, existing[0].id));
      nodeIdMap.set(node.id, existing[0].id);
    } else {
      const [inserted] = await db
        .insert(networkNodes)
        .values({
          externalId,
          ...values,
        })
        .returning();
      nodeIdMap.set(node.id, inserted.id);
    }
  }

  for (const edge of (snapshot.edges ?? []).slice(0, 400)) {
    const sourceId = nodeIdMap.get(edge.source);
    const targetId = nodeIdMap.get(edge.target);
    if (!sourceId || !targetId) continue;
    await db.insert(networkEdges).values({
      sourceNodeId: sourceId,
      targetNodeId: targetId,
      protocol: mapProtocol(String(edge.protocol || "other")),
      packetCount: Number(edge.packets || 0),
      weight: Math.min(Number(edge.bytes || 0) / 1000, 10),
      timestamp: edge.timestamp ? new Date(edge.timestamp) : new Date(),
    });
  }
}
