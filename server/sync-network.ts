/**
 * Sync network topology from real dataset graph into PostgreSQL.
 * Run on startup to populate network_nodes and network_edges from TGNN graph builder.
 */

import { eq } from "drizzle-orm";
import { db } from "./db";
import { networkNodes, networkEdges } from "@shared/schema";
import { aiService } from "./ai-client";

export async function syncNetworkFromDataset(datasetId = "cicids2017", windowSeconds = 30) {
  console.log("[sync] Building graph from real dataset...");

  try {
    const graph = await aiService.buildGraph(datasetId, windowSeconds);
    const snapshot = graph.snapshot as {
      nodes: Array<{
        id: string; ip: string; type: string; packets: number; bytes: number;
        connections: number; failed_logins: number; ports: number[];
      }>;
      edges: Array<{
        source: string; target: string; protocol: string;
        bytes: number; packets: number; timestamp: string;
      }>;
    };

    const nodeIdMap = new Map<string, string>();

    for (const node of snapshot.nodes) {
      const riskScore = Math.min(
        (node.failed_logins * 0.15) + (node.connections / 100) + (node.packets / 10000),
        1.0,
      );
      const status = node.failed_logins > 3 ? "compromised"
        : node.failed_logins > 0 ? "suspicious" : "online";

      const existing = await db
        .select()
        .from(networkNodes)
        .where(eq(networkNodes.externalId, node.id))
        .limit(1);

      if (existing.length) {
        await db.update(networkNodes).set({
          ipAddress: node.ip,
          nodeType: mapNodeType(node.type),
          status: status as typeof networkNodes.status.enumValues[number],
          riskScore,
          packets: node.packets,
          bytes: node.bytes,
          failedLogins: node.failed_logins,
          connectionCount: node.connections,
          openPorts: node.ports,
          lastSeenAt: new Date(),
          updatedAt: new Date(),
        }).where(eq(networkNodes.id, existing[0].id));
        nodeIdMap.set(node.id, existing[0].id);
      } else {
        const [inserted] = await db.insert(networkNodes).values({
          externalId: node.id,
          ipAddress: node.ip,
          hostname: `HOST-${node.ip.split(".").pop()}`,
          nodeType: mapNodeType(node.type),
          status: status as typeof networkNodes.status.enumValues[number],
          riskScore,
          packets: node.packets,
          bytes: node.bytes,
          failedLogins: node.failed_logins,
          connectionCount: node.connections,
          openPorts: node.ports,
          subnet: node.ip.split(".").slice(0, 3).join(".") + ".0/24",
        }).returning();
        nodeIdMap.set(node.id, inserted.id);
      }
    }

    for (const edge of snapshot.edges.slice(0, 500)) {
      const sourceId = nodeIdMap.get(edge.source);
      const targetId = nodeIdMap.get(edge.target);
      if (!sourceId || !targetId) continue;

      await db.insert(networkEdges).values({
        sourceNodeId: sourceId,
        targetNodeId: targetId,
        protocol: mapProtocol(edge.protocol),
        packetCount: edge.packets,
        weight: Math.min(edge.bytes / 1000, 10),
        timestamp: new Date(edge.timestamp),
      });
    }

    console.log(`[sync] Synced ${snapshot.nodes.length} nodes, ${Math.min(snapshot.edges.length, 500)} edges`);
    return { nodes: snapshot.nodes.length, edges: snapshot.edges.length };
  } catch (error) {
    console.warn("[sync] Network sync failed (AI service may be unavailable):", error);
    return seedDemoNetworkIfEmpty();
  }
}

async function seedDemoNetworkIfEmpty() {
  const existing = await db.select({ id: networkNodes.id }).from(networkNodes).limit(1);
  if (existing.length) return null;

  console.log("[sync] Seeding demo network topology (AI service offline)...");

  const demoNodes = [
    { externalId: "demo-gw", ipAddress: "10.0.0.1", hostname: "gateway-01", nodeType: "router" as const, status: "online" as const, riskScore: 0.12, packets: 42000, bytes: 8_500_000, failedLogins: 0, connectionCount: 48, openPorts: [22, 443], subnet: "10.0.0.0/24" },
    { externalId: "demo-web", ipAddress: "10.0.0.10", hostname: "web-server", nodeType: "server" as const, status: "suspicious" as const, riskScore: 0.61, packets: 18500, bytes: 3_200_000, failedLogins: 2, connectionCount: 96, openPorts: [80, 443], subnet: "10.0.0.0/24" },
    { externalId: "demo-db", ipAddress: "10.0.0.20", hostname: "db-primary", nodeType: "server" as const, status: "online" as const, riskScore: 0.28, packets: 9200, bytes: 1_100_000, failedLogins: 0, connectionCount: 14, openPorts: [5432], subnet: "10.0.0.0/24" },
    { externalId: "demo-iot", ipAddress: "10.0.0.55", hostname: "camera-03", nodeType: "iot_device" as const, status: "compromised" as const, riskScore: 0.91, packets: 6400, bytes: 780_000, failedLogins: 7, connectionCount: 31, openPorts: [554, 8080], subnet: "10.0.0.0/24" },
    { externalId: "demo-ws", ipAddress: "10.0.0.42", hostname: "analyst-ws", nodeType: "host" as const, status: "online" as const, riskScore: 0.18, packets: 3100, bytes: 420_000, failedLogins: 0, connectionCount: 8, openPorts: [22], subnet: "10.0.0.0/24" },
  ];

  const inserted = [];
  for (const node of demoNodes) {
    const [row] = await db.insert(networkNodes).values(node).returning();
    inserted.push(row);
  }

  const byExt = Object.fromEntries(inserted.map((n) => [n.externalId!, n.id]));
  const demoEdges = [
    { source: "demo-gw", target: "demo-web", protocol: "https" as const, packetCount: 1200, weight: 2.4 },
    { source: "demo-web", target: "demo-db", protocol: "tcp" as const, packetCount: 800, weight: 1.8 },
    { source: "demo-gw", target: "demo-iot", protocol: "tcp" as const, packetCount: 450, weight: 3.1 },
    { source: "demo-ws", target: "demo-web", protocol: "https" as const, packetCount: 220, weight: 0.9 },
    { source: "demo-iot", target: "demo-db", protocol: "tcp" as const, packetCount: 90, weight: 4.2 },
  ];

  for (const edge of demoEdges) {
    await db.insert(networkEdges).values({
      sourceNodeId: byExt[edge.source],
      targetNodeId: byExt[edge.target],
      protocol: edge.protocol,
      packetCount: edge.packetCount,
      weight: edge.weight,
      timestamp: new Date(),
    });
  }

  console.log(`[sync] Seeded ${demoNodes.length} demo nodes and ${demoEdges.length} edges`);
  return { nodes: demoNodes.length, edges: demoEdges.length };
}

function mapNodeType(type: string): typeof networkNodes.nodeType.enumValues[number] {
  const map: Record<string, typeof networkNodes.nodeType.enumValues[number]> = {
    router: "router", server: "server", host: "host", iot_device: "iot_device",
    ip_address: "ip_address", switch: "switch", user: "user",
  };
  return map[type] ?? "host";
}

function mapProtocol(proto: string): typeof networkEdges.protocol.enumValues[number] {
  const map: Record<string, typeof networkEdges.protocol.enumValues[number]> = {
    tcp: "tcp", udp: "udp", http: "http", https: "https", ssh: "ssh",
    dns: "dns", ftp: "ftp", smtp: "smtp", mqtt: "mqtt",
  };
  return map[proto.toLowerCase()] ?? "other";
}

if (process.argv[1]?.endsWith("sync-network.ts")) {
  syncNetworkFromDataset()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}
