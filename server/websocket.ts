import type { Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import jwt from "jsonwebtoken";
import type { AuthPayload } from "./auth";
import { getRedis } from "./redis";

export type WsEventType =
  | "alert"
  | "prediction"
  | "graph_update"
  | "training_progress"
  | "network_topology"
  | "risk_update"
  | "system_health"
  | "model_activated";

export interface WsMessage {
  type: WsEventType;
  payload: unknown;
  timestamp: string;
}

const clients = new Set<WebSocket>();

export function setupWebSocket(server: Server) {
  const wss = new WebSocketServer({ server, path: "/ws" });

  wss.on("connection", (ws, req) => {
    const url = new URL(req.url || "", `http://${req.headers.host}`);
    const token = url.searchParams.get("token");

    if (!token) {
      ws.close(4001, "Authentication required");
      return;
    }

    try {
      const secret = process.env.JWT_ACCESS_SECRET || "dev-access-secret-change-in-production";
      jwt.verify(token, secret);
    } catch {
      ws.close(4001, "Invalid token");
      return;
    }

    clients.add(ws);

    ws.send(JSON.stringify({
      type: "system_health",
      payload: { status: "connected", clients: clients.size },
      timestamp: new Date().toISOString(),
    }));

    ws.on("close", () => clients.delete(ws));
    ws.on("error", () => clients.delete(ws));
  });

  const redis = getRedis();
  redis.subscribe("gnn-ids:events").catch(() => {});

  redis.on("message", (_channel, message) => {
    try {
      const parsed = JSON.parse(message) as WsMessage;
      broadcast(parsed);
    } catch {
      // ignore malformed messages
    }
  });

  return wss;
}

export function broadcast(message: WsMessage) {
  const data = JSON.stringify(message);
  for (const client of Array.from(clients)) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(data);
    }
  }
}

export function broadcastEvent(type: WsEventType, payload: unknown) {
  broadcast({
    type,
    payload,
    timestamp: new Date().toISOString(),
  });
}

export function getConnectedClients(): number {
  return clients.size;
}
