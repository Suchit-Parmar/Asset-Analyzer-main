import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";

const EVENT_QUERY_MAP: Record<string, string[][]> = {
  alert: [["alerts"], ["dashboard"]],
  prediction: [["predictions"], ["attack-stage"], ["dashboard"], ["risk"]],
  graph_update: [["network"], ["attack-stage"]],
  risk_update: [["risk"], ["dashboard"]],
  training_progress: [["training"], ["metrics"], ["model"], ["cl"]],
  model_activated: [["model"], ["metrics"], ["cl"], ["dashboard"]],
  network_topology: [["network"]],
  system_health: [["health"], ["model"], ["dashboard"]],
};

export function useWebSocketSync() {
  const queryClient = useQueryClient();
  const [connected, setConnected] = useState(false);
  const [lastEventAt, setLastEventAt] = useState<string | null>(null);
  const [lastEventType, setLastEventType] = useState<string | null>(null);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let attempt = 0;

    const connect = () => {
      if (closed || !api.getAccessToken()) {
        setConnected(false);
        return;
      }

      ws = api.createWebSocket(
        (msg: unknown) => {
          const event = msg as { type?: string };
          if (!event.type) return;
          setLastEventAt(new Date().toISOString());
          setLastEventType(event.type);

          const keys = EVENT_QUERY_MAP[event.type];
          if (keys) {
            for (const queryKey of keys) {
              queryClient.invalidateQueries({ queryKey });
            }
          }
        },
        {
          onOpen: () => {
            attempt = 0;
            setConnected(true);
          },
          onClose: () => {
            setConnected(false);
            if (closed) return;
            const delay = Math.min(1000 * 2 ** attempt, 15000);
            attempt += 1;
            retryTimer = setTimeout(connect, delay);
          },
          onError: () => {
            setConnected(false);
          },
        },
      );

      if (!ws) setConnected(false);
    };

    connect();

    return () => {
      closed = true;
      if (retryTimer) clearTimeout(retryTimer);
      ws?.close();
    };
  }, [queryClient]);

  return { connected, lastEventAt, lastEventType };
}
