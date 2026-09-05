import { useEffect, useMemo, useRef, useState } from "react";
import type { Topology } from "@/lib/api";
import { TrafficModeBadge, type TrafficMode } from "@/components/TrafficModeBadge";
import {
  compactGraphLabel,
  deviceCategory,
  deviceCategoryLabel,
  formatBytes,
  resolveHostIdentity,
  riskLevel,
  riskLevelClass,
  riskScore100,
} from "@/lib/cyber-display";
import { cn } from "@/lib/utils";

export interface TopologyNodeView {
  id: string;
  label: string;
  ip: string;
  type: string;
  status: string;
  risk: number;
  vendor?: string | null;
  hostname?: string | null;
  websiteName?: string | null;
  packets?: number | null;
  bytes?: number | null;
  connectionCount?: number | null;
  firstSeen?: string | null;
  lastSeen?: string | null;
}

export interface TopologyEdgeView {
  id: string;
  source: string;
  target: string;
  protocol: string;
  weight: number;
  packetCount?: number | null;
  timestamp?: string | null;
}

export interface TopologyView {
  nodes: TopologyNodeView[];
  edges: TopologyEdgeView[];
}

interface GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  id: string;
  label: string;
  ip: string;
  type: string;
  status: string;
  risk: number;
  vendor?: string | null;
  hostname?: string | null;
  websiteName?: string | null;
  packets?: number | null;
  bytes?: number | null;
  connectionCount?: number | null;
  firstSeen?: string | null;
  lastSeen?: string | null;
  display: "malicious" | "suspicious" | "normal";
}

interface NetworkGraphProps {
  active?: boolean;
  alertMode?: boolean;
  topology?: Topology | TopologyView | null;
  mode?: TrafficMode;
  selectedNodeId?: string | null;
  onSelectNode?: (node: TopologyNodeView | null) => void;
  className?: string;
}

function displayKind(status: string, risk: number): GraphNode["display"] {
  if (status === "compromised") return "malicious";
  if (status === "suspicious" || riskScore100(risk) >= 60) return "suspicious";
  return "normal";
}

function pickField<T>(n: Record<string, unknown>, key: string): T | null {
  return key in n ? ((n[key] as T | null | undefined) ?? null) : null;
}

function toView(topology?: Topology | TopologyView | null): TopologyView | null {
  if (!topology?.nodes?.length) return null;
  return {
    nodes: topology.nodes.map((n) => {
      const rec = n as unknown as Record<string, unknown>;
      return {
        id: n.id,
        label: n.label,
        ip: n.ip,
        type: n.type,
        status: n.status,
        risk: n.risk,
        vendor: pickField<string>(rec, "vendor"),
        hostname: pickField<string>(rec, "hostname"),
        websiteName: pickField<string>(rec, "websiteName"),
        packets: pickField<number>(rec, "packets"),
        bytes: pickField<number>(rec, "bytes"),
        connectionCount: pickField<number>(rec, "connectionCount"),
        firstSeen: pickField<string>(rec, "firstSeen"),
        lastSeen: pickField<string>(rec, "lastSeen"),
      };
    }),
    edges: (topology.edges ?? []).map((e) => {
      const rec = e as unknown as Record<string, unknown>;
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        protocol: e.protocol,
        weight: e.weight,
        packetCount: pickField<number>(rec, "packetCount"),
        timestamp: pickField<string>(rec, "timestamp"),
      };
    }),
  };
}

function identityFor(node: {
  label: string;
  ip: string;
  type: string;
  vendor?: string | null;
  hostname?: string | null;
  websiteName?: string | null;
}) {
  return resolveHostIdentity({
    label: node.label,
    hostname: node.hostname,
    ip: node.ip,
    vendor: node.vendor,
    websiteName: node.websiteName,
    nodeType: node.type,
  });
}

function NetworkGraphCanvas({
  active = true,
  alertMode = false,
  topology,
  selectedNodeId,
  onSelectNode,
}: NetworkGraphProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const nodesRef = useRef<GraphNode[]>([]);
  const alertModeRef = useRef(alertMode);
  const selectedRef = useRef(selectedNodeId);
  const viewRef = useRef<TopologyView | null>(null);
  const onSelectRef = useRef(onSelectNode);

  const view = useMemo(() => toView(topology), [topology]);
  viewRef.current = view;
  onSelectRef.current = onSelectNode;

  const [hover, setHover] = useState<{
    kind: "node" | "edge";
    x: number;
    y: number;
    title: string;
    lines: string[];
  } | null>(null);

  useEffect(() => {
    alertModeRef.current = alertMode;
  }, [alertMode]);

  useEffect(() => {
    selectedRef.current = selectedNodeId;
  }, [selectedNodeId]);

  useEffect(() => {
    if (!view?.nodes?.length) {
      nodesRef.current = [];
      return;
    }
    const prev = new Map(nodesRef.current.map((n) => [n.id, n]));
    const count = view.nodes.length;
    nodesRef.current = view.nodes.map((node, i) => {
      const existing = prev.get(node.id);
      if (existing) {
        return {
          ...existing,
          label: node.label,
          ip: node.ip,
          type: node.type,
          status: node.status,
          risk: node.risk,
          vendor: node.vendor,
          hostname: node.hostname,
          websiteName: node.websiteName,
          packets: node.packets,
          bytes: node.bytes,
          connectionCount: node.connectionCount,
          firstSeen: node.firstSeen,
          lastSeen: node.lastSeen,
          display: displayKind(node.status, node.risk),
        };
      }
      const angle = (i / Math.max(count, 1)) * Math.PI * 2;
      const radius = 28 + Math.min(riskScore100(node.risk), 100) * 0.22;
      return {
        x: 50 + Math.cos(angle) * radius,
        y: 50 + Math.sin(angle) * radius,
        vx: (Math.random() - 0.5) * 0.06,
        vy: (Math.random() - 0.5) * 0.06,
        id: node.id,
        label: node.label,
        ip: node.ip,
        type: node.type,
        status: node.status,
        risk: node.risk,
        vendor: node.vendor,
        hostname: node.hostname,
        websiteName: node.websiteName,
        packets: node.packets,
        bytes: node.bytes,
        connectionCount: node.connectionCount,
        firstSeen: node.firstSeen,
        lastSeen: node.lastSeen,
        display: displayKind(node.status, node.risk),
      };
    });
  }, [view]);

  useEffect(() => {
    if (!active || !canvasRef.current) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId = 0;
    let alive = true;

    const resize = () => {
      if (canvas.parentElement) {
        const w = canvas.parentElement.clientWidth;
        const h = canvas.parentElement.clientHeight;
        // Skip zero-size frames while keep-alive hides the page (display:none).
        if (w > 0 && h > 0) {
          canvas.width = w;
          canvas.height = h;
        }
      }
    };
    resize();
    window.addEventListener("resize", resize);
    const ro =
      typeof ResizeObserver !== "undefined" && canvas.parentElement
        ? new ResizeObserver(resize)
        : null;
    if (ro && canvas.parentElement) ro.observe(canvas.parentElement);

    const render = () => {
      if (!alive) return;
      const nodes = nodesRef.current;
      const currentView = viewRef.current;
      const isAlert = alertModeRef.current;
      const selected = selectedRef.current;

      ctx.fillStyle = "rgba(13, 17, 23, 0.25)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      nodes.forEach((node) => {
        node.x += node.vx;
        node.y += node.vy;
        if (node.x < 6 || node.x > 94) node.vx *= -1;
        if (node.y < 6 || node.y > 94) node.vy *= -1;
      });

      const byId = new Map(nodes.map((n) => [n.id, n]));

      if (currentView?.edges?.length) {
        currentView.edges.forEach((edge) => {
          const src = byId.get(edge.source);
          const tgt = byId.get(edge.target);
          if (!src || !tgt) return;
          const highlight =
            selected && (edge.source === selected || edge.target === selected);
          ctx.strokeStyle = highlight
            ? "rgba(34, 211, 238, 0.85)"
            : isAlert
              ? "rgba(239, 68, 68, 0.35)"
              : "rgba(6, 182, 212, 0.28)";
          ctx.lineWidth = highlight ? 1.8 : 0.9;
          ctx.beginPath();
          ctx.moveTo((src.x * canvas.width) / 100, (src.y * canvas.height) / 100);
          ctx.lineTo((tgt.x * canvas.width) / 100, (tgt.y * canvas.height) / 100);
          ctx.stroke();
        });
      }

      // Cap on-canvas text labels to avoid overcrowding large topologies.
      const websiteNodes = nodes.filter((n) => identityFor(n).isWebsite);
      const labeledIds = new Set<string>();
      if (selected) labeledIds.add(selected);
      for (const n of websiteNodes.slice(0, 12)) labeledIds.add(n.id);

      nodes.forEach((node) => {
        const px = (node.x * canvas.width) / 100;
        const py = (node.y * canvas.height) / 100;
        const cat = deviceCategory(node.type, node.vendor);
        const base =
          node.display === "malicious" ? 6 : node.display === "suspicious" ? 5 : 3.5;
        const radius = selected === node.id ? base + 2 : base;

        ctx.beginPath();
        ctx.arc(px, py, radius, 0, Math.PI * 2);
        if (node.display === "malicious") {
          ctx.fillStyle = isAlert ? "#ef4444" : "#f97316";
          ctx.shadowColor = "#ef4444";
          ctx.shadowBlur = isAlert ? 14 : 6;
        } else if (node.display === "suspicious") {
          ctx.fillStyle = "#eab308";
          ctx.shadowBlur = 0;
        } else if (cat === "iot") {
          ctx.fillStyle = "#a78bfa";
          ctx.shadowBlur = 0;
        } else if (cat === "website") {
          ctx.fillStyle = "#38bdf8";
          ctx.shadowBlur = 0;
        } else {
          ctx.fillStyle = "#06b6d4";
          ctx.shadowBlur = 0;
        }
        ctx.fill();
        ctx.shadowBlur = 0;

        if (selected === node.id) {
          ctx.strokeStyle = "rgba(255,255,255,0.7)";
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(px, py, radius + 3, 0, Math.PI * 2);
          ctx.stroke();
        }

        if (labeledIds.has(node.id)) {
          const idn = identityFor(node);
          const compact = compactGraphLabel(idn);
          ctx.font = "600 10px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace";
          ctx.fillStyle = "rgba(226, 232, 240, 0.92)";
          ctx.textAlign = "center";
          ctx.fillText(compact.line1.slice(0, 22), px, py + radius + 12);
          if (compact.line2) {
            ctx.font = "9px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace";
            ctx.fillStyle = "rgba(148, 163, 184, 0.9)";
            ctx.fillText(compact.line2.slice(0, 28), px, py + radius + 24);
          }
        }
      });

      animationFrameId = requestAnimationFrame(render);
    };

    const hitTest = (clientX: number, clientY: number) => {
      const rect = canvas.getBoundingClientRect();
      const mx = ((clientX - rect.left) / rect.width) * 100;
      const my = ((clientY - rect.top) / rect.height) * 100;
      const nodes = nodesRef.current;
      const currentView = viewRef.current;

      for (let i = nodes.length - 1; i >= 0; i--) {
        const n = nodes[i];
        const dx = n.x - mx;
        const dy = n.y - my;
        if (dx * dx + dy * dy < 3.2 * 3.2) return { kind: "node" as const, node: n };
      }

      if (currentView?.edges?.length) {
        const byId = new Map(nodes.map((n) => [n.id, n]));
        for (const edge of currentView.edges) {
          const s = byId.get(edge.source);
          const t = byId.get(edge.target);
          if (!s || !t) continue;
          const dist = pointToSegment(mx, my, s.x, s.y, t.x, t.y);
          if (dist < 1.2) return { kind: "edge" as const, edge, s, t };
        }
      }
      return null;
    };

    const onMove = (ev: MouseEvent) => {
      const hit = hitTest(ev.clientX, ev.clientY);
      const rect = canvas.getBoundingClientRect();
      if (!hit) {
        setHover(null);
        canvas.style.cursor = "default";
        return;
      }
      canvas.style.cursor = "pointer";
      if (hit.kind === "node") {
        const score = riskScore100(hit.node.risk);
        const level = riskLevel(score);
        const idn = identityFor(hit.node);
        const lines = idn.isWebsite
          ? [
              `Website: ${idn.displayName}`,
              `Hostname: ${idn.hostname ?? "—"}`,
              `IP: ${idn.ip ?? "—"}`,
              "Type: External Website",
              `Risk: ${score}/100 (${level})`,
            ]
          : [
              `Device: ${idn.displayName}`,
              idn.hostname ? `Hostname: ${idn.hostname}` : "",
              `IP: ${idn.ip ?? hit.node.ip}`,
              `Type: ${deviceCategoryLabel(deviceCategory(hit.node.type, hit.node.vendor))}`,
              `Risk: ${score}/100 (${level})`,
              hit.node.packets != null ? `Packets: ${hit.node.packets.toLocaleString()}` : "",
            ].filter(Boolean);

        setHover({
          kind: "node",
          x: ev.clientX - rect.left + 12,
          y: ev.clientY - rect.top + 12,
          title: idn.displayName,
          lines,
        });
      } else {
        setHover({
          kind: "edge",
          x: ev.clientX - rect.left + 12,
          y: ev.clientY - rect.top + 12,
          title: `${hit.s.label} → ${hit.t.label}`,
          lines: [
            `Protocol: ${hit.edge.protocol?.toUpperCase() ?? "—"}`,
            `Weight: ${hit.edge.weight ?? "—"}`,
            hit.edge.packetCount != null
              ? `Packets: ${hit.edge.packetCount.toLocaleString()}`
              : "",
            hit.edge.timestamp
              ? `Time: ${new Date(hit.edge.timestamp).toLocaleString()}`
              : "",
          ].filter(Boolean),
        });
      }
    };

    const onLeave = () => {
      setHover(null);
      canvas.style.cursor = "default";
    };

    const onClick = (ev: MouseEvent) => {
      const hit = hitTest(ev.clientX, ev.clientY);
      const select = onSelectRef.current;
      if (!select) return;
      if (hit?.kind === "node") {
        select({
          id: hit.node.id,
          label: hit.node.label,
          ip: hit.node.ip,
          type: hit.node.type,
          status: hit.node.status,
          risk: hit.node.risk,
          vendor: hit.node.vendor,
          hostname: hit.node.hostname,
          websiteName: hit.node.websiteName,
          packets: hit.node.packets,
          bytes: hit.node.bytes,
          connectionCount: hit.node.connectionCount,
          firstSeen: hit.node.firstSeen,
          lastSeen: hit.node.lastSeen,
        });
      } else {
        select(null);
      }
    };

    canvas.addEventListener("mousemove", onMove);
    canvas.addEventListener("mouseleave", onLeave);
    canvas.addEventListener("click", onClick);
    render();

    return () => {
      alive = false;
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", resize);
      ro?.disconnect();
      canvas.removeEventListener("mousemove", onMove);
      canvas.removeEventListener("mouseleave", onLeave);
      canvas.removeEventListener("click", onClick);
    };
  }, [active]);

  return (
    <>
      <canvas ref={canvasRef} className="w-full h-full block" />
      {hover && (
        <div
          className="pointer-events-none absolute z-20 max-w-[260px] rounded-lg border border-border/70 bg-background/95 px-3 py-2 text-[11px] shadow-xl backdrop-blur"
          style={{ left: hover.x, top: hover.y }}
        >
          <div className="font-semibold text-foreground mb-1">{hover.title}</div>
          {hover.lines.map((line) => (
            <div key={line} className="font-mono text-muted-foreground">
              {line}
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function pointToSegment(
  px: number,
  py: number,
  x1: number,
  y1: number,
  x2: number,
  y2: number,
): number {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const len2 = dx * dx + dy * dy || 1;
  let t = ((px - x1) * dx + (py - y1) * dy) / len2;
  t = Math.max(0, Math.min(1, t));
  const qx = x1 + t * dx;
  const qy = y1 + t * dy;
  return Math.hypot(px - qx, py - qy);
}

function NetworkGraphWrapper(props: NetworkGraphProps) {
  const empty = !props.topology?.nodes?.length;
  const mode: TrafficMode = props.mode ?? (empty ? "awaiting" : "live");

  return (
    <div
      className={cn(
        "w-full h-full relative overflow-hidden bg-card/20 rounded-lg border border-border/50",
        props.className,
      )}
    >
      <div className="absolute top-2 left-2 z-10">
        <TrafficModeBadge mode={mode} showHint={false} />
      </div>
      <div className="absolute top-2 right-2 z-10 flex flex-wrap gap-1 justify-end">
        <LegendDot color="bg-cyan-400" label="Normal" />
        <LegendDot color="bg-violet-400" label="IoT" />
        <LegendDot color="bg-sky-400" label="Website" />
        <LegendDot color="bg-yellow-400" label="Suspicious" />
        <LegendDot color="bg-orange-400" label="Malicious" />
      </div>
      {empty && (
        <div className="absolute inset-0 z-10 flex items-center justify-center text-xs font-mono text-muted-foreground px-6 text-center">
          No topology yet — sync network nodes or start dataset replay
        </div>
      )}
      <NetworkGraphCanvas {...props} />
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1 rounded border border-border/50 bg-background/60 px-1.5 py-0.5 text-[9px] font-mono text-muted-foreground">
      <span className={cn("h-1.5 w-1.5 rounded-full", color)} />
      {label}
    </span>
  );
}

function fmtWhen(value?: string | null): string {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

export function NodeDetailPanel({
  node,
  onClose,
}: {
  node: TopologyNodeView | null;
  onClose?: () => void;
}) {
  if (!node) return null;
  const score = riskScore100(node.risk);
  const level = riskLevel(score);
  const cat = deviceCategory(node.type, node.vendor);
  const idn = identityFor(node);

  return (
    <div className="rounded-lg border border-border/60 bg-card/40 p-4 space-y-2">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="text-sm font-semibold text-white">{idn.displayName}</div>
          {idn.isWebsite ? (
            <div className="text-xs font-mono text-muted-foreground mt-0.5 space-y-0.5">
              <div>Hostname: {idn.hostname ?? "—"}</div>
              <div>IP: {idn.ip ?? "—"}</div>
            </div>
          ) : (
            <div className="text-xs font-mono text-muted-foreground mt-0.5 space-y-0.5">
              {idn.hostname && idn.hostname !== idn.displayName && (
                <div>Hostname: {idn.hostname}</div>
              )}
              <div>IP: {idn.ip ?? node.ip}</div>
            </div>
          )}
        </div>
        {onClose && (
          <button
            type="button"
            className="text-xs text-muted-foreground hover:text-foreground"
            onClick={onClose}
          >
            Close
          </button>
        )}
      </div>
      <div className="flex flex-wrap gap-2 text-xs">
        <span className="rounded border border-border/50 px-2 py-0.5">
          {idn.isWebsite ? "External Website" : deviceCategoryLabel(cat)}
        </span>
        <span className={cn("rounded border px-2 py-0.5", riskLevelClass(level))}>
          {score}/100 · {level}
        </span>
        <span className="rounded border border-border/50 px-2 py-0.5 capitalize">
          {node.status}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-2 text-xs font-mono text-muted-foreground">
        <div>Connections: {node.connectionCount?.toLocaleString() ?? "—"}</div>
        <div>Traffic: {formatBytes(node.bytes)}</div>
        <div>First seen: {fmtWhen(node.firstSeen)}</div>
        <div>Last seen: {fmtWhen(node.lastSeen)}</div>
        <div>Packets: {node.packets?.toLocaleString() ?? "—"}</div>
        <div>Risk score: {score}/100</div>
      </div>
    </div>
  );
}

export { NetworkGraphWrapper as NetworkGraph };
