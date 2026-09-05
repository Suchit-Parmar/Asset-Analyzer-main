import { useCallback, useEffect, useMemo, useState } from "react";
import {
  NetworkGraph,
  NodeDetailPanel,
  type TopologyNodeView,
  type TopologyView,
} from "@/components/viz/NetworkGraph";
import { TrafficModeBadge } from "@/components/TrafficModeBadge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { EmptyState, PageLoader } from "@/components/states";
import {
  useNetworkEdges,
  useNetworkNodes,
  usePredictDataset,
  useTopology,
} from "@/hooks/useApi";
import { api, type LiveDetectionStatus } from "@/lib/api";
import {
  deviceCategory,
  deviceCategoryLabel,
  deviceFilterGroup,
  formatBytes,
  isValidHttpUrl,
  riskLevel,
  riskLevelClass,
  riskScore100,
  websiteDisplayName,
} from "@/lib/cyber-display";
import { toast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import {
  ChevronLeft,
  ChevronRight,
  Globe,
  Loader2,
  Pause,
  Play,
  Plus,
  RadioTower,
  Square,
} from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";

const MAX_TIMELINE_WINDOWS = 48;

const WINDOW_OPTIONS = [
  { value: 5, label: "5s" },
  { value: 10, label: "10s" },
  { value: 30, label: "30s" },
  { value: 60, label: "1 min" },
] as const;

const LIVE_WINDOW_OPTIONS = [
  { value: 5, label: "5s" },
  { value: 10, label: "10s" },
  { value: 30, label: "30s" },
] as const;

const TYPE_FILTERS = [
  { value: "all", label: "All" },
  { value: "computers", label: "Computers" },
  { value: "mobile", label: "Mobile" },
  { value: "servers", label: "Servers" },
  { value: "routers", label: "Routers" },
  { value: "iot", label: "IoT" },
  { value: "website", label: "Websites" },
  { value: "unknown", label: "Unknown" },
] as const;

type TimelineWindow = { start: number; end: number; label: string };

function buildTimelineWindows(
  edgeTimestamps: number[],
  windowSec: number,
): TimelineWindow[] {
  const step = Math.max(1, windowSec) * 1000;

  if (!edgeTimestamps.length) {
    const end = Date.now();
    return [{ start: end - step, end, label: "Current snapshot" }];
  }

  const t0 = edgeTimestamps[0];
  const t1 = edgeTimestamps[edgeTimestamps.length - 1];
  const span = Math.max(t1 - t0, step);

  // Aggregate a long chronological span into at most MAX_TIMELINE_WINDOWS buckets.
  const idealCount = Math.floor(span / step) + 1;
  const count = Math.min(MAX_TIMELINE_WINDOWS, Math.max(1, idealCount));
  const bucketWidth = Math.max(step, Math.ceil(span / count));

  const windows: TimelineWindow[] = [];
  for (let i = 0; i < count; i++) {
    const start = t0 + i * bucketWidth;
    const end = i === count - 1 ? Math.max(t1 + 1, start + step) : start + bucketWidth;
    windows.push({
      start,
      end,
      label: `${new Date(start).toLocaleTimeString()} – ${new Date(end).toLocaleTimeString()}`,
    });
  }
  return windows;
}

function edgesInWindow(
  edges: TopologyView["edges"],
  win: TimelineWindow,
): TopologyView["edges"] {
  return edges.filter((e) => {
    if (!e.timestamp) return false;
    const ts = new Date(e.timestamp).getTime();
    return Number.isFinite(ts) && ts >= win.start && ts < win.end;
  });
}

/** Soft time filter: prefer the selected window; otherwise nearest non-empty window. */
function resolveWindowEdges(
  edges: TopologyView["edges"],
  windows: TimelineWindow[],
  windowIndex: number,
): { edges: TopologyView["edges"]; usedNearest: boolean } {
  if (!windows.length) return { edges, usedNearest: false };
  const safeIndex = Math.min(Math.max(0, windowIndex), windows.length - 1);
  const selected = windows[safeIndex];
  const direct = edgesInWindow(edges, selected);
  if (direct.length > 0) return { edges: direct, usedNearest: false };

  let bestIdx = -1;
  let bestDist = Number.POSITIVE_INFINITY;
  for (let i = 0; i < windows.length; i++) {
    if (i === safeIndex) continue;
    const candidate = edgesInWindow(edges, windows[i]);
    if (!candidate.length) continue;
    const dist = Math.abs(i - safeIndex);
    if (dist < bestDist) {
      bestDist = dist;
      bestIdx = i;
    }
  }

  if (bestIdx >= 0) {
    return { edges: edgesInWindow(edges, windows[bestIdx]), usedNearest: true };
  }

  // No timestamped traffic in any window — keep chronological edges with timestamps if any.
  const timed = edges.filter((e) => e.timestamp);
  if (timed.length) return { edges: timed, usedNearest: true };
  return { edges, usedNearest: false };
}

function isPrivateIp(ip: string): boolean {
  return (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("127.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)
  );
}

/** Map a live AI snapshot onto the existing TopologyView shape (no second graph). */
function liveSnapshotToTopology(
  snapshot: NonNullable<LiveDetectionStatus["snapshot"]>,
): TopologyView {
  const nodes = (snapshot.nodes ?? []).map((raw) => {
    const n = raw as Record<string, unknown>;
    const ip = String(n.ip ?? "");
    const hostname = (n.hostname as string | null | undefined) ?? null;
    const external = ip ? !isPrivateIp(ip) : false;
    const websiteName =
      external && hostname ? websiteDisplayName(hostname) : external ? "Unknown" : null;
    return {
      id: String(n.id),
      label: hostname || ip || String(n.id),
      ip,
      type: String(n.type ?? "host"),
      status: String(n.status ?? "online"),
      risk: Number(n.risk_score ?? 0.1),
      vendor: external ? "website" : null,
      hostname: hostname || (external ? null : null),
      websiteName,
      packets: Number(n.packets ?? 0),
      bytes: Number(n.bytes ?? 0),
      connectionCount: Number(n.connections ?? 0),
      firstSeen: null,
      lastSeen: snapshot.timestamp ?? null,
    };
  });

  const edges = (snapshot.edges ?? []).map((raw, idx) => {
    const e = raw as Record<string, unknown>;
    return {
      id: `live-edge-${idx}`,
      source: String(e.source),
      target: String(e.target),
      protocol: String(e.protocol ?? "other"),
      weight: Math.min(Number(e.bytes ?? 0) / 1000, 10),
      packetCount: Number(e.packets ?? 0),
      timestamp: (e.timestamp as string | undefined) ?? snapshot.timestamp ?? null,
    };
  });

  return { nodes, edges };
}

export default function NetworkExplorer() {
  const queryClient = useQueryClient();
  const { data: topology, isLoading: topoLoading } = useTopology();
  const { data: nodesData } = useNetworkNodes(undefined, true);
  const { data: edgesData } = useNetworkEdges();
  const predictDataset = usePredictDataset();

  const [windowSec, setWindowSec] = useState(30);
  const [windowIndex, setWindowIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [selected, setSelected] = useState<TopologyNodeView | null>(null);
  /** Default remains Dataset Replay — LIVE only when user selects it. */
  const [detectionMode, setDetectionMode] = useState<"replay" | "live">("replay");
  const [websiteOpen, setWebsiteOpen] = useState(false);
  const [websiteUrl, setWebsiteUrl] = useState("https://");
  const [addingWebsite, setAddingWebsite] = useState(false);

  const [liveStatus, setLiveStatus] = useState<LiveDetectionStatus | null>(null);
  const [liveIfaces, setLiveIfaces] = useState<
    Array<{ name: string; display_name?: string; ipv4?: string | null; is_up?: boolean }>
  >([]);
  const [selectedIface, setSelectedIface] = useState("");
  const [liveBusy, setLiveBusy] = useState(false);
  const [liveError, setLiveError] = useState<string | null>(null);

  const handleSelectNode = useCallback((node: TopologyNodeView | null) => {
    setSelected(node);
  }, []);

  const nodeMeta = useMemo(() => {
    const map = new Map<
      string,
      {
        vendor?: string | null;
        hostname?: string | null;
        websiteName?: string | null;
        packets?: number | null;
        bytes?: number | null;
        connectionCount?: number | null;
        firstSeen?: string | null;
        lastSeen?: string | null;
      }
    >();
    for (const n of nodesData?.nodes ?? []) {
      const isWebsite = (n.vendor ?? "").toLowerCase().includes("website");
      map.set(n.id, {
        vendor: n.vendor,
        hostname: n.hostname,
        websiteName: isWebsite ? websiteDisplayName(n.hostname) : null,
        packets: n.packets,
        bytes: n.bytes,
        connectionCount: n.connectionCount,
        firstSeen: n.createdAt ?? null,
        lastSeen: n.lastSeenAt,
      });
    }
    return map;
  }, [nodesData]);

  const enrichedBase: TopologyView | null = useMemo(() => {
    if (!topology?.nodes?.length) return null;

    const edgeByPair = new Map<
      string,
      { packetCount?: number | null; timestamp?: string | null }
    >();
    for (const e of edgesData?.edges ?? []) {
      edgeByPair.set(`${e.sourceNodeId}->${e.targetNodeId}`, {
        packetCount: e.packetCount,
        timestamp: e.timestamp,
      });
    }

    return {
      nodes: topology.nodes.map((n) => {
        const meta = nodeMeta.get(n.id);
        return {
          id: n.id,
          label: n.label,
          ip: n.ip,
          type: n.type,
          status: n.status,
          risk: n.risk,
          vendor: meta?.vendor ?? n.vendor ?? null,
          hostname: meta?.hostname ?? n.hostname ?? null,
          websiteName: meta?.websiteName ?? n.websiteName ?? null,
          packets: meta?.packets ?? n.packets ?? null,
          bytes: meta?.bytes ?? n.bytes ?? null,
          connectionCount: meta?.connectionCount ?? n.connectionCount ?? null,
          firstSeen: meta?.firstSeen ?? n.firstSeen ?? null,
          lastSeen: meta?.lastSeen ?? n.lastSeen ?? null,
        };
      }),
      edges: topology.edges.map((e) => {
        const extra = edgeByPair.get(`${e.source}->${e.target}`);
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          protocol: e.protocol,
          weight: e.weight,
          packetCount: extra?.packetCount ?? e.packetCount ?? null,
          timestamp: extra?.timestamp ?? e.timestamp ?? null,
        };
      }),
    };
  }, [topology, nodeMeta, edgesData]);

  const timelineWindows = useMemo(() => {
    const stamps = [...(edgesData?.edges ?? [])]
      .map((e) => (e.timestamp ? new Date(e.timestamp).getTime() : NaN))
      .filter((ts): ts is number => Number.isFinite(ts))
      .sort((a, b) => a - b);

    if (!enrichedBase) return [] as TimelineWindow[];
    return buildTimelineWindows(stamps, windowSec);
  }, [edgesData, enrichedBase, windowSec]);

  useEffect(() => {
    setWindowIndex(0);
    setPlaying(false);
  }, [windowSec]);

  useEffect(() => {
    setWindowIndex((i) => {
      if (timelineWindows.length === 0) return 0;
      return Math.min(i, timelineWindows.length - 1);
    });
  }, [timelineWindows.length]);

  useEffect(() => {
    if (!playing || timelineWindows.length < 2) return;
    const id = window.setInterval(() => {
      setWindowIndex((i) => (i + 1) % timelineWindows.length);
    }, 1200);
    return () => window.clearInterval(id);
  }, [playing, timelineWindows.length]);

  const { filteredTopology, isEmptyWindow } = useMemo(() => {
    // LIVE mode: feed existing NetworkGraph from live snapshot (not a second viz).
    if (detectionMode === "live") {
      const snap = liveStatus?.snapshot;
      if (!snap || !Array.isArray(snap.nodes) || snap.nodes.length === 0) {
        return { filteredTopology: { nodes: [], edges: [] } as TopologyView, isEmptyWindow: true };
      }
      let view = liveSnapshotToTopology(snap);
      if (typeFilter !== "all") {
        let nodes = view.nodes.filter(
          (n) => deviceFilterGroup(deviceCategory(n.type, n.vendor)) === typeFilter,
        );
        const typedKeep = new Set(nodes.map((n) => n.id));
        const edges = view.edges.filter((e) => typedKeep.has(e.source) && typedKeep.has(e.target));
        view = { nodes, edges };
      }
      if (!view.nodes.length) {
        return { filteredTopology: { nodes: [], edges: [] }, isEmptyWindow: true };
      }
      return { filteredTopology: view, isEmptyWindow: false };
    }

    if (!enrichedBase) {
      return { filteredTopology: null as TopologyView | null, isEmptyWindow: false };
    }

    const resolved = resolveWindowEdges(
      enrichedBase.edges,
      timelineWindows,
      windowIndex,
    );
    let edges = resolved.edges;
    const keepIds = new Set(edges.flatMap((e) => [e.source, e.target]));
    let nodes =
      keepIds.size > 0
        ? enrichedBase.nodes.filter((n) => keepIds.has(n.id))
        : enrichedBase.nodes;

    if (typeFilter !== "all") {
      nodes = nodes.filter(
        (n) => deviceFilterGroup(deviceCategory(n.type, n.vendor)) === typeFilter,
      );
      const typedKeep = new Set(nodes.map((n) => n.id));
      edges = edges.filter((e) => typedKeep.has(e.source) && typedKeep.has(e.target));
    }

    if (!nodes.length) {
      return { filteredTopology: { nodes: [], edges: [] }, isEmptyWindow: true };
    }

    return {
      filteredTopology: { nodes, edges },
      isEmptyWindow: false,
    };
  }, [
    detectionMode,
    liveStatus?.snapshot,
    enrichedBase,
    timelineWindows,
    windowIndex,
    typeFilter,
  ]);

  const windowStats = useMemo(() => {
    const nodes = filteredTopology?.nodes ?? [];
    const edges = filteredTopology?.edges ?? [];
    const suspicious = nodes.filter(
      (n) =>
        n.status === "suspicious" ||
        n.status === "compromised" ||
        riskScore100(n.risk) >= 60,
    );
    const bytes = nodes.reduce((s, n) => s + (n.bytes ?? 0), 0);
    return {
      nodes: nodes.length,
      edges: edges.length,
      suspicious: suspicious.length,
      bytes,
    };
  }, [filteredTopology]);

  async function handleReplay() {
    try {
      setDetectionMode("replay");
      setPlaying(true);
      const result = await predictDataset.mutateAsync({
        datasetId: "cicids2017",
        maxRows: 3000,
        windowSeconds: windowSec,
      });
      toast({
        title: "Dataset replay complete",
        description: `${result.attackType} · ${Math.round((result.confidence ?? 0) * 100)}% confidence (not live capture)`,
      });
      await queryClient.invalidateQueries({ queryKey: ["network"] });
      await queryClient.invalidateQueries({ queryKey: ["predictions"] });
      await queryClient.invalidateQueries({ queryKey: ["alerts"] });
    } catch (err) {
      toast({
        title: "Replay failed",
        description: err instanceof Error ? err.message : "Prediction failed",
        variant: "destructive",
      });
    }
  }

  // Load NICs when entering LIVE mode (does not start capture).
  useEffect(() => {
    if (detectionMode !== "live") return;
    let cancelled = false;
    (async () => {
      try {
        const res = await api.getLiveInterfaces();
        if (cancelled) return;
        const list = res.interfaces ?? [];
        setLiveIfaces(list);
        setSelectedIface((prev) => prev || list.find((i) => i.is_up !== false)?.name || list[0]?.name || "");
        const st = await api.getLiveStatus();
        if (!cancelled) setLiveStatus(st);
      } catch (err) {
        if (!cancelled) {
          setLiveError(err instanceof Error ? err.message : "Could not load live interfaces");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [detectionMode]);

  // Poll live status while LIVE mode is selected.
  useEffect(() => {
    if (detectionMode !== "live") return;
    let cancelled = false;
    const tick = async () => {
      try {
        const st = await api.getLiveStatus();
        if (cancelled) return;
        setLiveStatus(st);
        if (st.error) setLiveError(st.error);
        if (st.running) {
          await queryClient.invalidateQueries({ queryKey: ["network"] });
          await queryClient.invalidateQueries({ queryKey: ["predictions"] });
        }
      } catch {
        // keep last status; badge shows disconnect via next status call
      }
    };
    void tick();
    const id = window.setInterval(tick, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [detectionMode, queryClient]);

  // Live capture keeps running while Network Graph stays mounted in the background
  // (see NetworkGraphKeepAlive). Explicit Stop / Replay switch / logout still stop it.

  async function handleLiveStart() {
    if (!selectedIface) {
      toast({
        title: "Select an interface",
        description: "Choose an authorized local network interface first.",
        variant: "destructive",
      });
      return;
    }
    setLiveBusy(true);
    setLiveError(null);
    try {
      const win = LIVE_WINDOW_OPTIONS.some((w) => w.value === windowSec) ? windowSec : 5;
      setWindowSec(win);
      const st = await api.startLive({ interface: selectedIface, windowSeconds: win });
      setLiveStatus(st);
      toast({
        title: "LIVE detection started",
        description: `Monitoring ${selectedIface} · ${win}s windows (authorized local only)`,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to start live detection";
      setLiveError(msg);
      toast({ title: "Live Detection Unavailable", description: msg, variant: "destructive" });
    } finally {
      setLiveBusy(false);
    }
  }

  async function handleLiveStop() {
    setLiveBusy(true);
    try {
      const st = await api.stopLive();
      setLiveStatus(st);
      toast({ title: "LIVE detection stopped" });
    } catch (err) {
      toast({
        title: "Stop failed",
        description: err instanceof Error ? err.message : "Could not stop capture",
        variant: "destructive",
      });
    } finally {
      setLiveBusy(false);
    }
  }

  async function handleAddWebsite() {
    if (!isValidHttpUrl(websiteUrl)) {
      toast({
        title: "Invalid URL",
        description: "Enter a valid http(s) URL.",
        variant: "destructive",
      });
      return;
    }
    setAddingWebsite(true);
    try {
      const res = await api.addWebsite({ url: websiteUrl.trim() });
      const name = res.websiteName || res.node.hostname || "Website";
      toast({
        title: "Website added",
        description: `${name} · ${res.node.hostname ?? ""} stored as observable graph identity (no intrusive scan).`,
      });
      setWebsiteOpen(false);
      setWebsiteUrl("https://");
      await queryClient.invalidateQueries({ queryKey: ["network"] });
    } catch (err) {
      toast({
        title: "Could not add website",
        description: err instanceof Error ? err.message : "Request failed",
        variant: "destructive",
      });
    } finally {
      setAddingWebsite(false);
    }
  }

  if (topoLoading) {
    return <PageLoader label="Loading network graph…" />;
  }

  const currentWindow = timelineWindows[Math.min(windowIndex, Math.max(0, timelineWindows.length - 1))];
  const liveRunning = Boolean(liveStatus?.running);
  const trafficMode =
    detectionMode === "live"
      ? liveRunning
        ? "live"
        : liveStatus?.status === "waiting"
          ? "live"
          : "awaiting"
      : "replay";

  const liveStats = liveStatus?.stats;
  const secondsAgo = liveStatus?.last_update
    ? Math.max(0, Math.round((Date.now() - new Date(liveStatus.last_update).getTime()) / 1000))
    : null;

  return (
    <>
      <main className="flex-1 overflow-auto p-4 md:p-6 space-y-4">
        <header className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="text-[11px] uppercase tracking-[0.18em] text-muted-foreground mb-2">
              Dynamic Graph
            </div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-2">
              <RadioTower className="h-7 w-7 text-primary" />
              Network Graph
            </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
              Timestamp-windowed topology with device filters. Hover nodes/edges for details; use
              playback to replay activity over time.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <TrafficModeBadge mode={trafficMode} />
            <Button size="sm" variant="outline" onClick={() => setWebsiteOpen(true)}>
              <Plus className="h-4 w-4 mr-1" /> Add Website
            </Button>
            <Button size="sm" onClick={handleReplay} disabled={predictDataset.isPending || liveRunning}>
              {predictDataset.isPending ? (
                <Loader2 className="h-4 w-4 mr-1 animate-spin" />
              ) : (
                <Play className="h-4 w-4 mr-1" />
              )}
              Dataset Replay
            </Button>
          </div>
        </header>

        <Card className="panel-card">
          <CardContent className="pt-4 flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-muted-foreground mr-1">Detection Mode</span>
              <Button
                size="sm"
                variant={detectionMode === "live" ? "default" : "outline"}
                onClick={() => setDetectionMode("live")}
              >
                LIVE
              </Button>
              <Button
                size="sm"
                variant={detectionMode === "replay" ? "default" : "outline"}
                onClick={() => {
                  if (liveRunning) void handleLiveStop();
                  setDetectionMode("replay");
                }}
              >
                DATASET REPLAY
              </Button>
              <span className="text-[10px] text-muted-foreground font-mono ml-2">
                {detectionMode === "live"
                  ? "LIVE = Authorized Local Network Monitoring"
                  : "DATASET REPLAY = Historical/Demo Traffic"}
              </span>
            </div>

            {detectionMode === "live" && (
              <div className="flex flex-col gap-3 rounded border border-border/50 bg-black/20 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs text-muted-foreground">Network Interface</span>
                  <select
                    className="h-8 rounded border border-border/60 bg-background px-2 text-xs font-mono max-w-[280px]"
                    value={selectedIface}
                    onChange={(e) => setSelectedIface(e.target.value)}
                    disabled={liveRunning || liveBusy}
                  >
                    {liveIfaces.length === 0 && <option value="">No interfaces found</option>}
                    {liveIfaces.map((iface) => (
                      <option key={iface.name} value={iface.name}>
                        {iface.display_name || iface.name}
                        {iface.ipv4 ? ` (${iface.ipv4})` : ""}
                        {iface.is_up === false ? " [down]" : ""}
                      </option>
                    ))}
                  </select>
                  {!liveRunning ? (
                    <Button size="sm" onClick={handleLiveStart} disabled={liveBusy || !selectedIface}>
                      {liveBusy ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Play className="h-4 w-4 mr-1" />}
                      Start Live Detection
                    </Button>
                  ) : (
                    <Button size="sm" variant="destructive" onClick={handleLiveStop} disabled={liveBusy}>
                      {liveBusy ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Square className="h-4 w-4 mr-1" />}
                      Stop
                    </Button>
                  )}
                </div>
                <div className="text-xs font-mono text-muted-foreground flex flex-wrap gap-x-4 gap-y-1">
                  <span>
                    {liveRunning
                      ? liveStatus?.status === "waiting"
                        ? "● LIVE DETECTION ACTIVE (waiting for traffic)"
                        : "● LIVE DETECTION ACTIVE"
                      : "● LIVE DETECTION STOPPED"}
                  </span>
                  {liveRunning && (
                    <>
                      <span>Monitoring: {liveStatus?.interface || selectedIface}</span>
                      <span>Window: {liveStatus?.window_seconds ?? windowSec} sec</span>
                      <span>
                        Last update:{" "}
                        {secondsAgo == null ? "—" : `${secondsAgo} sec ago`}
                      </span>
                    </>
                  )}
                </div>
                {(liveError || liveStatus?.error) && (
                  <div className="text-xs text-amber-300 border border-amber-500/30 rounded p-2 bg-amber-500/10">
                    <div className="font-semibold mb-1">Live Detection Unavailable</div>
                    {liveError || liveStatus?.error}
                  </div>
                )}
                {liveRunning && liveStatus?.status === "waiting" && (
                  <div className="text-xs text-cyan-300">Waiting for network traffic...</div>
                )}
                {liveRunning && liveStatus?.prediction?.message === "Prediction unavailable" && (
                  <div className="text-xs text-muted-foreground">Prediction unavailable</div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {detectionMode === "live" ? (
            <>
              <Stat label="Active nodes" value={String(liveStats?.active_nodes ?? windowStats.nodes)} />
              <Stat label="Connections" value={String(liveStats?.connections ?? windowStats.edges)} />
              <Stat label="Flows" value={String(liveStats?.flows ?? 0)} />
              <Stat label="Threats" value={String(liveStats?.threats ?? 0)} accent="text-red-400" />
              <Stat
                label="Suspicious nodes"
                value={String(liveStats?.suspicious_nodes ?? windowStats.suspicious)}
                accent="text-orange-400"
              />
            </>
          ) : (
            <>
              <Stat label="Current window" value={currentWindow?.label ?? "—"} mono />
              <Stat label="Active nodes" value={String(windowStats.nodes)} />
              <Stat label="Connections" value={String(windowStats.edges)} />
              <Stat label="Suspicious" value={String(windowStats.suspicious)} accent="text-orange-400" />
              <Stat label="Traffic volume" value={formatBytes(windowStats.bytes)} />
            </>
          )}
        </div>

        <Card className="panel-card">
          <CardContent className="pt-4 flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-muted-foreground mr-1">Time window</span>
              {(detectionMode === "live" ? LIVE_WINDOW_OPTIONS : WINDOW_OPTIONS).map((w) => (
                <Button
                  key={w.value}
                  size="sm"
                  variant={windowSec === w.value ? "default" : "outline"}
                  disabled={detectionMode === "live" && liveRunning}
                  onClick={() => setWindowSec(w.value)}
                >
                  {w.label}
                </Button>
              ))}
              {detectionMode === "replay" && (
                <>
                  <div className="mx-2 h-5 w-px bg-border/60" />
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setWindowIndex((i) => Math.max(0, i - 1))}
                    disabled={windowIndex <= 0}
                  >
                    <ChevronLeft className="h-4 w-4" />
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => setPlaying((p) => !p)}>
                    {playing ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() =>
                      setWindowIndex((i) => Math.min(Math.max(0, timelineWindows.length - 1), i + 1))
                    }
                    disabled={windowIndex >= timelineWindows.length - 1}
                  >
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                  <input
                    type="range"
                    min={0}
                    max={Math.max(0, timelineWindows.length - 1)}
                    value={Math.min(windowIndex, Math.max(0, timelineWindows.length - 1))}
                    onChange={(e) => {
                      setPlaying(false);
                      setWindowIndex(Number(e.target.value));
                    }}
                    className="w-40 accent-cyan-400"
                  />
                  <span className="text-xs font-mono text-muted-foreground">
                    {timelineWindows.length === 0 ? "0/0" : `${windowIndex + 1}/${timelineWindows.length}`}
                  </span>
                </>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs text-muted-foreground mr-1">Device type</span>
              {TYPE_FILTERS.map((f) => (
                <Button
                  key={f.value}
                  size="sm"
                  variant={typeFilter === f.value ? "default" : "outline"}
                  onClick={() => setTypeFilter(f.value)}
                >
                  {f.label}
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-4 min-h-[480px]">
          <div className="h-[520px]">
            {isEmptyWindow ? (
              <div className="h-full rounded-lg border border-border/50 bg-card/20 flex items-center justify-center">
                <EmptyState
                  title={
                    detectionMode === "live"
                      ? liveRunning
                        ? "Waiting for network traffic..."
                        : "LIVE detection stopped"
                      : "No nodes in this window"
                  }
                  message={
                    detectionMode === "live"
                      ? liveRunning
                        ? "Authorized capture is running. Flows will appear after the next time window."
                        : "Select an interface and start live detection."
                      : "Widen the time window or clear device filters."
                  }
                />
              </div>
            ) : (
              <NetworkGraph
                topology={filteredTopology}
                mode={trafficMode}
                selectedNodeId={selected?.id ?? null}
                onSelectNode={handleSelectNode}
              />
            )}
          </div>

          <div className="space-y-3">
            <NodeDetailPanel node={selected} onClose={() => setSelected(null)} />
            <Card className="panel-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Top risk in window</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {(filteredTopology?.nodes ?? [])
                  .slice()
                  .sort((a, b) => b.risk - a.risk)
                  .slice(0, 6)
                  .map((n) => {
                    const score = riskScore100(n.risk);
                    const level = riskLevel(score);
                    return (
                      <button
                        key={n.id}
                        type="button"
                        className="w-full text-left rounded border border-border/50 px-2 py-1.5 hover:bg-white/5"
                        onClick={() => setSelected(n)}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-xs truncate">
                            {n.websiteName || n.hostname || n.ip}
                          </span>
                          <Badge className={cn("border text-[10px]", riskLevelClass(level))}>
                            {score}
                          </Badge>
                        </div>
                        <div className="text-[10px] text-muted-foreground truncate">
                          {n.hostname && n.hostname !== n.ip ? `${n.hostname} · ` : ""}
                          {n.ip} · {deviceCategoryLabel(deviceCategory(n.type, n.vendor))}
                        </div>
                      </button>
                    );
                  })}
                {!(filteredTopology?.nodes?.length) && (
                  <p className="text-xs text-muted-foreground">No nodes to rank in this view.</p>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </main>

      <Dialog open={websiteOpen} onOpenChange={setWebsiteOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-primary" /> Add Website
            </DialogTitle>
            <DialogDescription>
              Adds an external host as a graph entity using only observable metadata (domain / URL).
              No intrusive scanning or exploitation is performed.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 py-2">
            <label className="text-xs text-muted-foreground">Website URL</label>
            <Input
              value={websiteUrl}
              onChange={(e) => setWebsiteUrl(e.target.value)}
              placeholder="https://example.com"
            />
            <p className="text-[11px] text-muted-foreground">
              Labelled as <span className="text-cyan-300">demo / observable</span> metadata in the
              device list.
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setWebsiteOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleAddWebsite} disabled={addingWebsite}>
              {addingWebsite ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : null}
              Analyze Website
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>

  );
}

function Stat({
  label,
  value,
  accent,
  mono,
}: {
  label: string;
  value: string;
  accent?: string;
  mono?: boolean;
}) {
  return (
    <Card className="panel-card">
      <CardContent className="pt-3 pb-3">
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
        <div
          className={cn(
            "mt-1 text-sm font-semibold truncate",
            mono && "font-mono text-xs",
            accent ?? "text-white",
          )}
        >
          {value}
        </div>
      </CardContent>
    </Card>
  );
}
