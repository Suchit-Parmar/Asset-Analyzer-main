import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Slider } from "@/components/ui/slider";
import { Play, RotateCcw, Save, Database, BrainCircuit, Activity, Wifi, Gauge, Server, Clock } from "lucide-react";
import { TrainingTerminal, type LogEntry } from "@/components/viz/TrainingTerminal";
import { EmptyState } from "@/components/states";
import { useToast } from "@/hooks/use-toast";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  useStartTraining,
  useTrainingRuns,
  useModelInfo,
  useDashboardMetrics,
  useMetrics,
  usePredictions,
  useTopology,
  useStudioConfig,
  useSaveStudioConfig,
} from "@/hooks/useApi";

const DATASET_MAP: Record<string, string> = {
  unsw: "unsw_nb15",
  cicids2017: "cicids2017",
  cse_cic_ids2018: "cse_cic_ids2018",
  ton_iot_live: "ton_iot",
  darpa: "nsl_kdd",
};

const LIVE_DATASET_ID = "unsw";
// `enabled: false` datasets have no local loader yet — shown as "Coming Soon"
// and not selectable so users can only train pipelines that actually exist.
const DATASET_OPTIONS = [
  { id: "unsw", label: "UNSW-NB15", mode: "batch" as const, description: "Real intrusion detection benchmark", source: "UNSW Canberra", enabled: true },
  { id: "cicids2017", label: "CICIDS2017", mode: "batch" as const, description: "Enterprise network flows", source: "Canadian Institute", enabled: true },
  { id: "cse_cic_ids2018", label: "CSE-CIC-IDS2018", mode: "batch" as const, description: "Modern enterprise attack flows (CICFlowMeter)", source: "CSE / Canadian Institute", enabled: true },
  { id: "ton_iot_live", label: "TON-IoT", mode: "live" as const, description: "IoT/IIoT telemetry dataset", source: "UNSW CERT", enabled: false },
  { id: "darpa", label: "NSL-KDD", mode: "batch" as const, description: "Classic KDD cup dataset", source: "NSL-KDD", enabled: false },
];

function getDatasetOption(id: string) {
  return DATASET_OPTIONS.find((o) => o.id === id) ?? DATASET_OPTIONS[0];
}

type GraphStrategy = "endpoint" | "flow" | "similarity" | "temporal";

// Graph construction strategies (Module C). Each genuinely changes how the
// backend builds graphs before training/inference.
const GRAPH_STRATEGY_OPTIONS: { id: GraphStrategy; label: string; description: string }[] = [
  { id: "endpoint", label: "Endpoint Graph", description: "Nodes = endpoints (IPs); edges = communications." },
  { id: "flow", label: "Flow Graph", description: "Nodes = flows; edges = sequential/related flows." },
  { id: "similarity", label: "Feature Similarity", description: "Nodes = flows; edges via cosine/kNN similarity." },
  { id: "temporal", label: "Temporal Sliding Window", description: "Endpoint graphs over sliding time windows." },
];

const GRAPH_STRATEGY_LABELS: Record<string, string> = Object.fromEntries(
  GRAPH_STRATEGY_OPTIONS.map((o) => [o.id, o.label]),
);

/** Model Studio feature toggles — must match ai/app/services/config_store.py */
const DEFAULT_FEATURE_SET: Record<string, boolean> = {
  timestamp: true,
  packet_size: true,
  protocol: true,
  ports: true,
  flow_duration: true,
  tcp_flags: false,
};

const FEATURE_OPTIONS: { id: keyof typeof DEFAULT_FEATURE_SET; label: string }[] = [
  { id: "timestamp", label: "Timestamp" },
  { id: "packet_size", label: "Packet Size" },
  { id: "protocol", label: "Protocol" },
  { id: "ports", label: "Port No." },
  { id: "flow_duration", label: "Flow Duration" },
  { id: "tcp_flags", label: "TCP Flags" },
];

function sliderToLR(val: number): string {
  return (0.0001 * Math.pow(100, val / 100)).toFixed(4);
}

function sliderToHiddenDim(val: number): number {
  const dims = [32, 64, 128, 256, 512];
  return dims[Math.round((val / 100) * (dims.length - 1))];
}

const DATASET_LABELS: Record<string, string> = {
  unsw_nb15: "UNSW-NB15",
  cicids2017: "CICIDS2017",
  cse_cic_ids2018: "CSE-CIC-IDS2018",
  ton_iot: "TON-IoT",
  nsl_kdd: "NSL-KDD",
};

/** Human-readable absolute timestamp (e.g. "Jul 12, 8:31 PM"). */
function formatTimestamp(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

/** Short clock label for chart axes (e.g. "8:31:04 PM"). */
function formatClock(iso?: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit", second: "2-digit" });
}

/** Relative "time ago" for the last-update label. */
function timeAgo(iso?: string | null): string {
  if (!iso) return "no data yet";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "no data yet";
  const secs = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}

/** Low / Medium / High colour band for a 0–100 threat score. */
function threatBand(score: number) {
  if (score >= 67) return { label: "High", text: "text-red-300", badge: "bg-red-500/15 text-red-300 border-red-500/30" };
  if (score >= 34) return { label: "Medium", text: "text-amber-300", badge: "bg-amber-500/15 text-amber-300 border-amber-500/30" };
  return { label: "Low", text: "text-emerald-300", badge: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" };
}

function pct(value: number | undefined | null, digits = 0): number {
  if (typeof value !== "number" || Number.isNaN(value)) return 0;
  return Number((value * 100).toFixed(digits));
}

type TopologyNode = { id: string; label: string; ip: string; type: string; status: string; risk: number };
type TopologyEdge = { id: string; source: string; target: string; protocol: string; weight: number };

function nodeColor(status: string, risk: number): string {
  if (status === "compromised" || risk >= 0.67) return "#ef4444";
  if (status === "suspicious" || risk >= 0.34) return "#f59e0b";
  return "hsl(186 95% 55%)";
}

/**
 * Compact SVG network preview built from real topology data. Used to fill a
 * chart panel that has no series data yet (instead of a blank graph).
 */
function MiniNetworkPreview({ nodes, edges }: { nodes: TopologyNode[]; edges: TopologyEdge[] }) {
  const shown = nodes.slice(0, 16);
  const n = shown.length;
  const index = new Map(shown.map((node, i) => [node.id, i]));
  const cx = 50;
  const cy = 50;
  const r = 34;
  const pos = shown.map((_, i) => {
    const a = (i / Math.max(n, 1)) * Math.PI * 2 - Math.PI / 2;
    return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
  });
  const visibleEdges = edges
    .filter((e) => index.has(e.source) && index.has(e.target))
    .slice(0, 40);

  return (
    <div className="flex h-full flex-col items-center justify-center gap-2">
      <svg viewBox="0 0 100 100" className="h-[190px] w-[190px]" role="img" aria-label="Network topology preview">
        {visibleEdges.map((e) => {
          const a = pos[index.get(e.source)!];
          const b = pos[index.get(e.target)!];
          return (
            <line
              key={e.id}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke="rgba(148, 163, 184, 0.25)"
              strokeWidth={0.4}
            />
          );
        })}
        {shown.map((node, i) => (
          <circle
            key={node.id}
            cx={pos[i].x}
            cy={pos[i].y}
            r={2.6}
            fill={nodeColor(node.status, node.risk)}
            opacity={0.9}
          />
        ))}
      </svg>
      <div className="text-center text-xs text-muted-foreground">
        {n > 0
          ? `Live topology preview · ${nodes.length} node${nodes.length === 1 ? "" : "s"}`
          : "Network topology will appear once traffic is analyzed."}
      </div>
    </div>
  );
}

export default function Experiment() {
  const { toast } = useToast();
  const startTrainingMutation = useStartTraining();
  const { data: runsData } = useTrainingRuns();
  const [isTraining, setIsTraining] = useState(false);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [lrSlider, setLrSlider] = useState(30);
  const [hiddenSlider, setHiddenSlider] = useState(60);
  const [selectedDataset, setSelectedDataset] = useState("unsw");
  const [graphStrategy, setGraphStrategy] = useState<GraphStrategy>("temporal");
  const [modelVariant, setModelVariant] = useState<"gcn" | "gat" | "graphsage" | "tgn">("tgn");

  // Per-strategy graph parameters (Module C).
  const [directed, setDirected] = useState(true);
  const [flowDistance, setFlowDistance] = useState(1);
  const [simMetric, setSimMetric] = useState<"cosine" | "knn">("cosine");
  const [simThreshold, setSimThreshold] = useState(0.8);
  const [simNeighbors, setSimNeighbors] = useState(5);
  const [windowSize, setWindowSize] = useState(30);
  const [windowOverlap, setWindowOverlap] = useState(0);
  const [featureSet, setFeatureSet] = useState<Record<string, boolean>>({ ...DEFAULT_FEATURE_SET });

  const { data: studioConfig } = useStudioConfig();
  const saveConfigMutation = useSaveStudioConfig();

  const { data: modelInfo } = useModelInfo();
  const { data: dashboard } = useDashboardMetrics();
  const { data: metricsResp } = useMetrics();
  const { data: predictionsData } = usePredictions();
  const { data: topology } = useTopology();

  const dataset = getDatasetOption(selectedDataset);
  const isLiveDataset = dataset.mode === "live";

  const latestRun = runsData?.runs?.[0];

  // Full per-epoch training history (accuracy, precision, recall, f1, losses).
  type HistoryRow = {
    epoch: number;
    train_loss?: number;
    val_loss?: number;
    train_accuracy?: number;
    val_accuracy?: number;
    precision?: number;
    recall?: number;
    f1?: number;
  };
  const historyData = useMemo<HistoryRow[]>(() => {
    const runHistory = (latestRun?.metrics as { history?: HistoryRow[] } | undefined)?.history;
    const metricHistory = (metricsResp?.metrics as { history?: HistoryRow[] } | undefined)?.history;
    const source = runHistory?.length ? runHistory : metricHistory;
    return Array.isArray(source) ? source : [];
  }, [latestRun, metricsResp]);

  const qualityData = useMemo(
    () =>
      historyData.map((h) => ({
        time: `E${h.epoch}`,
        accuracy: pct(h.val_accuracy, 1),
        precision: pct(h.precision, 1),
        recall: pct(h.recall, 1),
        f1: pct(h.f1, 1),
      })),
    [historyData],
  );

  // Active model summary (the checkpoint currently loaded by the AI service).
  const modelMetrics = (modelInfo?.metrics ?? {}) as Record<string, number>;
  const activeDatasetId = modelInfo?.dataset_id ?? (metricsResp?.dataset_id as string | undefined);
  const activeDatasetLabel = activeDatasetId ? DATASET_LABELS[activeDatasetId] ?? activeDatasetId : "—";
  const modelAccuracy = pct(modelMetrics.accuracy);
  const activeStrategy = (modelInfo as unknown as { graph_strategy?: string } | undefined)?.graph_strategy;
  const activeStrategyLabel = activeStrategy ? GRAPH_STRATEGY_LABELS[activeStrategy] ?? activeStrategy : null;
  const activeFeatureSet = (modelInfo as unknown as { feature_set?: Record<string, unknown> } | undefined)?.feature_set;
  const activeFeaturesLabel = useMemo(() => {
    if (!activeFeatureSet) return null;
    const enabled = FEATURE_OPTIONS.filter((f) => activeFeatureSet[f.id] !== false).map((f) => f.label);
    return enabled.length ? enabled.join(", ") : "None";
  }, [activeFeatureSet]);

  // Live system state from the running backend (network + alerts).
  const net = dashboard?.network ?? { total: 0, compromised: 0, suspicious: 0, avgRisk: 0 };
  const alertsSummary = dashboard?.alerts ?? { total: 0, critical: 0, high: 0, open: 0 };
  const monitoredNodes = net.total;
  const maliciousShare = net.total > 0 ? Math.round(((net.compromised + net.suspicious) / net.total) * 100) : 0;
  const threatScore = Math.round((net.avgRisk ?? 0) * 100);
  const threat = threatBand(threatScore);
  const lastUpdated = modelInfo?.trained_at ?? dashboard?.timestamp ?? latestRun?.createdAt ?? null;

  // Throughput lane: prefer the real inference stream (recent predictions);
  // fall back to the training loss curve when no predictions exist yet.
  const predictions = predictionsData?.predictions ?? [];
  const throughputMode: "live" | "history" = predictions.length >= 2 ? "live" : "history";
  const throughputData = useMemo(() => {
    if (throughputMode === "live") {
      return [...predictions]
        .reverse()
        .map((p) => ({
          time: formatClock(p.createdAt),
          primary: pct(p.confidence),
          secondary: pct(p.riskScore),
        }));
    }
    return historyData.map((h) => ({
      time: `E${h.epoch}`,
      primary: Number((h.train_loss ?? 0).toFixed(3)),
      secondary: Number((h.val_loss ?? 0).toFixed(3)),
    }));
  }, [throughputMode, predictions, historyData]);
  const throughputPrimaryName = throughputMode === "live" ? "Confidence %" : "Train Loss";
  const throughputSecondaryName = throughputMode === "live" ? "Risk %" : "Val Loss";

  const topoNodes = (topology?.nodes ?? []) as TopologyNode[];
  const topoEdges = (topology?.edges ?? []) as TopologyEdge[];
  const hasTopology = topoNodes.length > 0;

  // Assemble strategy-specific graph parameters sent to the backend.
  const graphParams = useMemo<Record<string, unknown>>(() => {
    switch (graphStrategy) {
      case "endpoint":
        return { directed };
      case "flow":
        return { flow_sequential_distance: flowDistance, directed };
      case "similarity":
        return {
          similarity_metric: simMetric,
          similarity_threshold: simThreshold,
          similarity_neighbors: simNeighbors,
        };
      case "temporal":
      default:
        return { window_size: windowSize, window_overlap: windowOverlap };
    }
  }, [graphStrategy, directed, flowDistance, simMetric, simThreshold, simNeighbors, windowSize, windowOverlap]);

  // Load the persisted Studio configuration once it arrives (auto-reload).
  useEffect(() => {
    if (!studioConfig) return;
    const s = studioConfig.graph_strategy as GraphStrategy | undefined;
    if (s && ["endpoint", "flow", "similarity", "temporal"].includes(s)) setGraphStrategy(s);
    const p = (studioConfig.graph_params ?? {}) as Record<string, unknown>;
    if (typeof p.directed === "boolean") setDirected(p.directed);
    if (p.flow_sequential_distance != null) setFlowDistance(Number(p.flow_sequential_distance));
    if (p.similarity_metric) setSimMetric(p.similarity_metric === "knn" ? "knn" : "cosine");
    if (p.similarity_threshold != null) setSimThreshold(Number(p.similarity_threshold));
    if (p.similarity_neighbors != null) setSimNeighbors(Number(p.similarity_neighbors));
    if (p.window_size != null) setWindowSize(Number(p.window_size));
    if (p.window_overlap != null) setWindowOverlap(Number(p.window_overlap));
    if (studioConfig.feature_set) {
      setFeatureSet({ ...DEFAULT_FEATURE_SET, ...studioConfig.feature_set });
    }
    if (studioConfig.dataset_id) {
      const uiId = Object.entries(DATASET_MAP).find(([, v]) => v === studioConfig.dataset_id)?.[0];
      if (uiId) setSelectedDataset(uiId);
    }
    if (studioConfig.architecture) {
      const arch = studioConfig.architecture;
      if (arch === "gcn" || arch === "gat" || arch === "graphsage") {
        setModelVariant(arch);
      }
    }
    const hp = studioConfig.hyperparameters ?? {};
    if (hp.learning_rate != null) {
      const lr = Number(hp.learning_rate);
      const slider = Math.round((Math.log10(lr / 0.0001) / 2) * 100);
      if (!Number.isNaN(slider)) setLrSlider(Math.min(100, Math.max(0, slider)));
    }
    if (hp.hidden_dim != null) {
      const dims = [32, 64, 128, 256, 512];
      const idx = dims.indexOf(Number(hp.hidden_dim));
      if (idx >= 0) setHiddenSlider(Math.round((idx / (dims.length - 1)) * 100));
    }
  }, [studioConfig]);

  const handleReset = () => {
    setSelectedDataset("unsw");
    setGraphStrategy("temporal");
    setModelVariant("tgn");
    setDirected(true);
    setFlowDistance(1);
    setSimMetric("cosine");
    setSimThreshold(0.8);
    setSimNeighbors(5);
    setWindowSize(30);
    setWindowOverlap(0);
    setFeatureSet({ ...DEFAULT_FEATURE_SET });
    setLrSlider(30);
    setHiddenSlider(60);
    setLogs([]);
    setProgress(0);
    setIsTraining(false);
    toast({
      title: "Configuration reset",
      description: "Model Studio switched back to the live replay dataset and default hyperparameters.",
    });
  };

  const handleSaveConfig = async () => {
    try {
      await saveConfigMutation.mutateAsync({
        dataset_id: DATASET_MAP[selectedDataset] ?? "unsw_nb15",
        architecture: modelVariant === "tgn" ? "gat" : modelVariant,
        graph_strategy: graphStrategy,
        graph_params: graphParams,
        feature_set: featureSet,
        hyperparameters: {
          learning_rate: parseFloat(sliderToLR(lrSlider)),
          hidden_dim: sliderToHiddenDim(hiddenSlider),
        },
      });
      toast({
        title: "Configuration saved",
        description: `${GRAPH_STRATEGY_LABELS[graphStrategy]} + ${Object.values(featureSet).filter(Boolean).length} features saved — will auto-load on next visit.`,
      });
    } catch (err) {
      toast({
        title: "Save failed",
        description: err instanceof Error ? err.message : "Unknown error",
        variant: "destructive",
      });
    }
  };

  const startTraining = async () => {
    if (!dataset.enabled) {
      toast({
        title: "Dataset not available",
        description: `${dataset.label} is coming soon and cannot be trained yet.`,
        variant: "destructive",
      });
      return;
    }

    setIsTraining(true);
    setLogs([]);
    setProgress(0);

    const datasetId = DATASET_MAP[selectedDataset] ?? "unsw_nb15";
    setLogs([{ text: `[INFO] Starting TGNN training on ${datasetId}...`, time: new Date().toLocaleTimeString() }]);

    try {
      await startTrainingMutation.mutateAsync({
        datasetId,
        architecture: modelVariant === "tgn" ? "gat" : modelVariant,
        hyperparameters: {
          learning_rate: parseFloat(sliderToLR(lrSlider)),
          hidden_dim: sliderToHiddenDim(hiddenSlider),
        },
        epochs: 50,
        graphStrategy,
        graphParams,
        featureSet,
      });
      setLogs((prev) => [
        ...prev,
        { text: `[INFO] Graph strategy: ${GRAPH_STRATEGY_LABELS[graphStrategy]} ${JSON.stringify(graphParams)}`, time: new Date().toLocaleTimeString() },
        { text: `[INFO] Feature set: ${JSON.stringify(featureSet)}`, time: new Date().toLocaleTimeString() },
        { text: "[INFO] Training queued on AI service", time: new Date().toLocaleTimeString() },
      ]);
      setProgress(100);
      toast({ title: "Training started", description: `TGNN ${modelVariant.toUpperCase()} training on ${datasetId}` });
    } catch (err) {
      setLogs((prev) => [...prev, { text: `[ERROR] ${err instanceof Error ? err.message : "Training failed"}`, time: new Date().toLocaleTimeString() }]);
      toast({ title: "Training failed", description: err instanceof Error ? err.message : "Unknown error", variant: "destructive" });
    } finally {
      setIsTraining(false);
    }
  };

  return (
    <main className="app-main flex-1 overflow-auto p-4 md:p-6 space-y-6">
        <div className="page-header flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="page-kicker">Model Studio</div>
            <h1 className="text-3xl font-bold tracking-tight text-white mb-2">Experiment Laboratory</h1>
            <p className="text-muted-foreground font-mono text-sm max-w-2xl">
              Train against historical datasets or attach the new live replay dataset so telemetry,
              anomaly pressure, and model quality move in real time while you tune the graph model.
            </p>
          </div>

          <div className="flex gap-2">
            <Button variant="outline" className="gap-2" onClick={handleReset}>
              <RotateCcw size={16} /> Reset
            </Button>
            <Button variant="outline" className="gap-2" onClick={handleSaveConfig}>
              <Save size={16} /> Save Config
            </Button>
            <Button
              onClick={startTraining}
              disabled={isTraining}
              className="gap-2 min-w-[150px] bg-primary text-primary-foreground"
            >
              {isTraining ? (
                <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
              ) : (
                <Play size={16} />
              )}
              {isTraining ? "Running..." : "Start Training"}
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-4">
          <Card className="metric-surface rounded-[1.35rem]">
            <CardContent className="p-4">
              <div className="text-xs uppercase tracking-[0.16em] text-muted-foreground">Dataset Feed</div>
              <div className="mt-2 flex items-center gap-2">
                <Badge className={isLiveDataset ? "bg-emerald-500/15 text-emerald-300" : "bg-blue-500/15 text-blue-300"}>
                  {dataset.mode === "live" ? "LIVE" : "BATCH"}
                </Badge>
                <span className="font-mono text-xs text-muted-foreground">{dataset.label}</span>
              </div>
              <div className="mt-3 text-xs text-muted-foreground">{dataset.description}</div>
            </CardContent>
          </Card>

          <Card className="metric-surface rounded-[1.35rem]">
            <CardContent className="p-4">
              <div className="text-xs uppercase tracking-[0.16em] text-muted-foreground">Monitored Nodes</div>
              <div className="mt-2 text-2xl font-bold font-mono text-primary">
                {monitoredNodes.toLocaleString()}
              </div>
              <div className="mt-2 text-xs text-muted-foreground">
                {alertsSummary.open} open alert{alertsSummary.open === 1 ? "" : "s"}
              </div>
            </CardContent>
          </Card>

          <Card className="metric-surface rounded-[1.35rem]">
            <CardContent className="p-4">
              <div className="text-xs uppercase tracking-[0.16em] text-muted-foreground">Anomaly Rate</div>
              <div className="mt-2 text-2xl font-bold font-mono text-orange-300">
                {maliciousShare.toFixed(0)}%
              </div>
              <div className="mt-2 text-xs text-muted-foreground">
                {net.compromised} compromised · {net.suspicious} suspicious
              </div>
            </CardContent>
          </Card>

          <Card className="metric-surface rounded-[1.35rem]">
            <CardContent className="p-4">
              <div className="text-xs uppercase tracking-[0.16em] text-muted-foreground">Model Accuracy</div>
              <div className="mt-2 text-2xl font-bold font-mono text-cyan-200">
                {modelInfo?.model_loaded ? `${modelAccuracy}%` : "—"}
              </div>
              <div className="mt-2 flex items-center gap-1.5 text-xs text-muted-foreground">
                <Server size={12} />
                {modelInfo?.architecture ? modelInfo.architecture.toUpperCase() : "Model"} · {activeDatasetLabel}
              </div>
              {activeStrategyLabel && (
                <div className="mt-1 flex items-center gap-1.5 text-[11px] text-muted-foreground/80">
                  <Activity size={11} />
                  {activeStrategyLabel}
                </div>
              )}
              {activeFeaturesLabel && (
                <div className="mt-1 text-[11px] text-muted-foreground/80 truncate" title={activeFeaturesLabel}>
                  Features: {activeFeaturesLabel}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 space-y-6">
            <Card className="panel-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database size={18} className="text-primary" />
                  Dataset
                </CardTitle>
                <CardDescription>Select the training source and attach the live replay when needed.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Source Dataset</Label>
                  <Select value={selectedDataset} onValueChange={setSelectedDataset}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select dataset" />
                    </SelectTrigger>
                    <SelectContent>
                      {DATASET_OPTIONS.map((option) => (
                        <SelectItem key={option.id} value={option.id} disabled={!option.enabled}>
                          {option.label}
                          {!option.enabled ? " (Coming Soon)" : ""}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="panel-subtle p-4 text-xs text-muted-foreground">
                  <div className="flex items-center gap-2 font-mono text-primary mb-2">
                    <Wifi size={14} />
                    {isLiveDataset ? "Live dataset attached" : "Historical dataset selected"}
                  </div>
                  <p>{dataset.source}</p>
                  <p className="mt-2">{dataset.description}</p>
                </div>

                <div className="space-y-3">
                  <div className="space-y-2">
                    <Label>Graph Construction Strategy</Label>
                    <Select value={graphStrategy} onValueChange={(v) => setGraphStrategy(v as GraphStrategy)}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {GRAPH_STRATEGY_OPTIONS.map((o) => (
                          <SelectItem key={o.id} value={o.id}>
                            {o.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">
                      {GRAPH_STRATEGY_OPTIONS.find((o) => o.id === graphStrategy)?.description}
                    </p>
                  </div>

                  {(graphStrategy === "endpoint" || graphStrategy === "flow") && (
                    <div className="flex items-center space-x-2">
                      <Checkbox
                        id="directed"
                        checked={directed}
                        onCheckedChange={(c) => setDirected(Boolean(c))}
                      />
                      <Label htmlFor="directed" className="text-xs">
                        Directed edges
                      </Label>
                    </div>
                  )}

                  {graphStrategy === "flow" && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-xs">
                        <Label>Sequential edge distance</Label>
                        <span className="text-muted-foreground font-mono">{flowDistance}</span>
                      </div>
                      <Slider value={[flowDistance]} onValueChange={([v]) => setFlowDistance(v)} min={1} max={5} step={1} />
                    </div>
                  )}

                  {graphStrategy === "similarity" && (
                    <div className="space-y-3">
                      <div className="space-y-2">
                        <Label className="text-xs">Similarity metric</Label>
                        <Select value={simMetric} onValueChange={(v) => setSimMetric(v as "cosine" | "knn")}>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="cosine">Cosine threshold</SelectItem>
                            <SelectItem value="knn">k-Nearest Neighbors</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      {simMetric === "cosine" ? (
                        <div className="space-y-2">
                          <div className="flex justify-between text-xs">
                            <Label>Similarity threshold</Label>
                            <span className="text-muted-foreground font-mono">{simThreshold.toFixed(2)}</span>
                          </div>
                          <Slider value={[simThreshold]} onValueChange={([v]) => setSimThreshold(v)} min={0.5} max={0.99} step={0.01} />
                        </div>
                      ) : (
                        <div className="space-y-2">
                          <div className="flex justify-between text-xs">
                            <Label>Number of neighbors (k)</Label>
                            <span className="text-muted-foreground font-mono">{simNeighbors}</span>
                          </div>
                          <Slider value={[simNeighbors]} onValueChange={([v]) => setSimNeighbors(v)} min={2} max={15} step={1} />
                        </div>
                      )}
                    </div>
                  )}

                  {graphStrategy === "temporal" && (
                    <div className="space-y-3">
                      <div className="space-y-2">
                        <div className="flex justify-between text-xs">
                          <Label>Window size (seconds)</Label>
                          <span className="text-muted-foreground font-mono">{windowSize}s</span>
                        </div>
                        <Slider value={[windowSize]} onValueChange={([v]) => setWindowSize(v)} min={5} max={120} step={5} />
                      </div>
                      <div className="space-y-2">
                        <div className="flex justify-between text-xs">
                          <Label>Window overlap</Label>
                          <span className="text-muted-foreground font-mono">{Math.round(windowOverlap * 100)}%</span>
                        </div>
                        <Slider value={[windowOverlap]} onValueChange={([v]) => setWindowOverlap(v)} min={0} max={0.9} step={0.05} />
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card className="panel-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <BrainCircuit size={18} className="text-primary" />
                  Model Architecture
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>GNN Variant</Label>
                  <Select value={modelVariant} onValueChange={(value) => setModelVariant(value as "gcn" | "gat" | "graphsage" | "tgn")}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="gcn">Graph Convolutional Network (GCN)</SelectItem>
                      <SelectItem value="gat">Graph Attention Network (GAT)</SelectItem>
                      <SelectItem value="graphsage">GraphSAGE</SelectItem>
                      <SelectItem value="tgn">Temporal Graph Network (TGN)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-4 pt-2">
                  <div className="space-y-2">
                    <div className="flex justify-between text-xs">
                      <Label>Learning Rate</Label>
                      <span className="text-muted-foreground font-mono">{sliderToLR(lrSlider)}</span>
                    </div>
                    <Slider value={[lrSlider]} onValueChange={([value]) => setLrSlider(value)} max={100} step={1} />
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between text-xs">
                      <Label>Hidden Dimension</Label>
                      <span className="text-muted-foreground font-mono">{sliderToHiddenDim(hiddenSlider)}</span>
                    </div>
                    <Slider value={[hiddenSlider]} onValueChange={([value]) => setHiddenSlider(value)} max={100} step={1} />
                  </div>
                </div>

                <div className="space-y-2 pt-2">
                  <Label>Features to Include</Label>
                  <p className="text-[11px] text-muted-foreground">
                    Disabled features are removed from preprocessing, graph vectors, training, and inference.
                  </p>
                  <div className="grid grid-cols-2 gap-2">
                    {FEATURE_OPTIONS.map((feat) => (
                      <div key={feat.id} className="flex items-center space-x-2">
                        <Checkbox
                          id={`feat-${feat.id}`}
                          checked={Boolean(featureSet[feat.id])}
                          onCheckedChange={(checked) =>
                            setFeatureSet((prev) => ({ ...prev, [feat.id]: Boolean(checked) }))
                          }
                        />
                        <Label htmlFor={`feat-${feat.id}`} className="text-xs">
                          {feat.label}
                        </Label>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="lg:col-span-2 flex flex-col gap-6">
            <Card className="panel-card overflow-hidden">
              <div className="p-3 border-b border-white/10 flex justify-between items-center bg-card/20">
                <span className="font-mono text-sm text-muted-foreground">Console Output</span>
                <div className="flex items-center gap-2 text-[11px] font-mono">
                  <span className="text-primary">{dataset.label}</span>
                  {isTraining && <span className="text-emerald-300 animate-pulse">TRAINING IN PROGRESS</span>}
                </div>
              </div>
              <div className="flex-1 p-0">
                <TrainingTerminal logs={logs} className="h-[320px] border-none rounded-none" />
              </div>
            </Card>

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
              <Card className="panel-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Activity size={18} className="text-primary" />
                    Live Dataset Throughput
                  </CardTitle>
                  <CardDescription>
                    {throughputMode === "live"
                      ? "Confidence and risk of the most recent live inference predictions."
                      : "Train vs. validation loss across the latest training run."}
                  </CardDescription>
                </CardHeader>
                <CardContent className="h-72">
                  {throughputData.length ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={throughputData}>
                        <defs>
                          <linearGradient id="throughputFill" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="hsl(186 95% 55%)" stopOpacity={0.35} />
                            <stop offset="95%" stopColor="hsl(186 95% 55%)" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#233041" />
                        <XAxis dataKey="time" stroke="#6b7280" minTickGap={24} />
                        <YAxis stroke="#6b7280" domain={throughputMode === "live" ? [0, 100] : ["auto", "auto"]} />
                        <Tooltip contentStyle={{ backgroundColor: "#08111b", borderColor: "#1f2d3d" }} />
                        <Legend />
                        <Area
                          type="monotone"
                          dataKey="primary"
                          stroke="hsl(186 95% 55%)"
                          fill="url(#throughputFill)"
                          strokeWidth={2}
                          name={throughputPrimaryName}
                        />
                        <Line
                          type="monotone"
                          dataKey="secondary"
                          stroke="#60a5fa"
                          strokeWidth={2}
                          dot={false}
                          name={throughputSecondaryName}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  ) : hasTopology ? (
                    <MiniNetworkPreview nodes={topoNodes} edges={topoEdges} />
                  ) : (
                    <EmptyState
                      title="No stream data yet"
                      message="Run a dataset prediction or start training to populate this lane."
                    />
                  )}
                </CardContent>
              </Card>

              <Card className="panel-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Gauge size={18} className="text-primary" />
                    Training Quality Window
                  </CardTitle>
                  <CardDescription>
                    Per-epoch validation quality of the latest training run (Accuracy, Precision, Recall, F1).
                  </CardDescription>
                </CardHeader>
                <CardContent className="h-72">
                  {qualityData.length ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={qualityData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#233041" />
                        <XAxis dataKey="time" stroke="#6b7280" minTickGap={24} />
                        <YAxis stroke="#6b7280" domain={[0, 100]} unit="%" />
                        <Tooltip contentStyle={{ backgroundColor: "#08111b", borderColor: "#1f2d3d" }} formatter={(v: number) => `${v}%`} />
                        <Legend />
                        <Line type="monotone" dataKey="accuracy" stroke="hsl(186 95% 55%)" strokeWidth={2} dot={false} name="Accuracy" />
                        <Line type="monotone" dataKey="precision" stroke="#f59e0b" strokeWidth={2} dot={false} name="Precision" />
                        <Line type="monotone" dataKey="recall" stroke="#22c55e" strokeWidth={2} dot={false} name="Recall" />
                        <Line type="monotone" dataKey="f1" stroke="#a855f7" strokeWidth={2} dot={false} name="F1" />
                      </LineChart>
                    </ResponsiveContainer>
                  ) : hasTopology ? (
                    <MiniNetworkPreview nodes={topoNodes} edges={topoEdges} />
                  ) : (
                    <EmptyState
                      title="No training history yet"
                      message="Start a training run to see per-epoch quality metrics."
                    />
                  )}
                </CardContent>
              </Card>
            </div>

            <Card className="panel-card">
              <CardHeader>
                <CardTitle>Current Stream Snapshot</CardTitle>
                <CardDescription>
                  Live figures from the active model and the running detection backend.
                </CardDescription>
              </CardHeader>
              <CardContent className="grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-4">
                <div className="panel-subtle p-4">
                  <div className="text-xs uppercase tracking-[0.14em] text-muted-foreground">Malicious Share</div>
                  <div className="mt-2 text-2xl font-mono font-bold text-red-300">{maliciousShare}%</div>
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    of {monitoredNodes.toLocaleString()} monitored nodes
                  </div>
                </div>
                <div className="panel-subtle p-4">
                  <div className="text-xs uppercase tracking-[0.14em] text-muted-foreground">Open Alerts</div>
                  <div className="mt-2 text-2xl font-mono font-bold text-yellow-300">{alertsSummary.open}</div>
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    {alertsSummary.critical} critical · {alertsSummary.high} high
                  </div>
                </div>
                <div className="panel-subtle p-4">
                  <div className="flex items-center justify-between">
                    <div className="text-xs uppercase tracking-[0.14em] text-muted-foreground">Threat Score</div>
                    <span className={`rounded-full border px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider ${threat.badge}`}>
                      {threat.label}
                    </span>
                  </div>
                  <div className={`mt-2 text-2xl font-mono font-bold ${threat.text}`}>{threatScore}%</div>
                  <div className="mt-1 text-[11px] text-muted-foreground">avg network risk</div>
                </div>
                <div className="panel-subtle p-4">
                  <div className="text-xs uppercase tracking-[0.14em] text-muted-foreground">Last Update</div>
                  <div className="mt-2 flex items-center gap-1.5 text-base font-mono font-bold text-white">
                    <Clock size={14} className="text-muted-foreground" />
                    {formatTimestamp(lastUpdated)}
                  </div>
                  <div className="mt-1 text-[11px] text-muted-foreground">{timeAgo(lastUpdated)}</div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
  );
}
