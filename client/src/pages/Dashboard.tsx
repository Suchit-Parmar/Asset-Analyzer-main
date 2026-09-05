import { useEffect, useMemo, useState } from "react";
import { NetworkGraph } from "@/components/viz/NetworkGraph";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Activity, ShieldAlert, Network as NetworkIcon, Globe, Lock, LogOut, RadioTower,
  Loader2, Crosshair, Cpu, Wifi, Play,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { AnimatePresence, motion } from "framer-motion";
import {
  Area, AreaChart, CartesianGrid, Legend, Line,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import {
  useDashboardMetrics, useAlerts, useTopology, usePredictions,
  useModelInfo, useRiskScores, usePredictDataset, useAttackStages,
} from "@/hooks/useApi";
import { useWebSocketSync } from "@/hooks/useWebSocketSync";
import { toast } from "@/hooks/use-toast";
import { EmptyState, ErrorState, PageLoader } from "@/components/states";
import { TrafficModeBadge } from "@/components/TrafficModeBadge";
import { riskScore100 } from "@/lib/cyber-display";
import { Link } from "wouter";

const SEVERITY_STYLES: Record<string, { label: string; border: string; bg: string; text: string; dot: string }> = {
  critical: { label: "CRITICAL", border: "border-red-500/60", bg: "bg-red-500/8", text: "text-red-400", dot: "bg-red-500" },
  high: { label: "HIGH", border: "border-orange-500/60", bg: "bg-orange-500/8", text: "text-orange-400", dot: "bg-orange-500" },
  medium: { label: "MEDIUM", border: "border-yellow-500/60", bg: "bg-yellow-500/8", text: "text-yellow-400", dot: "bg-yellow-500" },
  low: { label: "LOW", border: "border-blue-500/60", bg: "bg-blue-500/8", text: "text-blue-400", dot: "bg-blue-500" },
  info: { label: "INFO", border: "border-blue-500/60", bg: "bg-blue-500/8", text: "text-blue-400", dot: "bg-blue-500" },
};

export default function Dashboard({ onLogout }: { onLogout?: () => void }) {
  const { connected: wsConnected, lastEventType } = useWebSocketSync();
  const { data: metrics, isLoading: metricsLoading, isError: metricsError, refetch: refetchMetrics } = useDashboardMetrics();
  const { data: alertsData, isLoading: alertsLoading, isError: alertsError, refetch: refetchAlerts } = useAlerts();
  const { data: topology } = useTopology();
  const { data: predictionsData } = usePredictions();
  const { data: modelInfo } = useModelInfo();
  const { data: riskData } = useRiskScores();
  const { data: attackStageData } = useAttackStages();
  const predictDataset = usePredictDataset();
  const [currentTime, setCurrentTime] = useState(new Date());
  const [timeline, setTimeline] = useState<Array<{ time: string; alerts: number; risk: number; confidence: number }>>([]);

  const [trafficMode, setTrafficMode] = useState<"live" | "replay">("live");

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const alerts = useMemo(() => {
    const rows = alertsData?.alerts ?? [];
    // Prefer open alerts first so the Overview stream never looks empty when SOC alerts exist.
    return [...rows].sort((a, b) => {
      const aOpen = a.status === "open" ? 0 : 1;
      const bOpen = b.status === "open" ? 0 : 1;
      if (aOpen !== bOpen) return aOpen - bOpen;
      return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
    });
  }, [alertsData?.alerts]);
  const predictions = predictionsData?.predictions ?? [];
  const riskScores = riskData?.scores ?? [];
  const openAlertCount = metrics?.alerts?.open ?? alerts.filter((a) => a.status === "open").length;

  const avgConfidence = useMemo(() => {
    if (!predictions.length) return 0;
    return predictions.reduce((sum, p) => sum + (p.confidence ?? 0), 0) / predictions.length;
  }, [predictions]);

  useEffect(() => {
    if (!metrics) return;
    setTimeline((prev) => {
      const next = [
        ...prev,
        {
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          alerts: metrics.alerts?.open ?? openAlertCount,
          risk: Math.round((metrics.network?.avgRisk ?? 0) * 100),
          confidence: Math.round(avgConfidence * 100),
        },
      ];
      return next.slice(-24);
    });
  }, [metrics, avgConfidence, openAlertCount]);

  const threatLevel = (metrics?.alerts?.critical ?? 0) > 0 ? "CRITICAL"
    : (metrics?.alerts?.high ?? 0) > 0 ? "ELEVATED" : "LOW";
  const isThreatElevated = threatLevel !== "LOW";
  const activeNodes = metrics?.network?.total ?? 0;
  const avgRisk = metrics?.network?.avgRisk ?? 0;
  const topRiskNodes = [...(topology?.nodes ?? [])].sort((a, b) => b.risk - a.risk).slice(0, 5);

  const riskCards = useMemo(() => {
    if (riskScores.length) {
      const avg = (key: keyof typeof riskScores[0]) => {
        const vals = riskScores.map((s) => Number(s[key] ?? 0)).filter((n) => !Number.isNaN(n));
        if (!vals.length) return 0;
        return vals.reduce((a, b) => a + b, 0) / vals.length;
      };
      return [
        { label: "Node Risk", value: avg("nodeRisk") },
        { label: "Subnet Risk", value: avg("subnetRisk") },
        { label: "Org Risk", value: avg("organizationRisk") },
        { label: "Propagation", value: avg("propagationRisk") },
      ];
    }
    return [
      { label: "Avg Network Risk", value: avgRisk },
      { label: "Compromised Share", value: activeNodes ? (metrics?.network?.compromised ?? 0) / activeNodes : 0 },
      { label: "Suspicious Share", value: activeNodes ? (metrics?.network?.suspicious ?? 0) / activeNodes : 0 },
      { label: "Avg Confidence", value: avgConfidence },
    ];
  }, [riskScores, avgRisk, activeNodes, metrics, avgConfidence]);

  async function runLiveInference() {
    try {
      setTrafficMode("replay");
      const result = await predictDataset.mutateAsync({ datasetId: "cicids2017", maxRows: 3000 });
      toast({
        title: "Dataset replay complete",
        description: `${result.attackType} @ ${Math.round((result.confidence ?? 0) * 100)}% confidence (DATASET REPLAY — not live capture).`,
      });
    } catch (err) {
      toast({
        title: "Inference failed",
        description: err instanceof Error ? err.message : "Prediction request failed",
        variant: "destructive",
      });
    }
  }

  if (metricsLoading) {
    return <PageLoader label="Loading SOC dashboard…" />;
  }

  if (metricsError) {
    return (
      <main className="app-main flex-1 overflow-auto p-6">
          <ErrorState
            title="Dashboard metrics unavailable"
            message="Check JWT login and that Express is running on port 5000."
            onRetry={() => refetchMetrics()}
          />
        </main>
    );
  }

  return (
    <main className="app-main flex-1 overflow-auto p-4 md:p-6 space-y-6">
        <header className="page-header">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
            <div className="max-w-3xl">
              <div className="page-kicker">SOC Live View</div>
              <h1 className="text-3xl font-bold tracking-tight text-white md:text-4xl mb-3">Cyber Defense Command Center</h1>
              <p className="max-w-2xl text-sm text-muted-foreground md:text-base">
                GNN-based attack detection on a dynamic network graph. Dataset replay is clearly
                labelled — never presented as live enterprise capture.
              </p>
              <div className="mt-3">
                <TrafficModeBadge mode={trafficMode === "replay" ? "replay" : topology?.nodes?.length ? "live" : "awaiting"} />
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-[auto_auto_auto]">
              <div className="panel-subtle p-4">
                <div className="text-[11px] uppercase tracking-[0.18em] text-muted-foreground">AI Model</div>
                <div className="mt-2 flex items-center gap-2 text-xs font-mono text-emerald-300">
                  <span className={cn("h-2 w-2 rounded-full", modelInfo?.model_loaded ? "bg-emerald-400 animate-pulse" : "bg-yellow-400")} />
                  {modelInfo?.architecture ? `TGNN ${String(modelInfo.architecture).toUpperCase()}` : "TGNN"}
                  {modelInfo?.model_loaded ? " Active" : " Offline"}
                </div>
                <div className="mt-2 text-xs text-muted-foreground">
                  {modelInfo?.dataset_id ?? "—"} · {modelInfo?.trained_at ? new Date(modelInfo.trained_at).toLocaleString() : "not trained"}
                </div>
              </div>

              <div className="panel-subtle p-4">
                <div className="text-[11px] uppercase tracking-[0.18em] text-muted-foreground">Live WebSocket</div>
                <div className={cn("mt-2 inline-flex items-center gap-2 text-xs font-mono", wsConnected ? "text-emerald-300" : "text-yellow-300")}>
                  <Wifi className="h-3.5 w-3.5" />
                  {wsConnected ? "Connected" : "Reconnecting…"}
                </div>
                <div className="mt-2 text-xs text-muted-foreground">
                  Last event: {lastEventType ?? "waiting"}
                </div>
              </div>

              <div className="panel-subtle p-4">
                <div className="text-[11px] uppercase tracking-[0.18em] text-muted-foreground">Threat Status</div>
                <div className={cn(
                  "mt-2 inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-mono border",
                  isThreatElevated ? "bg-red-500/10 border-red-500/30 text-red-400" : "bg-green-500/10 border-green-500/20 text-green-400",
                )}>
                  <div className={cn("w-2 h-2 rounded-full animate-pulse", isThreatElevated ? "bg-red-500" : "bg-green-500")} />
                  {isThreatElevated ? `${threatLevel} ALERT` : "ALL SYSTEMS NORMAL"}
                </div>
              </div>

              <div className="panel-subtle p-4">
                <div className="text-[11px] uppercase tracking-[0.18em] text-muted-foreground">Current Time</div>
                <div className="mt-2 text-2xl font-mono font-bold text-white">{currentTime.toLocaleTimeString()}</div>
              </div>

              <div className="panel-subtle p-4 flex flex-col gap-2">
                <Button size="sm" onClick={runLiveInference} disabled={predictDataset.isPending}>
                  {predictDataset.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Play className="h-4 w-4 mr-2" />}
                  Run Dataset Replay
                </Button>
                <Button variant="ghost" size="sm" onClick={onLogout} className="justify-start text-muted-foreground hover:text-foreground hover:bg-destructive/10">
                  <LogOut className="w-4 h-4 mr-2" /> Secure Logout
                </Button>
              </div>
            </div>
          </div>
        </header>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard title="Network Nodes" value={activeNodes.toLocaleString()} icon={NetworkIcon} trend={`${metrics?.network?.compromised ?? 0} compromised`} color="text-blue-400" />
          <MetricCard title="Threat Posture" value={threatLevel} icon={ShieldAlert} color={isThreatElevated ? "text-red-400" : "text-green-400"} />
          <MetricCard title="Avg Confidence" value={`${Math.round(avgConfidence * 100)}%`} icon={Crosshair} trend={`${predictions.length} predictions`} color="text-cyan-300" />
          <MetricCard
            title="Open Alerts"
            value={String(openAlertCount)}
            icon={Lock}
            trend={`${metrics?.alerts?.open24h ?? 0} in last 24h · ${alerts.length} listed`}
            color="text-orange-400"
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {riskCards.map((card) => (
            <Card key={card.label} className="metric-surface rounded-[1.5rem]">
              <CardContent className="p-5">
                <div className="text-xs uppercase tracking-[0.16em] text-muted-foreground">{card.label}</div>
                <div className="mt-2 text-2xl font-mono font-bold text-primary">{Math.round(card.value * 100)}%</div>
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <Card className="panel-card xl:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Activity size={18} className="text-primary" /> Attack Timeline</CardTitle>
            </CardHeader>
            <CardContent className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeline}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#223041" />
                  <XAxis dataKey="time" stroke="#6b7280" minTickGap={24} />
                  <YAxis stroke="#6b7280" />
                  <Tooltip contentStyle={{ backgroundColor: "#08111b", borderColor: "#1f2d3d" }} />
                  <Legend />
                  <Area type="monotone" dataKey="alerts" stroke="hsl(186 95% 55%)" fill="hsl(186 95% 55% / 0.2)" name="Open Alerts" />
                  <Line type="monotone" dataKey="risk" stroke="#ef4444" strokeWidth={2} dot={false} name="Risk %" />
                  <Line type="monotone" dataKey="confidence" stroke="#22c55e" strokeWidth={2} dot={false} name="Confidence %" />
                </AreaChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          <Card className="panel-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Cpu size={18} className="text-primary" /> Model Information</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <InfoRow label="Loaded" value={modelInfo?.model_loaded ? "Yes" : "No"} />
              <InfoRow label="Architecture" value={modelInfo?.architecture ?? "—"} />
              <InfoRow label="Dataset" value={String(modelInfo?.dataset_id ?? "—")} />
              <InfoRow label="Device" value={modelInfo?.device ?? "—"} />
              <InfoRow label="Accuracy" value={modelInfo?.metrics?.accuracy != null ? String(modelInfo.metrics.accuracy) : "—"} />
              <InfoRow label="F1" value={modelInfo?.metrics?.f1 != null ? String(modelInfo.metrics.f1) : "—"} />
              <InfoRow label="Trained" value={modelInfo?.trained_at ? new Date(modelInfo.trained_at).toLocaleString() : "—"} />
              <div className="pt-2 text-xs text-muted-foreground">
                Stage lead: {attackStageData?.stats?.leadStage?.stage ?? "n/a"} · avg stage confidence{" "}
                {Math.round((attackStageData?.stats?.avgConfidence ?? 0) * 100)}%
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[520px]">
          <div className="panel-card lg:col-span-2 overflow-hidden flex flex-col">
            <div className="p-4 border-b border-border/50 flex justify-between items-center">
              <h3 className="font-semibold flex items-center gap-2"><Globe size={16} className="text-primary" /> Network Topology</h3>
              <div className="flex items-center gap-3">
                <Link href="/network" className="text-xs text-primary hover:underline">Open graph explorer</Link>
                <span className="text-xs font-mono text-muted-foreground">{topology?.nodes?.length ?? 0} nodes | {topology?.edges?.length ?? 0} edges</span>
              </div>
            </div>
            <div className="flex-1 relative">
              <NetworkGraph
                active={true}
                alertMode={isThreatElevated}
                topology={topology}
                mode={trafficMode === "replay" ? "replay" : topology?.nodes?.length ? "live" : "awaiting"}
              />
            </div>
          </div>

          <div className="panel-card flex flex-col overflow-hidden min-h-0">
            <div className="p-4 border-b border-border/50 flex justify-between items-center shrink-0">
              <h3 className="font-semibold flex items-center gap-2"><ShieldAlert size={16} className="text-destructive" /> Alert Stream</h3>
              <span className="text-[10px] font-mono text-muted-foreground">
                {alerts.length} alerts · {wsConnected ? "LIVE WS" : "POLLING"}
              </span>
            </div>
            <div className="flex-1 min-h-0 overflow-y-auto p-3 space-y-2 font-mono text-xs">
              {alertsLoading && <Loader2 className="h-4 w-4 animate-spin mx-auto mt-6" />}
              {alertsError && !alertsLoading && (
                <div className="text-center py-6 space-y-2">
                  <p className="text-red-400">Could not load alerts.</p>
                  <Button size="sm" variant="outline" onClick={() => void refetchAlerts()}>Retry</Button>
                </div>
              )}
              <AnimatePresence initial={false}>
                {alerts.map((alert) => {
                  const severityStyle = SEVERITY_STYLES[alert.severity] ?? SEVERITY_STYLES.info;
                  const src = alert.sourceIp || "unknown";
                  const dst = alert.targetIp || "unknown";
                  return (
                    <motion.div key={alert.id} initial={{ opacity: 0, y: -14 }} animate={{ opacity: 1, y: 0 }}
                      className={cn("p-3 rounded-2xl border", severityStyle.border, severityStyle.bg)}>
                      <div className="flex justify-between items-center mb-1 gap-2">
                        <span className={cn("flex items-center gap-1 font-bold", severityStyle.text)}>
                          <span className={cn("w-1.5 h-1.5 rounded-full", severityStyle.dot)} />
                          {severityStyle.label}
                        </span>
                        <span className="text-muted-foreground text-[10px] shrink-0">
                          {new Date(alert.createdAt).toLocaleString()}
                        </span>
                      </div>
                      <div className="text-foreground/90 mb-1 font-semibold truncate">{alert.title}</div>
                      <div className="text-muted-foreground truncate mb-1">
                        {src} → {dst}
                        {alert.protocol && <span className="ml-2 px-1 py-0.5 bg-white/5 rounded text-[9px]">{alert.protocol}</span>}
                        {alert.status && (
                          <span className="ml-2 px-1 py-0.5 bg-white/5 rounded text-[9px] uppercase">{alert.status}</span>
                        )}
                      </div>
                      {(alert.mitreTactic || alert.mitreTechnique) && (
                        <div className="text-[10px] text-cyan-300/90">
                          MITRE: {alert.mitreTactic ?? "—"} / {alert.mitreTechnique ?? "—"}
                        </div>
                      )}
                    </motion.div>
                  );
                })}
              </AnimatePresence>
              {!alerts.length && !alertsLoading && !alertsError && (
                <p className="text-center text-muted-foreground py-8">
                  No alerts stored yet. Elevated TGNN predictions (medium+) create SOC alerts. Normal live traffic will not.
                </p>
              )}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <Card className="panel-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><RadioTower size={18} className="text-primary" /> Prediction History</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 max-h-96 overflow-auto">
              {predictions.map((pred) => (
                <div key={pred.id} className="panel-subtle p-3 space-y-2">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="font-mono text-sm text-white">{pred.attackType}</div>
                      <div className="text-xs text-muted-foreground">
                        {pred.attackStage}
                        {pred.predictedNextStage ? ` → ${pred.predictedNextStage}` : ""}
                      </div>
                    </div>
                    <Badge variant="outline">{pred.threatLevel}</Badge>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-xs font-mono">
                    <div>Conf <span className="text-emerald-300">{Math.round(pred.confidence * 100)}%</span></div>
                    <div>Prob <span className="text-cyan-300">{Math.round(pred.probability * 100)}%</span></div>
                    <div>Risk <span className="text-orange-300">{Math.round(pred.riskScore * 100)}%</span></div>
                  </div>
                  <div className="text-[10px] text-muted-foreground">{new Date(pred.createdAt).toLocaleString()}</div>
                </div>
              ))}
              {!predictions.length && (
                <EmptyState
                  title="No predictions stored"
                  message="Use Run Dataset Predict to call POST /api/predict/dataset and persist results."
                />
              )}
            </CardContent>
          </Card>

          <Card className="panel-card">
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Potential Suspects</CardTitle>
              <Link href="/suspects" className="text-xs text-primary hover:underline">View all</Link>
            </CardHeader>
            <CardContent className="space-y-3">
              {topRiskNodes.map((node, index) => (
                <div key={node.id} className="panel-subtle p-3">
                  <div className="flex justify-between items-start gap-3">
                    <div>
                      <div className="font-mono text-sm text-white">{index + 1}. {node.label}</div>
                      <div className="text-xs text-muted-foreground">{node.ip} | {node.status}</div>
                    </div>
                    <div className="text-lg font-mono font-bold text-primary">{riskScore100(node.risk)}/100</div>
                  </div>
                </div>
              ))}
              {!topRiskNodes.length && <p className="text-sm text-muted-foreground">No network nodes synced yet. Ensure AI service is running so topology can sync.</p>}
            </CardContent>
          </Card>
        </div>
      </main>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-border/40 pb-2">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono text-xs text-foreground">{value}</span>
    </div>
  );
}

function MetricCard({ title, value, icon: Icon, trend, color }: {
  title: string; value: string; icon: typeof Activity; trend?: string; color: string;
}) {
  return (
    <Card className="metric-surface rounded-[1.5rem] hover:bg-card/60 transition-colors">
      <CardContent className="p-6">
        <div className="flex justify-between items-start">
          <div>
            <p className="text-sm font-medium text-muted-foreground mb-1">{title}</p>
            <h4 className={cn("text-2xl font-bold font-mono", color)}>{value}</h4>
          </div>
          <div className={cn("p-2 rounded-xl bg-background/50 border border-white/5", color)}>
            <Icon size={20} />
          </div>
        </div>
        {trend && <div className="mt-4 text-xs font-mono text-muted-foreground">{trend}</div>}
      </CardContent>
    </Card>
  );
}
