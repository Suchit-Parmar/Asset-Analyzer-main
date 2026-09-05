import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import {
  Loader2,
  Users,
  Database,
  Cpu,
  Activity,
  Server,
  RefreshCw,
  HardDrive,
  MemoryStick,
  ScrollText,
  AlertCircle,
} from "lucide-react";
import {
  useSystemHealth,
  useAdminHealth,
  useAdminAuditLogs,
  useAdminApiLogs,
  useAdminPredictionLogs,
  useAdminSystemLogs,
  useTrainingRuns,
  useDatasets,
  useModelInfo,
  useReloadModel,
} from "@/hooks/useApi";
import { toast } from "@/hooks/use-toast";

interface DatasetRow {
  id: string;
  name: string;
  source: string;
  status: string;
  recordCount: number;
}

function bytesToMb(n?: number) {
  if (typeof n !== "number") return "—";
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function pctBar(value?: number) {
  if (typeof value !== "number") return 0;
  return Math.min(100, Math.max(0, value));
}

export default function AdminPanel() {
  const { data: health, isLoading: healthLoading } = useSystemHealth();
  const { data: adminHealth } = useAdminHealth();
  const { data: auditData } = useAdminAuditLogs(80);
  const { data: apiLogData } = useAdminApiLogs(80);
  const { data: predictionLogs } = useAdminPredictionLogs(40);
  const { data: systemLogData } = useAdminSystemLogs(80);
  const { data: trainingData } = useTrainingRuns();
  const { data: datasetsData } = useDatasets();
  const { data: modelInfo, isLoading: modelLoading } = useModelInfo();
  const reloadModel = useReloadModel();

  const aiHealth = health?.ai as Record<string, unknown> | undefined;
  const aiSystem = (aiHealth?.system ?? (adminHealth?.ai as Record<string, unknown> | undefined)?.system) as Record<string, unknown> | undefined;
  const apiSystem = (health?.api ?? adminHealth?.api) as Record<string, unknown> | undefined;
  const datasets = (datasetsData as { datasets?: DatasetRow[] } | undefined)?.datasets ?? [];

  async function handleReload() {
    try {
      await reloadModel.mutateAsync();
      toast({ title: "Model reloaded", description: "Checkpoint reloaded from ai/models/tgnn_model.pt" });
    } catch (err) {
      toast({
        title: "Reload failed",
        description: err instanceof Error ? err.message : "Could not reload model",
        variant: "destructive",
      });
    }
  }

  return (
    <main className="flex-1 overflow-auto p-6 space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-white">Admin Panel</h1>
          <p className="text-muted-foreground mt-1">
            System health monitoring, audit logs, API/training/prediction logs
          </p>
        </div>

        {healthLoading && <Loader2 className="h-6 w-6 animate-spin text-primary" />}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card className="panel-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2"><Server className="h-4 w-4" /> API Server</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Badge variant="outline" className="text-emerald-400">{health?.status ?? "unknown"}</Badge>
              <MetricBar label="RAM" value={apiSystem?.memory_percent as number | undefined} />
              <p className="text-xs text-muted-foreground font-mono">
                Uptime: {apiSystem?.uptime_sec != null ? `${apiSystem.uptime_sec}s` : "—"} · CPUs: {String(apiSystem?.cpu_count ?? "—")}
              </p>
            </CardContent>
          </Card>

          <Card className="panel-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2"><Cpu className="h-4 w-4" /> AI Service</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Badge variant="outline">{String(aiHealth?.status ?? "unknown")}</Badge>
              <p className="text-xs text-muted-foreground">Model: {aiHealth?.model_loaded ? "Loaded" : "Not trained"}</p>
              <p className="text-xs text-muted-foreground">GPU: {aiHealth?.gpu_available ? "Available" : "CPU only"}</p>
              <MetricBar label="CPU" value={aiSystem?.cpu_percent as number | undefined} />
              <MetricBar label="RAM" value={aiSystem?.memory_percent as number | undefined} />
              {Boolean(aiSystem?.gpu_available) ? (
                <MetricBar label="GPU VRAM" value={aiSystem?.gpu_memory_percent as number | undefined} />
              ) : null}
            </CardContent>
          </Card>

          <Card className="panel-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2"><Database className="h-4 w-4" /> Storage</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="text-2xl font-bold font-mono">{datasets.length}</div>
              <p className="text-xs text-muted-foreground">Registered datasets</p>
              <MetricBar label="Disk" value={aiSystem?.disk_percent as number | undefined} />
              <p className="text-xs text-muted-foreground font-mono">
                Model: {modelInfo?.model_size_mb != null ? `${modelInfo.model_size_mb} MB` : bytesToMb(modelInfo?.model_size_bytes)}
              </p>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <ResourceCard icon={MemoryStick} label="API RAM Used" value={bytesToMb(apiSystem?.memory_used_bytes as number | undefined)} sub={`${apiSystem?.memory_percent ?? "—"}%`} />
          <ResourceCard icon={HardDrive} label="AI Disk Used" value={bytesToMb(aiSystem?.disk_used_bytes as number | undefined)} sub={`${aiSystem?.disk_percent ?? "—"}%`} />
          <ResourceCard icon={Cpu} label="AI CPU" value={aiSystem?.cpu_percent != null ? `${aiSystem.cpu_percent}%` : "—"} sub={`${aiSystem?.cpu_count ?? "—"} cores`} />
          <ResourceCard icon={Activity} label="Load Avg" value={Array.isArray(apiSystem?.load_avg) ? (apiSystem.load_avg as number[])[0]?.toFixed(2) ?? "—" : "—"} sub="1 min" />
        </div>

        <Tabs defaultValue="model" className="space-y-4">
          <TabsList>
            <TabsTrigger value="model">Model</TabsTrigger>
            <TabsTrigger value="audit">Audit Logs</TabsTrigger>
            <TabsTrigger value="api">API Logs</TabsTrigger>
            <TabsTrigger value="training">Training</TabsTrigger>
            <TabsTrigger value="predictions">Predictions</TabsTrigger>
            <TabsTrigger value="system">System Logs</TabsTrigger>
          </TabsList>

          <TabsContent value="model" className="space-y-4">
            <Card className="panel-card">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="flex items-center gap-2"><Cpu className="h-4 w-4" /> Model Information</CardTitle>
                <Button size="sm" variant="outline" onClick={handleReload} disabled={reloadModel.isPending}>
                  {reloadModel.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-2" />}
                  Reload Checkpoint
                </Button>
              </CardHeader>
              <CardContent>
                {modelLoading ? (
                  <Loader2 className="h-5 w-5 animate-spin text-primary" />
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 text-sm">
                    <Info label="Loaded" value={modelInfo?.model_loaded ? "Yes" : "No"} />
                    <Info label="Architecture" value={modelInfo?.architecture ?? "—"} />
                    <Info label="Dataset" value={String(modelInfo?.dataset_id ?? "—")} />
                    <Info label="Device" value={modelInfo?.device ?? "—"} />
                    <Info label="Inference" value={modelInfo?.metrics?.inference_time_ms != null ? `${modelInfo.metrics.inference_time_ms} ms` : "—"} />
                    <Info label="Trained At" value={modelInfo?.trained_at ? new Date(modelInfo.trained_at).toLocaleString() : "—"} />
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="panel-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2"><Users className="h-4 w-4" /> Registered Datasets</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {datasets.map((ds) => (
                  <div key={ds.id} className="flex justify-between p-3 rounded-lg border border-border/50">
                    <div>
                      <div className="font-medium">{ds.name}</div>
                      <div className="text-xs text-muted-foreground">{ds.source} | {ds.recordCount} records</div>
                    </div>
                    <Badge variant="outline">{ds.status}</Badge>
                  </div>
                ))}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="audit">
            <LogTable
              title="User Audit Trail"
              icon={ScrollText}
              empty="No audit entries yet. User actions are recorded on login and sensitive operations."
              rows={(auditData?.logs ?? []).map((log) => ({
                id: String(log.id),
                primary: `${log.action} · ${log.resource}`,
                secondary: String(log.userEmail ?? log.userId ?? "system"),
                meta: log.createdAt ? new Date(String(log.createdAt)).toLocaleString() : "",
              }))}
            />
          </TabsContent>

          <TabsContent value="api">
            <LogTable
              title="API Activity Log"
              icon={Server}
              empty="API requests will appear here as they are processed."
              rows={(apiLogData?.logs ?? []).map((log, i) => ({
                id: `${log.timestamp}-${i}`,
                primary: `[${log.scope}] ${log.message}`,
                secondary: log.level ? String(log.level) : "info",
                meta: log.timestamp ? new Date(String(log.timestamp)).toLocaleString() : "",
                error: log.level === "error",
              }))}
            />
          </TabsContent>

          <TabsContent value="training">
            <LogTable
              title="Training Runs"
              icon={Activity}
              empty="No training runs recorded."
              rows={(trainingData?.runs ?? []).map((run) => ({
                id: run.id,
                primary: `${run.architecture.toUpperCase()} — ${run.status}`,
                secondary: `Epoch ${run.currentEpoch}/${run.epochs} · loss ${run.trainLoss ?? "—"}`,
                meta: run.createdAt ? new Date(run.createdAt).toLocaleString() : "",
              }))}
            />
          </TabsContent>

          <TabsContent value="predictions">
            <LogTable
              title="Recent Predictions"
              icon={AlertCircle}
              empty="No predictions stored yet."
              rows={(predictionLogs?.predictions ?? []).map((p) => ({
                id: String(p.id),
                primary: `${p.attackType} (${p.threatLevel})`,
                secondary: `conf ${typeof p.confidence === "number" ? (p.confidence * 100).toFixed(0) : "—"}% · risk ${typeof p.riskScore === "number" ? (p.riskScore * 100).toFixed(0) : "—"}%`,
                meta: p.createdAt ? new Date(String(p.createdAt)).toLocaleString() : "",
              }))}
            />
          </TabsContent>

          <TabsContent value="system">
            <LogTable
              title="Persisted System Logs (warn/error)"
              icon={AlertCircle}
              empty="No persisted system errors yet. API warn/error events are stored here."
              rows={(systemLogData?.logs ?? []).map((log) => ({
                id: String(log.id),
                primary: `[${log.service}] ${String(log.message)}`,
                secondary: String(log.level ?? "info"),
                meta: log.createdAt ? new Date(String(log.createdAt)).toLocaleString() : "",
                error: log.level === "error",
              }))}
            />
          </TabsContent>
        </Tabs>
      </main>
  );
}

function MetricBar({ label, value }: { label: string; value?: number }) {
  return (
    <div>
      <div className="flex justify-between text-xs text-muted-foreground mb-1">
        <span>{label}</span>
        <span>{value != null ? `${value}%` : "—"}</span>
      </div>
      <Progress value={pctBar(value)} className="h-1.5" />
    </div>
  );
}

function ResourceCard({ icon: Icon, label, value, sub }: { icon: typeof Cpu; label: string; value: string; sub: string }) {
  return (
    <Card className="panel-card">
      <CardContent className="p-4 flex items-center gap-3">
        <Icon className="h-5 w-5 text-primary shrink-0" />
        <div>
          <div className="text-xs text-muted-foreground">{label}</div>
          <div className="font-mono font-bold">{value}</div>
          <div className="text-[11px] text-muted-foreground">{sub}</div>
        </div>
      </CardContent>
    </Card>
  );
}

function LogTable({
  title,
  icon: Icon,
  rows,
  empty,
}: {
  title: string;
  icon: typeof Cpu;
  rows: Array<{ id: string; primary: string; secondary: string; meta: string; error?: boolean }>;
  empty: string;
}) {
  return (
    <Card className="panel-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icon className="h-4 w-4 text-primary" />
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {!rows.length ? (
          <p className="text-sm text-muted-foreground font-mono">{empty}</p>
        ) : (
          <div className="max-h-[420px] overflow-y-auto space-y-2">
            {rows.map((row) => (
              <div
                key={row.id}
                className={`p-3 rounded-lg border text-sm ${row.error ? "border-red-500/30 bg-red-500/5" : "border-border/50"}`}
              >
                <div className="font-mono text-xs">{row.primary}</div>
                <div className="flex justify-between mt-1 text-xs text-muted-foreground">
                  <span>{row.secondary}</span>
                  <span>{row.meta}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border/50 p-3">
      <div className="text-[11px] uppercase tracking-[0.14em] text-muted-foreground">{label}</div>
      <div className="mt-1 font-mono text-xs break-all">{value}</div>
    </div>
  );
}
