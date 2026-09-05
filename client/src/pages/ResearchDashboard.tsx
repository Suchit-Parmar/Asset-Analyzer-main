import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { EmptyState } from "@/components/states";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar,
} from "recharts";
import {
  Activity, AlertTriangle, Boxes, Brain, Database, FlaskConical,
  GitBranch, Layers, Loader2, Download, RefreshCw, ShieldCheck, TrendingUp, History,
} from "lucide-react";
import {
  useDatasetVersions, useRegisterDataset, useDriftReports, useComputeDrift,
  useTrainingHistory, useRetrainCandidate, useCompareCandidate, useApproveCandidate,
  useReviewQueue, useRelabelReview, useApproveReview, useKnowledgeBase,
  useModelRegistry, useApprovalHistory, useRollbackModel, useRollbackInfo,
} from "@/hooks/useApi";
import { api, type ModelComparison } from "@/lib/api";
import { toast } from "@/hooks/use-toast";

const DATASETS = [
  { value: "cicids2017", label: "CICIDS2017" },
  { value: "unsw_nb15", label: "UNSW-NB15" },
  { value: "cse_cic_ids2018", label: "CSE-CIC-IDS2018" },
];

const RETRAIN_MODES = [
  { value: "full", label: "Full Retraining" },
  { value: "incremental", label: "Incremental Fine-Tuning" },
  { value: "transfer", label: "Transfer Learning" },
  { value: "resume", label: "Resume From Checkpoint" },
];

const ATTACK_LABELS = [
  "Normal", "DDoS", "DoS", "Probe", "R2L", "U2R", "Botnet",
  "Web Attack", "Infiltration", "Brute Force", "Heartbleed",
];

function pct(v?: number | null): string {
  if (v == null || Number.isNaN(v)) return "—";
  return `${(v * 100).toFixed(1)}%`;
}

function severityColor(sev?: string): string {
  if (sev === "significant") return "bg-red-500/15 text-red-400 border-red-500/30";
  if (sev === "moderate") return "bg-amber-500/15 text-amber-400 border-amber-500/30";
  return "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";
}

export default function ResearchDashboard() {
  const versions = useDatasetVersions();
  const drift = useDriftReports();
  const history = useTrainingHistory();
  const review = useReviewQueue();
  const kb = useKnowledgeBase();
  const registry = useModelRegistry();
  const approvals = useApprovalHistory();
  const rollback = useRollbackModel();
  const rollbackInfo = useRollbackInfo();

  const registerDataset = useRegisterDataset();
  const computeDrift = useComputeDrift();
  const retrain = useRetrainCandidate();
  const compare = useCompareCandidate();
  const approve = useApproveCandidate();
  const relabel = useRelabelReview();
  const approveSample = useApproveReview();

  const [dataset, setDataset] = useState("cicids2017");
  const [mode, setMode] = useState("full");
  const [useReplay, setUseReplay] = useState(false);
  const [includeReviewSamples, setIncludeReviewSamples] = useState(false);
  const [comparison, setComparison] = useState<ModelComparison | null>(null);

  const trend = history.data?.accuracy_trend ?? [];
  const experiments = history.data?.history ?? [];
  const datasetVersions = versions.data?.datasets ?? [];
  const driftReports = drift.data?.reports ?? [];
  const reviewSamples = review.data?.samples ?? [];
  const reviewStats = review.data?.stats;
  const candidates = (registry.data?.models ?? []).filter(
    (m) => typeof m.id === "string" && m.id.includes("candidate"),
  );

  const latestDrift = driftReports[0];
  const totalVersions = useMemo(
    () => datasetVersions.reduce((sum, d) => sum + (d.version_count ?? 0), 0),
    [datasetVersions],
  );

  const chartData = trend.map((t, i) => ({
    idx: i + 1,
    accuracy: t.accuracy != null ? Number((t.accuracy * 100).toFixed(2)) : null,
    f1: t.f1 != null ? Number((t.f1 * 100).toFixed(2)) : null,
    label: t.architecture ?? `run ${i + 1}`,
  }));

  const versionGrowthData = useMemo(
    () => datasetVersions.map((d) => ({
      name: (d.display_name ?? d.name).slice(0, 14),
      versions: d.version_count ?? d.versions?.length ?? 0,
      rows: d.versions?.reduce((sum, v) => sum + (v.rows ?? 0), 0) ?? 0,
    })),
    [datasetVersions],
  );

  const experimentCompareData = useMemo(() => {
    return experiments.slice(0, 8).reverse().map((exp, i) => {
      const m = (exp.metrics as { test?: { accuracy?: number; f1?: number } } | undefined)?.test ?? {};
      return {
        name: String(exp.architecture ?? `Run ${i + 1}`).slice(0, 10),
        accuracy: m.accuracy != null ? Number((m.accuracy * 100).toFixed(1)) : null,
        f1: m.f1 != null ? Number((m.f1 * 100).toFixed(1)) : null,
      };
    });
  }, [experiments]);

  async function handleRegister() {
    try {
      const res = await registerDataset.mutateAsync({ datasetId: dataset, source: "loader" });
      const nested = (res as { dataset?: { status?: string; message?: string; accepted?: boolean } }).dataset;
      const status = nested?.status ?? (res as { status?: string }).status ?? "unknown";
      const message = nested?.message ?? (res as { message?: string }).message ?? "";
      toast({
        title: status === "accepted" ? "Dataset version created" : `Dataset ${status}`,
        description: message,
        variant: status === "rejected" || status === "failed" ? "destructive" : "default",
      });
    } catch (err) {
      toast({ title: "Registration failed", description: msg(err), variant: "destructive" });
    }
  }

  async function handleDownloadReport(format: "html" | "csv") {
    try {
      await api.downloadReport(format);
      toast({
        title: format === "html" ? "Report opened" : "CSV downloaded",
        description: format === "html" ? "Evaluation report opened in a new tab." : "evaluation-report.csv saved.",
      });
    } catch (err) {
      toast({ title: "Report download failed", description: msg(err), variant: "destructive" });
    }
  }

  async function handleDrift() {
    try {
      const res = await computeDrift.mutateAsync({ datasetId: dataset });
      toast({
        title: "Drift analysed",
        description: (res as { summary?: string; message?: string }).summary
          ?? (res as { message?: string }).message ?? "Done.",
      });
    } catch (err) {
      toast({ title: "Drift check failed", description: msg(err), variant: "destructive" });
    }
  }

  async function handleRetrain() {
    try {
      const res = await retrain.mutateAsync({
        datasetId: dataset,
        mode,
        epochs: 30,
        useReplay,
        includeReviewSamples,
      });
      toast({
        title: "Candidate training started",
        description: `${res.candidate_id}${res.replay_rows ? ` · ${res.replay_rows} replay rows` : ""} — compare & approve before activation.`,
      });
    } catch (err) {
      toast({ title: "Retrain failed", description: msg(err), variant: "destructive" });
    }
  }

  async function handleRollback() {
    if (!window.confirm("Roll back to the previous active checkpoint?")) return;
    try {
      await rollback.mutateAsync();
      toast({ title: "Model rolled back", description: "Previous active checkpoint restored." });
    } catch (err) {
      toast({ title: "Rollback failed", description: msg(err), variant: "destructive" });
    }
  }

  async function handleCompare(candidateId: string) {
    try {
      const res = await compare.mutateAsync(candidateId);
      setComparison(res);
    } catch (err) {
      toast({ title: "Compare failed", description: msg(err), variant: "destructive" });
    }
  }

  async function handleApprove(candidateId: string) {
    if (!window.confirm(`Promote "${candidateId}" to the ACTIVE model? This replaces what inference uses.`)) return;
    try {
      await approve.mutateAsync(candidateId);
      toast({ title: "Model activated", description: `${candidateId} is now the active model.` });
      setComparison(null);
    } catch (err) {
      toast({ title: "Approval failed", description: msg(err), variant: "destructive" });
    }
  }

  return (
    <main className="flex-1 overflow-auto p-6 space-y-6">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-2">
              <FlaskConical className="h-7 w-7 text-primary" /> Research Dashboard
            </h1>
            <p className="text-muted-foreground mt-1">
              Continual learning — dataset versions, drift, experiments, model evolution and review.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => handleDownloadReport("html")}>
              <Download className="h-4 w-4 mr-1" /> Report (HTML)
            </Button>
            <Button size="sm" variant="outline" onClick={() => handleDownloadReport("csv")}>
              <Download className="h-4 w-4 mr-1" /> CSV
            </Button>
          </div>
        </div>

        {/* Summary cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <SummaryCard icon={Database} label="Dataset Versions" value={String(totalVersions)}
            hint={`${datasetVersions.length} dataset(s)`} />
          <SummaryCard icon={GitBranch} label="Experiments" value={String(experiments.length)}
            hint="training runs tracked" />
          <SummaryCard
            icon={AlertTriangle}
            label="Drift Status"
            value={latestDrift?.severity ?? "none"}
            hint={latestDrift?.recommend_retraining ? "retraining recommended" : "stable"}
            accent={severityColor(latestDrift?.severity)}
          />
          <SummaryCard icon={Brain} label="Review Queue" value={String(reviewStats?.pending ?? 0)}
            hint={`${reviewStats?.approved ?? 0} approved`} />
        </div>

        <Tabs defaultValue="datasets" className="w-full">
          <TabsList className="flex flex-wrap h-auto">
            <TabsTrigger value="datasets"><Layers className="h-4 w-4 mr-1" /> Datasets</TabsTrigger>
            <TabsTrigger value="drift"><Activity className="h-4 w-4 mr-1" /> Drift</TabsTrigger>
            <TabsTrigger value="evolution"><TrendingUp className="h-4 w-4 mr-1" /> Model Evolution</TabsTrigger>
            <TabsTrigger value="experiments"><GitBranch className="h-4 w-4 mr-1" /> Experiments</TabsTrigger>
            <TabsTrigger value="approvals"><History className="h-4 w-4 mr-1" /> Approvals</TabsTrigger>
            <TabsTrigger value="retrain"><RefreshCw className="h-4 w-4 mr-1" /> Retrain &amp; Approve</TabsTrigger>
            <TabsTrigger value="review"><Brain className="h-4 w-4 mr-1" /> Review Queue</TabsTrigger>
            <TabsTrigger value="knowledge"><Boxes className="h-4 w-4 mr-1" /> Knowledge Base</TabsTrigger>
          </TabsList>

          {/* -- Datasets -- */}
          <TabsContent value="datasets" className="space-y-4">
            <Card className="panel-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Collect &amp; version a dataset</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-wrap items-end gap-3">
                <div className="min-w-[220px]">
                  <label className="text-xs text-muted-foreground">Source dataset</label>
                  <Select value={dataset} onValueChange={setDataset}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {DATASETS.map((d) => <SelectItem key={d.value} value={d.value}>{d.label}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <Button onClick={handleRegister} disabled={registerDataset.isPending}>
                  {registerDataset.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Database className="h-4 w-4 mr-1" />}
                  Collect &amp; version
                </Button>
                <p className="text-xs text-muted-foreground">
                  Runs quality checks, deduplicates by content hash, and stores an immutable version.
                </p>
              </CardContent>
            </Card>

            {versions.isLoading ? (
              <Loading />
            ) : datasetVersions.length === 0 ? (
              <EmptyState title="No dataset versions yet" message="Collect a dataset above to create version 1." />
            ) : (
              <>
                <Card className="panel-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg">Dataset version growth</CardTitle>
                  </CardHeader>
                  <CardContent style={{ height: 280 }}>
                    {versionGrowthData.length === 0 ? (
                      <EmptyState title="No version data" message="Collect datasets to populate the growth chart." />
                    ) : (
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={versionGrowthData} margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
                          <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
                          <YAxis stroke="#64748b" fontSize={12} />
                          <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }} />
                          <Bar dataKey="versions" fill="#22d3ee" name="Versions" radius={[4, 4, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>
                {datasetVersions.map((d) => (
                <Card key={d.name} className="panel-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base flex items-center gap-2">
                      <Database className="h-4 w-4 text-primary" /> {d.display_name ?? d.name}
                      <Badge variant="outline">{d.version_count} version(s)</Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Version</TableHead>
                          <TableHead>Created</TableHead>
                          <TableHead>Rows</TableHead>
                          <TableHead>Classes</TableHead>
                          <TableHead>Quality</TableHead>
                          <TableHead>Source</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        { (d.versions ?? []).slice().reverse().map((v) => (
                          <TableRow key={v.version}>
                            <TableCell className="font-mono">{v.version}</TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {v.created_at ? new Date(v.created_at).toLocaleString() : "—"}
                            </TableCell>
                            <TableCell>{v.rows?.toLocaleString() ?? "—"}</TableCell>
                            <TableCell>{v.classes?.length ?? 0}</TableCell>
                            <TableCell>
                              <Badge className={v.quality_passed ? severityColor("none") : severityColor("significant")}>
                                {v.quality_score != null ? `${(v.quality_score * 100).toFixed(0)}%` : "—"}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-xs">{v.source ?? "—"}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              ))}
              </>
            )}
          </TabsContent>

          {/* -- Drift -- */}
          <TabsContent value="drift" className="space-y-4">
            <Card className="panel-card">
              <CardHeader className="pb-2"><CardTitle className="text-lg">Run drift analysis</CardTitle></CardHeader>
              <CardContent className="flex flex-wrap items-end gap-3">
                <div className="min-w-[220px]">
                  <label className="text-xs text-muted-foreground">Dataset</label>
                  <Select value={dataset} onValueChange={setDataset}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {DATASETS.map((d) => <SelectItem key={d.value} value={d.value}>{d.label}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <Button onClick={handleDrift} disabled={computeDrift.isPending}>
                  {computeDrift.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <Activity className="h-4 w-4 mr-1" />}
                  Analyse drift
                </Button>
                <p className="text-xs text-muted-foreground">
                  Compares current data vs the dataset's registered baseline (PSI + label drift). Register a version first.
                </p>
              </CardContent>
            </Card>

            {drift.isLoading ? (
              <Loading />
            ) : driftReports.length === 0 ? (
              <EmptyState title="No drift reports yet" message="Register a dataset version, then run drift analysis." />
            ) : (
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                {driftReports.map((r, i) => (
                  <Card key={i} className="panel-card">
                    <CardHeader className="pb-2 flex flex-row items-center justify-between">
                      <CardTitle className="text-base flex items-center gap-2">
                        {r.name ?? "drift"}
                        <Badge className={severityColor(r.severity)}>{r.severity}</Badge>
                      </CardTitle>
                      <span className="text-xs text-muted-foreground">
                        {r.computed_at ? new Date(r.computed_at).toLocaleString() : ""}
                      </span>
                    </CardHeader>
                    <CardContent className="space-y-2 text-sm">
                      <p className="text-muted-foreground">{r.summary}</p>
                      <div className="grid grid-cols-3 gap-2">
                        <Stat label="Avg PSI" value={r.avg_psi?.toFixed(3) ?? "—"} />
                        <Stat label="Max PSI" value={r.max_psi?.toFixed(3) ?? "—"} />
                        <Stat label="Label drift" value={r.label_drift?.toFixed(3) ?? "—"} />
                      </div>
                      {r.drift_types?.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {r.drift_types.map((t) => <Badge key={t} variant="outline">{t}</Badge>)}
                        </div>
                      )}
                      {r.recommend_retraining && (
                        <div className="text-xs text-amber-400 flex items-center gap-1">
                          <AlertTriangle className="h-3 w-3" /> Retraining recommended (evaluation + approval required)
                        </div>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </TabsContent>

          {/* -- Model Evolution -- */}
          <TabsContent value="evolution" className="space-y-4">
            <Card className="panel-card">
              <CardHeader className="pb-2"><CardTitle className="text-lg">Accuracy &amp; F1 trend across runs</CardTitle></CardHeader>
              <CardContent style={{ height: 320 }}>
                {chartData.length === 0 ? (
                  <EmptyState title="No training runs yet" message="Train or retrain a model to build the evolution trend." />
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={chartData} margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
                      <XAxis dataKey="idx" stroke="#64748b" fontSize={12} />
                      <YAxis domain={[0, 100]} stroke="#64748b" fontSize={12} unit="%" />
                      <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }} />
                      <Line type="monotone" dataKey="accuracy" stroke="#22d3ee" strokeWidth={2} dot={false} name="Accuracy" />
                      <Line type="monotone" dataKey="f1" stroke="#a78bfa" strokeWidth={2} dot={false} name="F1" />
                    </LineChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* -- Experiments -- */}
          <TabsContent value="experiments" className="space-y-4">
            <Card className="panel-card">
              <CardHeader className="pb-2"><CardTitle className="text-lg">Experiment comparison (test accuracy / F1)</CardTitle></CardHeader>
              <CardContent style={{ height: 280 }}>
                {experimentCompareData.length === 0 ? (
                  <EmptyState title="No experiment metrics" message="Run training to compare experiment outcomes." />
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={experimentCompareData} margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
                      <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
                      <YAxis domain={[0, 100]} stroke="#64748b" fontSize={12} unit="%" />
                      <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }} />
                      <Bar dataKey="accuracy" fill="#22d3ee" name="Accuracy %" radius={[4, 4, 0, 0]} />
                      <Bar dataKey="f1" fill="#a78bfa" name="F1 %" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>
            <Card className="panel-card">
              <CardHeader className="pb-2"><CardTitle className="text-lg">Experiment tracking</CardTitle></CardHeader>
              <CardContent>
                {history.isLoading ? (
                  <Loading />
                ) : experiments.length === 0 ? (
                  <EmptyState title="No experiments recorded" message="Every training run is logged here automatically." />
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>When</TableHead>
                        <TableHead>Dataset</TableHead>
                        <TableHead>Arch</TableHead>
                        <TableHead>Mode</TableHead>
                        <TableHead>Strategy</TableHead>
                        <TableHead>Test Acc</TableHead>
                        <TableHead>Test F1</TableHead>
                        <TableHead>Time</TableHead>
                        <TableHead>Commit</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {experiments.map((e) => {
                        const m = (e.metrics ?? {}) as Record<string, unknown>;
                        const test = (m.test ?? {}) as Record<string, number>;
                        return (
                          <TableRow key={e.id}>
                            <TableCell className="text-xs text-muted-foreground">
                              {e.recorded_at ? new Date(e.recorded_at).toLocaleString() : "—"}
                            </TableCell>
                            <TableCell>{e.dataset_id ?? "—"}</TableCell>
                            <TableCell className="uppercase text-xs">{e.architecture ?? "—"}</TableCell>
                            <TableCell>{e.mode ?? "full"}{e.activated ? "" : " (candidate)"}</TableCell>
                            <TableCell className="text-xs">{e.graph_strategy ?? "—"}</TableCell>
                            <TableCell>{pct(test.accuracy)}</TableCell>
                            <TableCell>{pct(test.f1)}</TableCell>
                            <TableCell className="text-xs">{e.training_time_sec != null ? `${e.training_time_sec}s` : "—"}</TableCell>
                            <TableCell className="font-mono text-xs">{e.git_commit ?? "—"}</TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* -- Approval History -- */}
          <TabsContent value="approvals" className="space-y-4">
            <Card className="panel-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-primary" /> Model approval history
                </CardTitle>
              </CardHeader>
              <CardContent>
                {approvals.isLoading ? (
                  <Loading />
                ) : (approvals.data?.approvals ?? []).length === 0 ? (
                  <EmptyState
                    title="No approvals yet"
                    message="When a candidate model is explicitly approved, the decision is recorded here."
                  />
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>When</TableHead>
                        <TableHead>Candidate</TableHead>
                        <TableHead>Dataset</TableHead>
                        <TableHead>Recommendation</TableHead>
                        <TableHead>Approved By</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {(approvals.data?.approvals ?? []).map((a) => (
                        <TableRow key={a.id}>
                          <TableCell className="text-xs text-muted-foreground">
                            {a.approved_at ? new Date(a.approved_at).toLocaleString() : "—"}
                          </TableCell>
                          <TableCell className="font-mono text-xs">{a.candidate_id}</TableCell>
                          <TableCell>{a.active_dataset ?? "—"}</TableCell>
                          <TableCell>
                            <Badge variant="outline">{a.comparison_recommendation ?? "approved"}</Badge>
                          </TableCell>
                          <TableCell className="text-xs">{a.approved_by ?? "operator"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* -- Retrain & Approve -- */}
          <TabsContent value="retrain" className="space-y-4">
            <Card className="panel-card">
              <CardHeader className="pb-2"><CardTitle className="text-lg">Smart retraining (candidate only)</CardTitle></CardHeader>
              <CardContent className="flex flex-wrap items-end gap-3">
                <div className="min-w-[200px]">
                  <label className="text-xs text-muted-foreground">Dataset</label>
                  <Select value={dataset} onValueChange={setDataset}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {DATASETS.map((d) => <SelectItem key={d.value} value={d.value}>{d.label}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className="min-w-[200px]">
                  <label className="text-xs text-muted-foreground">Strategy</label>
                  <Select value={mode} onValueChange={setMode}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {RETRAIN_MODES.map((d) => <SelectItem key={d.value} value={d.value}>{d.label}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <Button onClick={handleRetrain} disabled={retrain.isPending}>
                  {retrain.isPending ? <Loader2 className="h-4 w-4 mr-1 animate-spin" /> : <RefreshCw className="h-4 w-4 mr-1" />}
                  Train candidate
                </Button>
                <Button
                  variant="outline"
                  onClick={handleRollback}
                  disabled={rollback.isPending || !rollbackInfo.data?.available}
                >
                  Rollback active
                </Button>
                <div className="flex flex-col gap-2 w-full">
                  <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
                    <Checkbox checked={useReplay} onCheckedChange={(v) => setUseReplay(Boolean(v))} />
                    Mix replay buffer rows (anti-forgetting rehearsal)
                  </label>
                  <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
                    <Checkbox checked={includeReviewSamples} onCheckedChange={(v) => setIncludeReviewSamples(Boolean(v))} />
                    Include approved review-queue samples
                  </label>
                </div>
                <p className="text-xs text-muted-foreground max-w-md">
                  Candidates never replace the active model. Compare, then approve to activate.
                </p>
              </CardContent>
            </Card>

            <Card className="panel-card">
              <CardHeader className="pb-2"><CardTitle className="text-base">Candidate models</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                {candidates.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No candidate checkpoints. Train one above.</p>
                ) : (
                  candidates.map((c) => (
                    <div key={c.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border/60 p-3">
                      <div>
                        <div className="font-mono text-sm">{c.id}</div>
                        <div className="text-xs text-muted-foreground">
                          {pct(c.metrics?.test_f1 ?? c.metrics?.f1)} F1 · {c.trained_at ? new Date(c.trained_at).toLocaleString() : ""}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button size="sm" variant="outline" onClick={() => handleCompare(c.id)} disabled={compare.isPending}>
                          Compare
                        </Button>
                        <Button size="sm" onClick={() => handleApprove(c.id)} disabled={approve.isPending}>
                          <ShieldCheck className="h-4 w-4 mr-1" /> Approve &amp; activate
                        </Button>
                      </div>
                    </div>
                  ))
                )}

                {comparison && (
                  <div className="rounded-lg border border-primary/30 bg-primary/5 p-3 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-semibold">Comparison · {comparison.candidate_id}</span>
                      <Badge className={comparison.comparison.candidate_better ? severityColor("none") : severityColor("moderate")}>
                        {comparison.comparison.recommendation}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">{comparison.comparison.reason}</p>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Metric</TableHead>
                          <TableHead>Active</TableHead>
                          <TableHead>Candidate</TableHead>
                          <TableHead>Δ</TableHead>
                          <TableHead>Better</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {comparison.comparison.rows.map((r) => (
                          <TableRow key={r.metric}>
                            <TableCell className="text-xs">{r.metric}</TableCell>
                            <TableCell className="text-xs">{fmtCell(r.active)}</TableCell>
                            <TableCell className="text-xs">{fmtCell(r.candidate)}</TableCell>
                            <TableCell className="text-xs">{r.delta ?? "—"}</TableCell>
                            <TableCell className="text-xs">
                              {r.better === "candidate" ? <span className="text-emerald-400">candidate</span>
                                : r.better === "active" ? <span className="text-amber-400">active</span>
                                : r.better ?? "—"}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* -- Review Queue -- */}
          <TabsContent value="review" className="space-y-4">
            <Card className="panel-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">Unknown / low-confidence queue (active learning)</CardTitle>
              </CardHeader>
              <CardContent>
                {review.isLoading ? (
                  <Loading />
                ) : reviewSamples.length === 0 ? (
                  <EmptyState title="Queue is empty" message="Low-confidence and unknown predictions are captured here for review." />
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Captured</TableHead>
                        <TableHead>Predicted</TableHead>
                        <TableHead>Confidence</TableHead>
                        <TableHead>Reason</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Relabel</TableHead>
                        <TableHead></TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {reviewSamples.map((s) => (
                        <TableRow key={s.id}>
                          <TableCell className="text-xs text-muted-foreground">
                            {s.captured_at ? new Date(s.captured_at).toLocaleString() : "—"}
                          </TableCell>
                          <TableCell>{s.predicted_attack_type ?? "—"}</TableCell>
                          <TableCell>{pct(s.confidence)}</TableCell>
                          <TableCell className="text-xs">{s.reason ?? "—"}</TableCell>
                          <TableCell>
                            <Badge variant="outline">{s.true_label ? `${s.status} → ${s.true_label}` : s.status}</Badge>
                          </TableCell>
                          <TableCell>
                            <Select onValueChange={(label) => relabel.mutate({ id: s.id, label })}>
                              <SelectTrigger className="h-8 w-[130px]"><SelectValue placeholder="Label…" /></SelectTrigger>
                              <SelectContent>
                                {ATTACK_LABELS.map((l) => <SelectItem key={l} value={l}>{l}</SelectItem>)}
                              </SelectContent>
                            </Select>
                          </TableCell>
                          <TableCell>
                            <Button size="sm" variant="outline" onClick={() => approveSample.mutate(s.id)}
                              disabled={s.status === "approved"}>
                              Approve
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* -- Knowledge Base -- */}
          <TabsContent value="knowledge" className="space-y-4">
            {kb.isLoading ? (
              <Loading />
            ) : (
              <>
                <Card className="panel-card">
                  <CardContent className="pt-4 text-sm text-muted-foreground">{kb.data?.summary}</CardContent>
                </Card>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <KbList title="Known attacks" items={(kb.data?.known_attacks ?? []).map((a) => `${a.name} · ${a.mitre_technique} · ${a.threat_level}`)} />
                  <KbList title="Historical (observed)" items={(kb.data?.historical_attacks ?? []).map((a) => `${a.name} — ${(a.count ?? 0).toLocaleString()}`)} />
                  <KbList title="Unknown labels" items={(kb.data?.unknown_attacks ?? []).map((a) => `${a.name} — ${a.count ?? 0}`)} empty="None flagged." />
                  <KbList title="Emerging patterns" items={(kb.data?.emerging_patterns ?? []).map((a) => `${a.name} +${(((a.delta ?? 0) * 100)).toFixed(1)}%`)} empty="No emerging patterns." />
                </div>
              </>
            )}
          </TabsContent>
        </Tabs>
      </main>
  );
}

function msg(err: unknown): string {
  return err instanceof Error ? err.message : "Unknown error";
}

function fmtCell(v: unknown): string {
  if (v == null) return "—";
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toFixed(4);
  return String(v);
}

function SummaryCard({ icon: Icon, label, value, hint, accent }: {
  icon: typeof Database; label: string; value: string; hint?: string; accent?: string;
}) {
  return (
    <Card className="panel-card">
      <CardContent className="pt-4">
        <div className="flex items-center gap-2 text-muted-foreground text-xs uppercase tracking-wider">
          <Icon className="h-4 w-4" /> {label}
        </div>
        <div className={`mt-2 text-2xl font-bold capitalize ${accent ? "inline-block px-2 py-0.5 rounded border " + accent : "text-white"}`}>
          {value}
        </div>
        {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
      </CardContent>
    </Card>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="panel-subtle rounded-lg p-2">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="font-mono text-sm text-cyan-200">{value}</div>
    </div>
  );
}

function KbList({ title, items, empty }: { title: string; items: string[]; empty?: string }) {
  return (
    <Card className="panel-card">
      <CardHeader className="pb-2"><CardTitle className="text-base">{title}</CardTitle></CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <p className="text-sm text-muted-foreground">{empty ?? "None."}</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {items.map((it, i) => <li key={i} className="font-mono text-xs text-muted-foreground">{it}</li>)}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

function Loading() {
  return (
    <div className="flex items-center gap-2 text-muted-foreground">
      <Loader2 className="h-5 w-5 animate-spin" /> Loading…
    </div>
  );
}
