/**
 * Model Performance Hub — live metrics from GET /api/metrics (Phase 5 advanced evaluation).
 */
import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Download, Share2, Maximize2, Minimize2, RadioTower } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { useMetrics } from "@/hooks/useApi";
import { EmptyState, ErrorState, PageLoader } from "@/components/states";
import { api } from "@/lib/api";

const ROC_COLORS = ["#06b6d4", "#f59e0b", "#22c55e", "#a78bfa", "#ef4444", "#eab308"];

function num(v: unknown, digits = 4): string {
  return typeof v === "number" && !Number.isNaN(v) ? v.toFixed(digits) : "—";
}

function pct(v: unknown): string {
  return typeof v === "number" && !Number.isNaN(v) ? `${(v * 100).toFixed(1)}%` : "—";
}

export default function Evaluation() {
  const { toast } = useToast();
  const [expandedChart, setExpandedChart] = useState<"roc" | "pr" | null>(null);
  const { data: metricsData, isLoading, isError, refetch, isFetching } = useMetrics();

  const raw = metricsData?.metrics as Record<string, unknown> | undefined;
  const headline = metricsData?.headline ?? {};
  const m = useMemo(() => {
    const h = headline as Record<string, unknown>;
    const r = raw ?? {};
    return {
      accuracy: (h.accuracy ?? r.accuracy) as number | undefined,
      precision: (h.precision ?? r.precision) as number | undefined,
      recall: (h.recall ?? r.recall) as number | undefined,
      f1: (h.f1 ?? r.f1) as number | undefined,
      macro_f1: (h.macro_f1 ?? r.macro_f1 ?? metricsData?.macro?.f1) as number | undefined,
      roc_auc: (h.roc_auc ?? r.roc_auc) as number | undefined,
      train_loss: (h.train_loss ?? r.train_loss) as number | undefined,
      val_loss: (h.val_loss ?? r.val_loss) as number | undefined,
      best_epoch: (h.best_epoch ?? r.best_epoch) as number | undefined,
    };
  }, [headline, raw, metricsData?.macro?.f1]);

  const perClass = metricsData?.per_class ?? (raw?.per_class as Record<string, { precision?: number; recall?: number; f1?: number; support?: number }> | undefined) ?? {};
  const confusion = metricsData?.confusion_matrix ?? (raw?.confusion_matrix as number[][] | undefined);
  const classLabels = metricsData?.class_labels ?? (raw?.class_labels as string[] | undefined) ?? [];
  const classDist = metricsData?.class_distribution ?? (raw?.class_distribution as Array<{ class: string; count: number }> | undefined) ?? [];
  const rocCurves = metricsData?.roc_curves ?? (raw?.roc_curves as Record<string, Array<{ fpr: number; tpr: number }>> | undefined) ?? {};
  const prCurves = metricsData?.pr_curves ?? (raw?.pr_curves as Record<string, Array<{ recall: number; precision: number }>> | undefined) ?? {};
  const learningCurve = metricsData?.learning_curve ?? (raw?.history as Array<Record<string, number>> | undefined) ?? [];

  const rocChartData = useMemo(() => {
    const names = Object.keys(rocCurves);
    if (!names.length) return [];
    const maxLen = Math.max(...names.map((n) => rocCurves[n]?.length ?? 0));
    return Array.from({ length: maxLen }, (_, i) => {
      const row: Record<string, number | string> = { idx: i };
      names.forEach((n) => {
        const pt = rocCurves[n]?.[i];
        if (pt) row[n] = pt.tpr;
      });
      return row;
    });
  }, [rocCurves]);

  const prChartData = useMemo(() => {
    const names = Object.keys(prCurves);
    if (!names.length) return [];
    const maxLen = Math.max(...names.map((n) => prCurves[n]?.length ?? 0));
    return Array.from({ length: maxLen }, (_, i) => {
      const row: Record<string, number | string> = { idx: i };
      names.forEach((n) => {
        const pt = prCurves[n]?.[i];
        if (pt) row[n] = pt.precision;
      });
      return row;
    });
  }, [prCurves]);

  const lossCurve = learningCurve.map((h) => ({
    epoch: `E${h.epoch ?? "?"}`,
    train_loss: h.train_loss,
    val_loss: h.val_loss,
    val_accuracy: h.val_accuracy,
    f1: h.f1,
  }));

  const perClassRows = Object.entries(perClass).map(([cls, vals]) => ({
    class: cls,
    precision: vals.precision ?? 0,
    recall: vals.recall ?? 0,
    f1: vals.f1 ?? 0,
    support: vals.support ?? 0,
  }));

  const hasMetrics = metricsData?.model_loaded || Object.keys(raw ?? {}).length > 0;

  const handleShare = () => {
    navigator.clipboard.writeText(window.location.href).then(() => {
      toast({ title: "Link copied", description: "Report URL copied to clipboard." });
    }).catch(() => {
      toast({ title: "Share", description: "Copy this URL: " + window.location.href });
    });
  };

  const handleExport = async (format: "html" | "csv" | "json") => {
    try {
      await api.downloadReport(format);
      toast({ title: "Export started", description: `${format.toUpperCase()} evaluation report ready.` });
    } catch (err) {
      toast({
        title: "Export failed",
        description: err instanceof Error ? err.message : "Could not download report",
        variant: "destructive",
      });
    }
  };

  const handlePdfExport = async () => {
    try {
      await api.downloadReport("html");
      toast({ title: "PDF export", description: "Print-ready report opened — choose Save as PDF in the print dialog." });
    } catch (err) {
      toast({
        title: "PDF export failed",
        description: err instanceof Error ? err.message : "Could not open report",
        variant: "destructive",
      });
    }
  };

  if (isLoading) {
    return <PageLoader label="Loading model metrics…" />;
  }

  return (
    <main className="app-main flex-1 overflow-auto p-4 md:p-6 space-y-6">
        <div className="page-header flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="page-kicker">Performance Intelligence</div>
            <h1 className="text-3xl font-bold tracking-tight text-white mb-2">Model Performance Hub</h1>
            <p className="text-muted-foreground font-mono text-sm max-w-2xl">
              Advanced evaluation from the active TGNN checkpoint — ROC/PR curves, confusion matrix,
              per-class metrics, and training history. Retrain to refresh curve data.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" className="gap-2" onClick={() => refetch()} disabled={isFetching}>
              Refresh
            </Button>
            <Button variant="outline" size="sm" className="gap-2" onClick={handleShare}>
              <Share2 size={14} /> Share
            </Button>
            <Button variant="outline" size="sm" className="gap-2" onClick={() => handleExport("csv")}>
              <Download size={14} /> CSV
            </Button>
            <Button variant="outline" size="sm" className="gap-2" onClick={() => handleExport("json")}>
              <Download size={14} /> JSON
            </Button>
            <Button variant="default" size="sm" className="gap-2 bg-primary text-primary-foreground" onClick={handlePdfExport}>
              <Download size={14} /> PDF Report
            </Button>
          </div>
        </div>

        {isError && (
          <ErrorState
            title="Metrics unavailable"
            message="Could not reach /api/metrics. Ensure the AI service is running and a checkpoint exists."
            onRetry={() => refetch()}
          />
        )}

        {!isError && !hasMetrics && (
          <EmptyState
            title="No trained metrics yet"
            message="Train or load a TGNN checkpoint (Phase 2), then refresh this page."
          />
        )}

        {!isError && hasMetrics && (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
              {[
                { key: "Accuracy", value: pct(m.accuracy) },
                { key: "Precision", value: pct(m.precision) },
                { key: "Recall", value: pct(m.recall) },
                { key: "F1", value: pct(m.f1) },
                { key: "Macro F1", value: pct(m.macro_f1) },
                { key: "ROC-AUC", value: num(m.roc_auc) },
                { key: "Train Loss", value: num(m.train_loss) },
                { key: "Val Loss", value: num(m.val_loss) },
              ].map((item) => (
                <Card key={item.key} className="metric-surface rounded-[1.35rem] border-primary/20">
                  <CardContent className="p-3 flex flex-col items-center text-center">
                    <span className="text-muted-foreground text-[10px] uppercase tracking-wider mb-1">{item.key}</span>
                    <span className="text-lg font-mono font-bold text-primary">{item.value}</span>
                  </CardContent>
                </Card>
              ))}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <Card className="panel-card lg:col-span-1">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <RadioTower size={18} className="text-primary" />
                    Model Artefacts
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3 text-sm font-mono">
                  <Row label="Architecture" value={String(metricsData?.architecture ?? "—")} />
                  <Row label="Dataset" value={String(metricsData?.dataset_id ?? "—")} />
                  <Row label="Graph strategy" value={String(metricsData?.graph_strategy ?? "—")} />
                  <Row label="Trained at" value={metricsData?.trained_at ? new Date(metricsData.trained_at).toLocaleString() : "—"} />
                  <Row label="Best epoch" value={String(m.best_epoch ?? "—")} />
                  <Row label="Training time" value={metricsData?.training_time_sec != null ? `${metricsData.training_time_sec}s` : "—"} />
                  <Row label="Inference speed" value={metricsData?.inference_time_ms != null ? `${metricsData.inference_time_ms} ms/snapshot` : "—"} />
                  <Row label="Model size" value={metricsData?.model_size_mb != null ? `${metricsData.model_size_mb} MB` : "—"} />
                </CardContent>
              </Card>

              <Card className="panel-card lg:col-span-2">
                <CardHeader><CardTitle>Class Distribution (Test Support)</CardTitle></CardHeader>
                <CardContent className="h-[260px]">
                  {classDist.length === 0 ? (
                    <p className="text-sm text-muted-foreground font-mono">Retrain the model to populate class distribution.</p>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={classDist}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                        <XAxis dataKey="class" stroke="#666" tick={{ fontSize: 10 }} angle={-25} textAnchor="end" height={60} />
                        <YAxis stroke="#666" />
                        <Tooltip contentStyle={{ backgroundColor: "#111", borderColor: "#333" }} />
                        <Bar dataKey="count" fill="hsl(190, 90%, 50%)" name="Support" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  )}
                </CardContent>
              </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className={`panel-card ${expandedChart === "roc" ? "fixed inset-4 z-50 overflow-auto" : ""}`}>
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle>ROC Curves (One-vs-Rest)</CardTitle>
                  {rocChartData.length > 0 && (
                    <Button size="icon" variant="ghost" onClick={() => setExpandedChart(expandedChart === "roc" ? null : "roc")}>
                      {expandedChart === "roc" ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
                    </Button>
                  )}
                </CardHeader>
                <CardContent className={expandedChart === "roc" ? "h-[70vh]" : "h-[280px]"}>
                  {rocChartData.length === 0 ? (
                    <p className="text-sm text-muted-foreground font-mono">No ROC curve data — retrain to generate.</p>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={rocChartData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                        <XAxis dataKey="idx" hide />
                        <YAxis domain={[0, 1]} stroke="#666" />
                        <Tooltip contentStyle={{ backgroundColor: "#111", borderColor: "#333" }} />
                        <Legend />
                        {Object.keys(rocCurves).map((name, i) => (
                          <Line key={name} type="monotone" dataKey={name} stroke={ROC_COLORS[i % ROC_COLORS.length]} dot={false} strokeWidth={2} />
                        ))}
                      </LineChart>
                    </ResponsiveContainer>
                  )}
                </CardContent>
              </Card>

              <Card className={`panel-card ${expandedChart === "pr" ? "fixed inset-4 z-50 overflow-auto" : ""}`}>
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle>Precision–Recall Curves</CardTitle>
                  {prChartData.length > 0 && (
                    <Button size="icon" variant="ghost" onClick={() => setExpandedChart(expandedChart === "pr" ? null : "pr")}>
                      {expandedChart === "pr" ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
                    </Button>
                  )}
                </CardHeader>
                <CardContent className={expandedChart === "pr" ? "h-[70vh]" : "h-[280px]"}>
                  {prChartData.length === 0 ? (
                    <p className="text-sm text-muted-foreground font-mono">No PR curve data — retrain to generate.</p>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={prChartData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                        <XAxis dataKey="idx" hide />
                        <YAxis domain={[0, 1]} stroke="#666" />
                        <Tooltip contentStyle={{ backgroundColor: "#111", borderColor: "#333" }} />
                        <Legend />
                        {Object.keys(prCurves).map((name, i) => (
                          <Line key={name} type="monotone" dataKey={name} stroke={ROC_COLORS[i % ROC_COLORS.length]} dot={false} strokeWidth={2} />
                        ))}
                      </LineChart>
                    </ResponsiveContainer>
                  )}
                </CardContent>
              </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="panel-card">
                <CardHeader><CardTitle>Loss &amp; Accuracy Curves</CardTitle></CardHeader>
                <CardContent className="h-[280px]">
                  {lossCurve.length === 0 ? (
                    <p className="text-sm text-muted-foreground font-mono">No training history recorded.</p>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={lossCurve}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                        <XAxis dataKey="epoch" stroke="#666" />
                        <YAxis stroke="#666" />
                        <Tooltip contentStyle={{ backgroundColor: "#111", borderColor: "#333" }} />
                        <Legend />
                        <Line type="monotone" dataKey="train_loss" stroke="#ef4444" dot={false} name="Train Loss" />
                        <Line type="monotone" dataKey="val_loss" stroke="#f59e0b" dot={false} name="Val Loss" />
                        <Line type="monotone" dataKey="val_accuracy" stroke="#22c55e" dot={false} name="Val Accuracy" />
                        <Line type="monotone" dataKey="f1" stroke="#06b6d4" dot={false} name="F1" />
                      </LineChart>
                    </ResponsiveContainer>
                  )}
                </CardContent>
              </Card>

              <Card className="panel-card">
                <CardHeader><CardTitle>Per-Class Metrics</CardTitle></CardHeader>
                <CardContent className="h-[280px] overflow-auto">
                  {perClassRows.length === 0 ? (
                    <p className="text-sm text-muted-foreground font-mono">No per-class breakdown available.</p>
                  ) : (
                    <table className="w-full text-xs font-mono">
                      <thead>
                        <tr className="text-muted-foreground border-b border-border">
                          <th className="text-left py-2">Class</th>
                          <th className="text-right py-2">Prec</th>
                          <th className="text-right py-2">Rec</th>
                          <th className="text-right py-2">F1</th>
                          <th className="text-right py-2">N</th>
                        </tr>
                      </thead>
                      <tbody>
                        {perClassRows.map((row) => (
                          <tr key={row.class} className="border-b border-border/40">
                            <td className="py-1.5">{row.class}</td>
                            <td className="text-right">{pct(row.precision)}</td>
                            <td className="text-right">{pct(row.recall)}</td>
                            <td className="text-right">{pct(row.f1)}</td>
                            <td className="text-right">{row.support}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </CardContent>
              </Card>
            </div>

            {confusion && confusion.length > 0 && (
              <Card className="panel-card">
                <CardHeader><CardTitle>Confusion Matrix</CardTitle></CardHeader>
                <CardContent className="overflow-x-auto">
                  <table className="text-xs font-mono mx-auto">
                    <thead>
                      <tr>
                        <th className="p-2 text-muted-foreground">Actual ↓ / Pred →</th>
                        {(classLabels.length ? classLabels : confusion.map((_, i) => String(i))).map((l) => (
                          <th key={l} className="p-2 text-cyan-300 font-normal">{l}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {confusion.map((row, i) => {
                        const label = classLabels[i] ?? String(i);
                        const maxVal = Math.max(...row, 1);
                        return (
                          <tr key={label}>
                            <th className="p-2 text-left text-muted-foreground font-normal">{label}</th>
                            {row.map((cell, j) => (
                              <td
                                key={j}
                                className="p-2 text-center rounded"
                                style={{
                                  backgroundColor: `rgba(6, 182, 212, ${0.08 + (cell / maxVal) * 0.45})`,
                                }}
                              >
                                {cell}
                              </td>
                            ))}
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </CardContent>
              </Card>
            )}
          </>
        )}
      </main>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-border/40 pb-2">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-foreground">{value}</span>
    </div>
  );
}
