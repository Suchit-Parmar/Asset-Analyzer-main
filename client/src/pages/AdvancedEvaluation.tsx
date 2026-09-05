import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Zap, BarChart3, TrendingDown, Gauge, Loader2 } from "lucide-react";
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
import { useMetrics, usePredictions, useTrainingRuns } from "@/hooks/useApi";
import { useWebSocketSync } from "@/hooks/useWebSocketSync";
import { useMemo } from "react";

export default function AdvancedEvaluation() {
  useWebSocketSync();
  const { data: metricsData, isLoading } = useMetrics();
  const { data: trainingData } = useTrainingRuns();
  const { data: predictionsData } = usePredictions();

  const raw = metricsData?.metrics as Record<string, unknown> | undefined;
  const headline = metricsData?.headline ?? {};
  const h = headline as Record<string, unknown>;
  const r = raw ?? {};

  const accuracy = (h.accuracy ?? r.accuracy ?? trainingData?.runs?.[0]?.valAccuracy) as number | undefined;
  const f1 = (h.f1 ?? r.f1) as number | undefined;
  const rocAuc = (h.roc_auc ?? r.roc_auc) as number | undefined;
  const macroF1 = (h.macro_f1 ?? r.macro_f1 ?? metricsData?.macro?.f1) as number | undefined;

  const learningCurve = metricsData?.learning_curve
    ?? (raw?.history as Array<Record<string, number>> | undefined)
    ?? [];

  const trainingTimeline = learningCurve.map((row) => ({
    time: `E${row.epoch ?? "?"}`,
    val_accuracy: row.val_accuracy ?? 0,
    precision: row.precision ?? 0,
    recall: row.recall ?? 0,
    f1: row.f1 ?? 0,
    train_loss: row.train_loss ?? 0,
    val_loss: row.val_loss ?? 0,
  }));

  const classDist = metricsData?.class_distribution
    ?? (raw?.class_distribution as Array<{ class: string; count: number }> | undefined)
    ?? [];

  const perClassFatigue = useMemo(() => {
    const pc = metricsData?.per_class ?? (raw?.per_class as Record<string, { f1?: number; support?: number }> | undefined) ?? {};
    return Object.entries(pc).map(([cls, vals]) => ({
      class: cls,
      f1: vals.f1 ?? 0,
      support: vals.support ?? 0,
      falsePositiveRate: Math.max(0, 1 - (vals.f1 ?? 0)),
    }));
  }, [metricsData?.per_class, raw?.per_class]);

  const predictionConfidence = useMemo(() => {
    const preds = predictionsData?.predictions ?? [];
    if (!preds.length) return [];
    return [...preds].reverse().slice(0, 12).map((p) => ({
      time: new Date(p.createdAt).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }),
      confidence: Math.round(p.confidence * 100),
      risk: Math.round(p.riskScore * 100),
    }));
  }, [predictionsData]);

  const avgConfidence = predictionsData?.predictions?.length
    ? predictionsData.predictions.reduce((s, p) => s + p.confidence, 0) / predictionsData.predictions.length
    : accuracy ?? 0;

  if (isLoading) {
    return (
      <div className="flex flex-1 items-center justify-center bg-background">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <main className="app-main flex-1 overflow-auto p-4 md:p-6 space-y-6">
        <div className="page-header">
          <div className="page-kicker">Advanced Metrics</div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2">Advanced Evaluation Metrics</h1>
          <p className="text-muted-foreground font-mono text-sm max-w-2xl">
            Deep analytics from checkpoint evaluation (ROC-AUC, macro F1, per-class breakdown),
            training epoch history, and live prediction confidence.
          </p>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card className="metric-surface rounded-[1.35rem]">
            <CardContent className="p-4">
              <div className="text-xs text-muted-foreground mb-1">Val Accuracy</div>
              <div className="text-2xl font-bold text-primary">{accuracy != null ? `${(accuracy * 100).toFixed(1)}%` : "—"}</div>
              <div className="text-xs text-muted-foreground">F1: {f1 != null ? f1.toFixed(3) : "—"}</div>
            </CardContent>
          </Card>
          <Card className="metric-surface rounded-[1.35rem]">
            <CardContent className="p-4">
              <div className="text-xs text-muted-foreground mb-1">ROC-AUC</div>
              <div className="text-2xl font-bold text-primary">{rocAuc != null ? rocAuc.toFixed(3) : "—"}</div>
              <div className="text-xs text-muted-foreground">Macro F1: {macroF1 != null ? macroF1.toFixed(3) : "—"}</div>
            </CardContent>
          </Card>
          <Card className="metric-surface rounded-[1.35rem]">
            <CardContent className="p-4">
              <div className="text-xs text-muted-foreground mb-1">Live Confidence</div>
              <div className="text-2xl font-bold text-primary">{Math.round(avgConfidence * 100)}%</div>
              <div className="text-xs text-muted-foreground">{predictionsData?.predictions?.length ?? 0} predictions</div>
            </CardContent>
          </Card>
          <Card className="metric-surface rounded-[1.35rem]">
            <CardContent className="p-4">
              <div className="text-xs text-muted-foreground mb-1">Inference Speed</div>
              <div className="text-2xl font-bold text-green-400">
                {metricsData?.inference_time_ms != null ? `${metricsData.inference_time_ms} ms` : "—"}
              </div>
              <div className="text-xs text-muted-foreground">
                Model: {metricsData?.model_size_mb != null ? `${metricsData.model_size_mb} MB` : "—"}
              </div>
            </CardContent>
          </Card>
        </div>

        <Card className="panel-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap size={18} className="text-primary" />
              Class Support Distribution
            </CardTitle>
          </CardHeader>
          <CardContent className="h-80">
            {classDist.length === 0 ? (
              <p className="text-muted-foreground font-mono text-sm">Retrain the model to populate class distribution from the test split.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={classDist}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                  <XAxis dataKey="class" stroke="#666" angle={-30} textAnchor="end" height={70} tick={{ fontSize: 11 }} />
                  <YAxis stroke="#666" />
                  <Tooltip contentStyle={{ backgroundColor: "#111", borderColor: "#333" }} />
                  <Bar dataKey="count" fill="hsl(190, 90%, 50%)" name="Test support" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card className="panel-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingDown size={18} className="text-primary" />
              Per-Class F1 &amp; Error Rate
            </CardTitle>
          </CardHeader>
          <CardContent className="h-80">
            {perClassFatigue.length === 0 ? (
              <p className="text-muted-foreground font-mono text-sm">No per-class evaluation data.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={perClassFatigue} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" horizontal={false} />
                  <XAxis type="number" domain={[0, 1]} stroke="#666" />
                  <YAxis dataKey="class" type="category" width={100} stroke="#999" tick={{ fontSize: 11 }} />
                  <Tooltip contentStyle={{ backgroundColor: "#111", borderColor: "#333" }} />
                  <Legend />
                  <Bar dataKey="f1" fill="#22c55e" name="F1" radius={[0, 4, 4, 0]} barSize={14} />
                  <Bar dataKey="falsePositiveRate" fill="hsl(0, 80%, 60%)" name="Error rate (1−F1)" radius={[0, 4, 4, 0]} barSize={14} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card className="panel-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BarChart3 size={18} className="text-primary" />
              Training Epoch History
            </CardTitle>
          </CardHeader>
          <CardContent className="h-80">
            {trainingTimeline.length === 0 ? (
              <p className="text-muted-foreground font-mono text-sm">
                No training history. Start a training run from Model Studio.
              </p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trainingTimeline}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                  <XAxis dataKey="time" stroke="#666" minTickGap={24} />
                  <YAxis stroke="#666" domain={[0, 1]} />
                  <Tooltip contentStyle={{ backgroundColor: "#111", borderColor: "#333" }} />
                  <Legend />
                  <Line type="monotone" dataKey="val_accuracy" stroke="hsl(190, 90%, 50%)" strokeWidth={2} dot={false} name="Val Accuracy" />
                  <Line type="monotone" dataKey="precision" stroke="#f59e0b" strokeWidth={2} dot={false} name="Precision" />
                  <Line type="monotone" dataKey="recall" stroke="#22c55e" strokeWidth={2} dot={false} name="Recall" />
                  <Line type="monotone" dataKey="f1" stroke="#a78bfa" strokeWidth={2} dot={false} name="F1" />
                </LineChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card className="panel-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Gauge size={18} className="text-primary" />
              Live Prediction Confidence Stream
            </CardTitle>
          </CardHeader>
          <CardContent className="h-72">
            {predictionConfidence.length === 0 ? (
              <p className="text-muted-foreground font-mono text-sm">Run dataset inference to populate live confidence data.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={predictionConfidence}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                  <XAxis dataKey="time" stroke="#666" />
                  <YAxis domain={[0, 100]} stroke="#666" />
                  <Tooltip contentStyle={{ backgroundColor: "#111", borderColor: "#333" }} />
                  <Legend />
                  <Line type="monotone" dataKey="confidence" stroke="#06b6d4" strokeWidth={2} dot={{ r: 3 }} name="Confidence %" />
                  <Line type="monotone" dataKey="risk" stroke="#ef4444" strokeWidth={2} dot={false} name="Risk %" />
                </LineChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </main>
  );
}
