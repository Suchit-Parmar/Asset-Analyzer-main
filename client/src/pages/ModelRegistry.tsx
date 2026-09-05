import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/states";
import {
  Boxes,
  CheckCircle2,
  Download,
  Loader2,
  Play,
  Trash2,
  Cpu,
  Clock,
} from "lucide-react";
import { useModelRegistry, useActivateModel, useDeleteModel } from "@/hooks/useApi";
import { api, type RegistryModel } from "@/lib/api";
import { toast } from "@/hooks/use-toast";

const DATASET_LABELS: Record<string, string> = {
  cicids2017: "CICIDS2017",
  unsw_nb15: "UNSW-NB15",
  cse_cic_ids2018: "CSE-CIC-IDS2018",
};

const STRATEGY_LABELS: Record<string, string> = {
  endpoint: "Endpoint Graph",
  flow: "Flow Graph",
  similarity: "Feature Similarity",
  temporal: "Temporal Sliding Window",
};

function fmtPct(v?: number): string {
  if (v == null || Number.isNaN(v)) return "—";
  return `${(v * 100).toFixed(1)}%`;
}

function fmtBytes(v?: number): string {
  if (!v) return "—";
  if (v > 1024 * 1024) return `${(v / (1024 * 1024)).toFixed(1)} MB`;
  return `${(v / 1024).toFixed(0)} KB`;
}

export default function ModelRegistry() {
  const { data, isLoading, refetch } = useModelRegistry();
  const activate = useActivateModel();
  const del = useDeleteModel();

  const models = data?.models ?? [];

  async function handleActivate(m: RegistryModel) {
    try {
      await activate.mutateAsync(m.id);
      toast({ title: "Model activated", description: `${m.name ?? m.id} is now the active model.` });
    } catch (err) {
      toast({
        title: "Activation failed",
        description: err instanceof Error ? err.message : "Unknown error",
        variant: "destructive",
      });
    }
  }

  async function handleDelete(m: RegistryModel) {
    if (!window.confirm(`Delete checkpoint "${m.id}"? This removes the .pt file from disk.`)) return;
    try {
      const res = await del.mutateAsync(m.id);
      toast({
        title: "Model deleted",
        description: (res as { note?: string }).note ?? `${m.id} removed.`,
      });
    } catch (err) {
      toast({
        title: "Delete failed",
        description: err instanceof Error ? err.message : "Unknown error",
        variant: "destructive",
      });
    }
  }

  async function handleExport(m: RegistryModel) {
    try {
      const meta = await api.exportModelMetadata(m.id);
      const blob = new Blob([JSON.stringify(meta, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${m.id}.metadata.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast({ title: "Metadata exported", description: `${m.id}.metadata.json downloaded.` });
    } catch (err) {
      toast({
        title: "Export failed",
        description: err instanceof Error ? err.message : "Unknown error",
        variant: "destructive",
      });
    }
  }

  return (
    <main className="flex-1 overflow-auto p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-2">
              <Boxes className="h-7 w-7 text-primary" /> Model Registry
            </h1>
            <p className="text-muted-foreground mt-1">
              Trained checkpoints on disk — activate, export or remove any model.
            </p>
          </div>
          <Button size="sm" variant="outline" onClick={() => refetch()}>
            Refresh
          </Button>
        </div>

        {isLoading ? (
          <div className="flex items-center gap-2 text-muted-foreground">
            <Loader2 className="h-5 w-5 animate-spin" /> Loading registry…
          </div>
        ) : models.length === 0 ? (
          <EmptyState
            title="No trained models yet"
            message="Train a model in Model Studio to populate the registry."
          />
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {models.map((m) => (
              <Card key={m.id} className={`panel-card ${m.is_active ? "ring-1 ring-primary/50" : ""}`}>
                <CardHeader className="flex flex-row items-start justify-between pb-2">
                  <div>
                    <CardTitle className="flex items-center gap-2 text-lg">
                      <Cpu className="h-4 w-4 text-primary" />
                      {DATASET_LABELS[m.dataset_id ?? ""] ?? m.name ?? m.id}
                    </CardTitle>
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs">
                      <Badge variant="outline">{(m.architecture ?? "gat").toUpperCase()}</Badge>
                      <Badge variant="outline">
                        {STRATEGY_LABELS[m.graph_strategy ?? ""] ?? m.graph_strategy ?? "—"}
                      </Badge>
                      {m.is_active && (
                        <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30">
                          <CheckCircle2 className="h-3 w-3 mr-1" /> Active
                        </Badge>
                      )}
                    </div>
                  </div>
                  <div className="text-right text-xs text-muted-foreground">
                    <div>{fmtBytes(m.size_bytes)}</div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
                    <Metric label="Test Acc" value={fmtPct(m.metrics?.test_accuracy ?? m.metrics?.accuracy)} />
                    <Metric label="Test F1" value={fmtPct(m.metrics?.test_f1 ?? m.metrics?.f1)} />
                    <Metric label="Macro F1" value={fmtPct(m.metrics?.macro_f1)} />
                    <Metric label="ROC-AUC" value={fmtPct(m.metrics?.roc_auc)} />
                  </div>

                  <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {m.trained_at ? new Date(m.trained_at).toLocaleString() : "—"}
                    </span>
                    {m.metrics?.graph_stats?.num_snapshots != null && (
                      <span>
                        {m.metrics.graph_stats.num_snapshots} snapshots · avg{" "}
                        {m.metrics.graph_stats.avg_nodes} nodes / {m.metrics.graph_stats.avg_edges} edges
                      </span>
                    )}
                    {m.metrics?.training_time_sec != null && (
                      <span>train {m.metrics.training_time_sec}s</span>
                    )}
                  </div>

                  <div className="flex items-center gap-2 pt-1">
                    <Button
                      size="sm"
                      onClick={() => handleActivate(m)}
                      disabled={m.is_active || activate.isPending}
                    >
                      {activate.isPending && activate.variables === m.id ? (
                        <Loader2 className="h-4 w-4 mr-1 animate-spin" />
                      ) : (
                        <Play className="h-4 w-4 mr-1" />
                      )}
                      {m.is_active ? "Active" : "Activate"}
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => handleExport(m)}>
                      <Download className="h-4 w-4 mr-1" /> Export
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-red-400 hover:text-red-300"
                      onClick={() => handleDelete(m)}
                      disabled={del.isPending}
                    >
                      <Trash2 className="h-4 w-4 mr-1" /> Delete
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </main>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="panel-subtle rounded-lg p-2">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="font-mono text-sm text-cyan-200">{value}</div>
    </div>
  );
}
