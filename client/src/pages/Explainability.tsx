import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Brain, Eye, AlertTriangle, Loader2, GitBranch, Flame } from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useLatestExplanation } from "@/hooks/useApi";
import { useWebSocketSync } from "@/hooks/useWebSocketSync";
import type { ExplainabilityResult } from "@/lib/api";

function ReasoningTreeNode({ node, depth = 0 }: { node: NonNullable<ExplainabilityResult["reasoning_tree"]>[number]; depth?: number }) {
  return (
    <div className={depth > 0 ? "ml-4 border-l border-primary/20 pl-3" : ""}>
      <div className="py-1">
        <div className="font-mono text-sm text-foreground">{node.label}</div>
        {node.detail && <div className="text-xs text-muted-foreground">{node.detail}</div>}
      </div>
      {(node.children ?? []).map((child) => (
        <ReasoningTreeNode key={child.id} node={child} depth={depth + 1} />
      ))}
    </div>
  );
}

export default function Explainability() {
  useWebSocketSync();
  const { data: explanation, isLoading, isError } = useLatestExplanation();

  const nodeWeights = (explanation?.node_importance ?? []).map((node) => ({
    name: (node.label ?? node.ip ?? node.entity ?? `Node ${node.node_index ?? 0}`).slice(0, 16),
    weight: node.importance,
    entity: node.label ?? node.ip ?? node.entity ?? "Unknown",
    type: "host",
    role: node.importance > 0.7 ? "critical" : node.importance > 0.4 ? "suspicious" : "peripheral",
  }));

  const igChart = (explanation?.integrated_gradients ?? []).slice(0, 10).map((f) => ({
    name: f.feature.slice(0, 12),
    score: Math.abs(f.importance),
  }));

  const shapChart = (explanation?.shap_values ?? []).slice(0, 8).map((f) => ({
    name: f.feature.slice(0, 12),
    score: Math.abs(f.shap_value),
  }));

  const heatmapNodes = explanation?.graph_heatmap?.nodes ?? [];
  const reasoning = explanation?.reasoning ?? "Explainability data will appear once TGNN inference runs against the synced network graph.";
  const reasoningTree = explanation?.reasoning_tree ?? [];

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
          <div className="page-kicker">Model Explainability</div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2">Model Explainability</h1>
          <p className="text-muted-foreground font-mono text-sm max-w-2xl">
            GAT attention weights, integrated gradients, SHAP approximations, reasoning tree, and graph heatmap
            from the TGNN explainability service for the highest-risk node in the live topology.
          </p>
        </div>

        {isError && (
          <Card className="panel-card border-yellow-500/30">
            <CardContent className="p-4 text-sm text-yellow-300 font-mono">
              Explainability service unavailable. Ensure the AI backend is running and a model checkpoint exists.
            </CardContent>
          </Card>
        )}

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <Card className="panel-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Eye size={18} className="text-primary" />
                Integrated Gradients (Feature Attribution)
              </CardTitle>
            </CardHeader>
            <CardContent>
              {igChart.length === 0 ? (
                <p className="text-muted-foreground font-mono text-sm">No IG scores yet.</p>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={igChart}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                      <XAxis dataKey="name" stroke="#666" angle={-35} textAnchor="end" height={70} fontSize={11} />
                      <YAxis stroke="#666" />
                      <Tooltip contentStyle={{ backgroundColor: "#111", borderColor: "#333" }} />
                      <Bar dataKey="score" fill="#22d3ee" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="panel-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Brain size={18} className="text-primary" />
                SHAP Approximation (Perturbation)
              </CardTitle>
            </CardHeader>
            <CardContent>
              {shapChart.length === 0 ? (
                <p className="text-muted-foreground font-mono text-sm">No SHAP values yet.</p>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={shapChart}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                      <XAxis dataKey="name" stroke="#666" angle={-35} textAnchor="end" height={70} fontSize={11} />
                      <YAxis stroke="#666" />
                      <Tooltip contentStyle={{ backgroundColor: "#111", borderColor: "#333" }} />
                      <Bar dataKey="score" fill="#a78bfa" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <Card className="panel-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Eye size={18} className="text-primary" />
              Attention Weight Distribution: Important Entities
            </CardTitle>
          </CardHeader>
          <CardContent>
            {nodeWeights.length === 0 ? (
              <p className="text-muted-foreground font-mono text-sm">No node importance scores available.</p>
            ) : (
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={nodeWeights.map((w) => ({ name: w.name, weight: Math.round(w.weight * 100) }))}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                    <XAxis dataKey="name" stroke="#666" angle={-45} textAnchor="end" height={80} />
                    <YAxis stroke="#666" />
                    <Tooltip contentStyle={{ backgroundColor: "#111", borderColor: "#333" }} />
                    <Bar dataKey="weight" fill="hsl(190, 90%, 50%)" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <Card className="panel-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <GitBranch size={18} className="text-primary" />
                Reasoning Tree
              </CardTitle>
            </CardHeader>
            <CardContent>
              {reasoningTree.length === 0 ? (
                <p className="text-muted-foreground font-mono text-sm">Structured reasoning tree unavailable.</p>
              ) : (
                reasoningTree.map((node) => <ReasoningTreeNode key={node.id} node={node} />)
              )}
            </CardContent>
          </Card>

          <Card className="panel-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Flame size={18} className="text-destructive" />
                Graph Heatmap (Node Intensity)
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 max-h-80 overflow-auto">
              {heatmapNodes.length === 0 ? (
                <p className="text-muted-foreground font-mono text-sm">No heatmap data.</p>
              ) : (
                heatmapNodes.slice(0, 12).map((n) => (
                  <div key={n.id} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span>{n.label}</span>
                      <span className="text-primary">{(n.intensity * 100).toFixed(0)}%</span>
                    </div>
                    <div className="h-2 rounded-full bg-background/50 overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-amber-500/60 to-red-500"
                        style={{ width: `${Math.round(n.intensity * 100)}%` }}
                      />
                    </div>
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        </div>

        <Card className="panel-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle size={18} className="text-destructive" />
              Alert Reasoning for SOC Investigation
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="bg-black/50 p-6 rounded-lg border border-border/50 font-mono text-sm text-foreground whitespace-pre-wrap max-h-96 overflow-auto">
              {reasoning}
            </div>
            {explanation?.fallback && (
              <p className="text-xs text-yellow-400 mt-2 font-mono">Using stored prediction explanation (AI service fallback).</p>
            )}
          </CardContent>
        </Card>

        <Card className="panel-card">
          <CardHeader>
            <CardTitle>Critical Subgraph Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-black/30 rounded border border-primary/30">
                <div className="text-xs text-muted-foreground mb-2">NODES IN CRITICAL SUBGRAPH</div>
                <div className="space-y-2 font-mono text-sm">
                  {nodeWeights.slice(0, 4).map((node) => (
                    <div key={node.entity} className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full bg-primary" />
                      <span>{node.entity}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="p-4 bg-black/30 rounded border border-primary/30">
                <div className="text-xs text-muted-foreground mb-2">EDGES IN CRITICAL SUBGRAPH</div>
                <div className="space-y-2 font-mono text-sm">
                  {(explanation?.edge_importance ?? []).slice(0, 4).map((edge, i) => (
                    <div key={`${edge.source}-${edge.target}-${i}`} className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full bg-primary" />
                      <span>{edge.source ?? "?"} → {edge.target ?? "?"} ({edge.importance.toFixed(2)})</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </main>
  );
}
