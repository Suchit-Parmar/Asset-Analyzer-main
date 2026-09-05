import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, Loader2, TrendingUp, Zap } from "lucide-react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useAttackStages, usePredictions, useAlerts } from "@/hooks/useApi";
import { useWebSocketSync } from "@/hooks/useWebSocketSync";

export default function AttackIntelligence() {
  useWebSocketSync();
  const { data, isLoading, isError } = useAttackStages();
  const { data: predictionsData } = usePredictions();
  const { data: alertsData } = useAlerts();

  const attackStages = data?.attackStages ?? [];
  const edges = data?.edges ?? [];
  const stats = data?.stats;
  const leadStage = stats?.leadStage ?? attackStages[0];
  const predictions = predictionsData?.predictions ?? [];
  const latestPrediction = predictions[0];
  const mitreAlerts = (alertsData?.alerts ?? []).filter((a) => a.mitreTactic || a.mitreTechnique);

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
          <div className="page-kicker">Threat Journey</div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2">Threat Journey Intelligence</h1>
          <p className="text-muted-foreground font-mono text-sm max-w-2xl">
            Attack progression is derived from live TGNN predictions stored in PostgreSQL, aggregated
            across the last 24 hours of inference activity.
          </p>
        </div>

        {isError && (
          <Card className="panel-card border-yellow-500/30">
            <CardContent className="p-4 text-sm text-yellow-300 font-mono">
              Attack stage data temporarily unavailable. Retrying automatically.
            </CardContent>
          </Card>
        )}

        <Card className="panel-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp size={18} className="text-primary" />
              Predicted Attack Journey
            </CardTitle>
          </CardHeader>
          <CardContent>
            {attackStages.length === 0 ? (
              <p className="text-muted-foreground font-mono text-sm">
                No attack stage predictions recorded yet. Run inference via POST /api/predict or sync network graph.
              </p>
            ) : (
              <>
                <div className="flex justify-between items-start gap-2 mb-6 overflow-x-auto">
                  {attackStages.slice(0, 8).map((stage, index) => (
                    <div key={stage.stageKey} className="flex-1 min-w-[100px] text-center">
                      <div
                        className={`relative mb-3 p-3 rounded border ${
                          stage.probability > 0.8
                            ? "bg-red-500/10 border-red-500/50"
                            : stage.probability > 0.5
                              ? "bg-yellow-500/10 border-yellow-500/50"
                              : "bg-green-500/10 border-green-500/50"
                        }`}
                      >
                        <div className="text-lg font-bold text-primary mb-1">{Math.round(stage.probability * 100)}%</div>
                        <div className="text-xs font-mono text-muted-foreground">{stage.stage}</div>

                        {index < Math.min(attackStages.length, 8) - 1 && (
                          <div className="absolute right-0 top-1/2 transform translate-x-1/2 -translate-y-1/2 hidden md:block">
                            <div className="w-8 h-0.5 bg-gradient-to-r from-yellow-500 to-red-500" />
                          </div>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground truncate">{stage.entities.join(", ") || "—"}</div>
                    </div>
                  ))}
                </div>

                <div className="mt-8 h-44">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={attackStages.map((stage) => ({ name: stage.stage.slice(0, 6), risk: Math.round(stage.probability * 100) }))}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                      <XAxis dataKey="name" stroke="#666" />
                      <YAxis stroke="#666" domain={[0, 100]} />
                      <Tooltip contentStyle={{ backgroundColor: "#111", borderColor: "#333" }} />
                      <Line type="monotone" dataKey="risk" stroke="hsl(190, 90%, 50%)" strokeWidth={3} dot={{ fill: "hsl(190, 90%, 50%)", r: 4 }} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        <Card className="panel-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap size={18} className="text-primary" />
              Attack Path Intelligence
            </CardTitle>
          </CardHeader>
          <CardContent>
            {edges.length === 0 ? (
              <p className="text-muted-foreground font-mono text-sm">No network edges synced. Ensure the AI service is running so topology can sync from CICIDS2017.</p>
            ) : (
              <div className="space-y-3">
                {edges.slice(0, 12).map((edge) => (
                  <div key={`${edge.source}-${edge.target}-${edge.timestamp}`} className="p-4 rounded border border-border/50 bg-black/20 font-mono text-xs">
                    <div className="flex justify-between items-start mb-2">
                      <div className="flex-1">
                        <div className="text-foreground mb-1">
                          <span className="text-blue-400">{edge.source}</span>
                          <span className="text-muted-foreground mx-2">→</span>
                          <span className="text-blue-400">{edge.target}</span>
                        </div>
                        <div className="text-muted-foreground text-xs">
                          {edge.type} | Weight: {edge.weight.toFixed(2)} | {new Date(edge.timestamp).toLocaleTimeString()}
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="h-6 w-12 bg-gradient-to-r from-primary/20 to-primary/50 rounded flex items-center justify-center">
                          <span className="text-primary font-bold">{Math.round(edge.weight * 100)}%</span>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="panel-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap size={18} className="text-primary" />
              Recent Predictions · Confidence
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {predictions.slice(0, 8).map((pred) => (
              <div key={pred.id} className="flex items-center justify-between gap-3 rounded border border-border/50 bg-black/20 p-3 font-mono text-xs">
                <div>
                  <div className="text-foreground">{pred.attackType} · {pred.attackStage}</div>
                  <div className="text-muted-foreground">
                    Next: {pred.predictedNextStage ?? "—"} · {new Date(pred.createdAt).toLocaleString()}
                  </div>
                </div>
                <div className="text-right space-y-1">
                  <Badge variant="outline">{pred.threatLevel}</Badge>
                  <div className="text-emerald-300">{Math.round(pred.confidence * 100)}% conf</div>
                </div>
              </div>
            ))}
            {!predictions.length && (
              <p className="text-sm text-muted-foreground">No predictions yet. Run dataset predict from the Dashboard.</p>
            )}
          </CardContent>
        </Card>

        <Card className="panel-card">
          <CardHeader>
            <CardTitle>MITRE ATT&CK Mapping</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {mitreAlerts.slice(0, 10).map((alert) => (
              <div key={alert.id} className="rounded border border-border/50 p-3 text-sm">
                <div className="font-medium text-foreground">{alert.title}</div>
                <div className="mt-1 font-mono text-xs text-cyan-300">
                  {alert.mitreTactic ?? "—"} / {alert.mitreTechnique ?? "—"}
                </div>
                <div className="mt-1 text-xs text-muted-foreground">
                  {alert.attackType} · {alert.attackStage} · {alert.severity}
                </div>
              </div>
            ))}
            {!mitreAlerts.length && (
              <p className="text-sm text-muted-foreground">
                MITRE mappings appear when TGNN predictions create non-low alerts (medium+ threat).
              </p>
            )}
          </CardContent>
        </Card>

        <Card className="panel-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle size={18} className="text-destructive" />
              Key Findings
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 font-mono text-sm text-muted-foreground">
            <div className="p-3 rounded bg-red-500/5 border border-red-500/20 text-red-300">
              <div className="font-bold mb-1">CRITICAL: {leadStage?.stage ?? "Awaiting data"} is the lead stage</div>
              {leadStage?.description ?? "Stage signal unavailable."}
              {latestPrediction && ` Latest TGNN prediction: ${latestPrediction.attackType} (${Math.round(latestPrediction.confidence * 100)}% confidence).`}
            </div>
            <div className="p-3 rounded bg-yellow-500/5 border border-yellow-500/20 text-yellow-300">
              <div className="font-bold mb-1">WARNING: Hostile share in prediction stream</div>
              {Math.round((stats?.maliciousShare ?? 0) * 100)}% of recent predictions ({stats?.totalPredictions ?? 0} total) are classified as malicious or elevated threat.
            </div>
            <div className="p-3 rounded bg-blue-500/5 border border-blue-500/20 text-blue-300">
              <div className="font-bold mb-1">INFO: Multi-stage attack graph active</div>
              TGNN is tracking transitions across {stats?.stageCount ?? 0} modeled attack phases with {Math.round((stats?.avgConfidence ?? 0) * 100)}% average confidence.
            </div>
          </CardContent>
        </Card>
      </main>
  );
}
