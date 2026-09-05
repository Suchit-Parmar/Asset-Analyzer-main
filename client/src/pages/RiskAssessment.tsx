import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Activity, AlertTriangle, Loader2, Shield } from "lucide-react";
import { CartesianGrid, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis } from "recharts";
import { useAlerts, useNetworkNodes, useRiskScores } from "@/hooks/useApi";
import { useWebSocketSync } from "@/hooks/useWebSocketSync";
import { useMemo } from "react";

export default function RiskAssessment() {
  useWebSocketSync();
  const { data: nodesData, isLoading: nodesLoading } = useNetworkNodes();
  const { data: riskData } = useRiskScores();
  const { data: alertsData } = useAlerts(undefined, "open");

  const riskNodes = useMemo(() => {
    const nodes = nodesData?.nodes ?? [];
    const alerts = alertsData?.alerts ?? [];

    return nodes.map((node) => {
      const nodeAlerts = alerts.filter(
        (a) => a.sourceIp === node.ipAddress || a.targetIp === node.ipAddress,
      );
      const storedRisk = riskData?.scores?.find(
        (s) => s.entityId === node.id || s.entityName === node.ipAddress,
      );

      return {
        node: node.hostname || node.ipAddress,
        ip: node.ipAddress,
        risk: storedRisk?.nodeRisk ?? node.riskScore,
        anomalies: node.failedLogins ?? 0,
        alerts: nodeAlerts.length,
        status: node.status,
      };
    }).sort((a, b) => b.risk - a.risk);
  }, [nodesData, riskData, alertsData]);

  if (nodesLoading) {
    return (
      <div className="flex flex-1 items-center justify-center bg-background">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <main className="app-main flex-1 overflow-auto p-4 md:p-6 space-y-6">
        <div className="page-header">
          <div className="page-kicker">Risk Intelligence</div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2">Network Risk Radar</h1>
          <p className="text-muted-foreground font-mono text-sm max-w-2xl">
            Risk scores from PostgreSQL network nodes and TGNN risk engine computations,
            cross-referenced with open SOC alerts.
          </p>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            {
              label: "Avg Node Risk",
              value: riskNodes.length
                ? riskNodes.reduce((s, n) => s + n.risk, 0) / riskNodes.length
                : 0,
            },
            {
              label: "Stored Risk Rows",
              value: riskData?.scores?.length ?? 0,
              raw: true,
            },
            {
              label: "Open Alert Nodes",
              value: riskNodes.filter((n) => n.alerts > 0).length,
              raw: true,
            },
            {
              label: "High Risk (>70%)",
              value: riskNodes.filter((n) => n.risk > 0.7).length,
              raw: true,
            },
          ].map((card) => (
            <Card key={card.label} className="panel-card">
              <CardContent className="p-4">
                <div className="text-[11px] uppercase tracking-[0.14em] text-muted-foreground">{card.label}</div>
                <div className="mt-2 text-2xl font-mono font-bold text-primary">
                  {"raw" in card && card.raw ? card.value : `${Math.round(Number(card.value) * 100)}%`}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        <Card className="panel-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle size={18} className="text-primary" />
              Network Nodes Risk Matrix
            </CardTitle>
          </CardHeader>
          <CardContent>
            {riskNodes.length === 0 ? (
              <p className="text-muted-foreground font-mono text-sm">
                No network nodes in database. Start the AI service so network sync can populate topology from CICIDS2017.
              </p>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {riskNodes.map((node) => {
                  const riskColor = node.risk > 0.85 ? "bg-red-500/10 border-red-500/50" :
                    node.risk > 0.7 ? "bg-yellow-500/10 border-yellow-500/50" :
                      node.risk > 0.5 ? "bg-orange-500/10 border-orange-500/50" :
                        "bg-green-500/10 border-green-500/50";

                  const textColor = node.risk > 0.85 ? "text-red-400" :
                    node.risk > 0.7 ? "text-yellow-400" :
                      node.risk > 0.5 ? "text-orange-400" :
                        "text-green-400";

                  return (
                    <div key={node.ip} className={`p-4 rounded-2xl border ${riskColor}`}>
                      <div className="flex justify-between items-start mb-3">
                        <div>
                          <div className="font-mono font-bold text-foreground mb-1">{node.node}</div>
                          <div className="text-xs text-muted-foreground">
                            Anomalies: {node.anomalies} | Alerts: {node.alerts} | Status: {node.status}
                          </div>
                        </div>
                        <div className={`text-2xl font-bold font-mono ${textColor}`}>{Math.round(node.risk * 100)}%</div>
                      </div>
                      <div className="w-full bg-background/50 rounded-full h-2 overflow-hidden">
                        <div
                          className={`h-full transition-all ${
                            node.risk > 0.85 ? "bg-red-500" :
                            node.risk > 0.7 ? "bg-yellow-500" :
                            node.risk > 0.5 ? "bg-orange-500" :
                            "bg-green-500"
                          }`}
                          style={{ width: `${node.risk * 100}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="panel-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity size={18} className="text-primary" />
              Risk Score vs Anomaly Count
            </CardTitle>
          </CardHeader>
          <CardContent className="h-80">
            {riskNodes.length === 0 ? (
              <p className="text-muted-foreground font-mono text-sm">No data for scatter plot.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <ScatterChart margin={{ top: 20, right: 20, bottom: 60, left: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                  <XAxis dataKey="anomalies" stroke="#666" label={{ value: "Anomaly Count", position: "bottom", offset: 40 }} />
                  <YAxis dataKey="risk" stroke="#666" label={{ value: "Risk Score", angle: -90, position: "insideLeft" }} domain={[0, 1]} />
                  <Tooltip contentStyle={{ backgroundColor: "#111", borderColor: "#333" }} cursor={{ strokeDasharray: "3 3" }} />
                  <Scatter name="Nodes" data={riskNodes} fill="hsl(190, 90%, 50%)" shape="circle" isAnimationActive={true} />
                </ScatterChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card className="panel-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield size={18} className="text-primary" />
              SOC Action Items - Prioritized by Risk
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {riskNodes.slice(0, 4).map((node, index) => (
              <div key={node.ip} className="panel-subtle p-4 font-mono text-sm">
                <div className="flex justify-between items-center mb-2">
                  <span className="text-foreground font-bold">{index + 1}. {node.node}</span>
                  <span className="text-primary font-bold">{Math.round(node.risk * 100)}% Risk</span>
                </div>
                <div className="text-xs text-muted-foreground mb-2">
                  {node.alerts} active alerts | {node.anomalies} anomalies detected
                </div>
                <div className="flex gap-2">
                  <span className={`px-2 py-1 rounded text-xs font-bold ${
                    node.risk > 0.7 ? "bg-red-500/20 text-red-300" : "bg-yellow-500/20 text-yellow-300"
                  }`}>
                    {node.risk > 0.7 ? "HIGH PRIORITY" : "MEDIUM PRIORITY"}
                  </span>
                  {node.alerts > 0 && (
                    <span className="px-2 py-1 bg-blue-500/20 text-blue-300 rounded text-xs">Needs Immediate Investigation</span>
                  )}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </main>
  );
}
