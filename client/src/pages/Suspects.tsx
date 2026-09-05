import { useMemo, useState } from "react";
import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { EmptyState, PageLoader } from "@/components/states";
import { TrafficModeBadge } from "@/components/TrafficModeBadge";
import { useAlerts, useNetworkNodes, usePredictions, useTopology } from "@/hooks/useApi";
import {
  attackDisplayName,
  deviceCategory,
  deviceCategoryLabel,
  plainLanguageReasons,
  riskLevel,
  riskLevelClass,
  riskScore100,
} from "@/lib/cyber-display";
import { cn } from "@/lib/utils";
import { AlertTriangle, Crosshair, Search, ShieldAlert } from "lucide-react";

export default function Suspects() {
  const { data: nodesData, isLoading: nodesLoading } = useNetworkNodes(undefined, true);
  const { data: predictionsData } = usePredictions();
  const { data: alertsData } = useAlerts();
  const { data: topology } = useTopology();
  const [query, setQuery] = useState("");

  const predictions = predictionsData?.predictions ?? [];
  const alerts = alertsData?.alerts ?? [];
  const latestPrediction = predictions[0];

  const suspects = useMemo(() => {
    const nodes = nodesData?.nodes ?? [];
    const fromDb = nodes
      .filter((n) => {
        const score = riskScore100(n.riskScore);
        return score >= 30 || n.status === "suspicious" || n.status === "compromised";
      })
      .map((n) => {
        const score = riskScore100(n.riskScore);
        const relatedAlert = alerts.find(
          (a) => a.sourceIp === n.ipAddress || a.targetIp === n.ipAddress,
        );
        const reasoning =
          typeof latestPrediction?.explanation === "object" && latestPrediction.explanation
            ? String((latestPrediction.explanation as { reasoning?: string }).reasoning ?? "")
            : "";
        return {
          id: n.id,
          ip: n.ipAddress,
          name: n.hostname || n.ipAddress,
          type: n.nodeType,
          vendor: n.vendor,
          status: n.status,
          score,
          level: riskLevel(score),
          packets: n.packets,
          connectionCount: n.connectionCount,
          failedLogins: n.failedLogins,
          lastSeen: n.lastSeenAt,
          attackType: relatedAlert?.attackType ?? latestPrediction?.attackType ?? null,
          confidence: latestPrediction?.confidence ?? null,
          threatLevel: relatedAlert?.severity ?? latestPrediction?.threatLevel ?? null,
          reasons: plainLanguageReasons({
            risk100: score,
            attackType: relatedAlert?.attackType ?? latestPrediction?.attackType,
            threatLevel: relatedAlert?.severity ?? latestPrediction?.threatLevel,
            packets: n.packets,
            connectionCount: n.connectionCount,
            failedLogins: n.failedLogins,
            reasoning,
            status: n.status,
          }),
        };
      })
      .sort((a, b) => b.score - a.score);

    if (fromDb.length) return fromDb;

    // Fallback: topology high-risk nodes when DB filter is empty
    return (topology?.nodes ?? [])
      .filter((n) => riskScore100(n.risk) >= 30 || n.status !== "online")
      .map((n) => {
        const score = riskScore100(n.risk);
        return {
          id: n.id,
          ip: n.ip,
          name: n.label,
          type: n.type,
          vendor: null as string | null,
          status: n.status,
          score,
          level: riskLevel(score),
          packets: null as number | null,
          connectionCount: null as number | null,
          failedLogins: null as number | null,
          lastSeen: null as string | null,
          attackType: latestPrediction?.attackType ?? null,
          confidence: latestPrediction?.confidence ?? null,
          threatLevel: latestPrediction?.threatLevel ?? null,
          reasons: plainLanguageReasons({
            risk100: score,
            attackType: latestPrediction?.attackType,
            status: n.status,
          }),
        };
      })
      .sort((a, b) => b.score - a.score);
  }, [nodesData, alerts, latestPrediction, topology]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return suspects;
    return suspects.filter(
      (s) =>
        s.ip.toLowerCase().includes(q) ||
        s.name.toLowerCase().includes(q) ||
        (s.attackType ?? "").toLowerCase().includes(q),
    );
  }, [suspects, query]);

  if (nodesLoading) {
    return <PageLoader label="Loading potential suspects…" />;
  }

  return (
    <main className="flex-1 overflow-auto p-4 md:p-6 space-y-6">
        <header className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="text-[11px] uppercase tracking-[0.18em] text-muted-foreground mb-2">
              Threat Triage
            </div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-2">
              <ShieldAlert className="h-7 w-7 text-orange-400" />
              Potential Suspects
            </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
              Devices the GNN and risk engine flag as unusual. Explanations use plain language for
              demo and viva review.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <TrafficModeBadge mode="live" />
            <div className="relative min-w-[220px]">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                className="pl-8"
                placeholder="Search IP / hostname…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
          </div>
        </header>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Stat label="Suspects" value={String(suspects.length)} />
          <Stat
            label="Critical"
            value={String(suspects.filter((s) => s.level === "Critical").length)}
            accent="text-red-400"
          />
          <Stat
            label="High"
            value={String(suspects.filter((s) => s.level === "High").length)}
            accent="text-orange-400"
          />
          <Stat label="Open alerts" value={String(alerts.filter((a) => a.status === "open").length)} />
        </div>

        {filtered.length === 0 ? (
          <EmptyState
            title="No suspects in the current window"
            message="Run dataset replay from Mission Control or wait for elevated risk scores."
          />
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {filtered.map((s) => (
              <Card key={s.id} className="panel-card border-border/60">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base flex items-start justify-between gap-3">
                    <span className="flex items-center gap-2">
                      <Crosshair className="h-4 w-4 text-orange-400 shrink-0" />
                      <span>
                        <span className="block font-mono text-white">{s.ip}</span>
                        <span className="block text-xs font-normal text-muted-foreground mt-0.5">
                          {s.name} · {deviceCategoryLabel(deviceCategory(s.type, s.vendor))}
                        </span>
                      </span>
                    </span>
                    <Badge className={cn("border", riskLevelClass(s.level))}>
                      {s.score}/100 · {s.level.toUpperCase()}
                    </Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3 text-sm">
                  <div className="flex flex-wrap gap-2 text-xs font-mono text-muted-foreground">
                    {s.attackType && (
                      <span>Attack: {attackDisplayName(s.attackType)}</span>
                    )}
                    {s.confidence != null && (
                      <span>Confidence: {Math.round(s.confidence * 100)}%</span>
                    )}
                    {s.threatLevel && <span>Threat: {s.threatLevel}</span>}
                    {s.lastSeen && (
                      <span>Last seen: {new Date(s.lastSeen).toLocaleString()}</span>
                    )}
                  </div>

                  <div>
                    <div className="text-xs uppercase tracking-wider text-muted-foreground mb-1.5 flex items-center gap-1">
                      <AlertTriangle className="h-3 w-3" /> Why suspicious?
                    </div>
                    <ul className="space-y-1">
                      {s.reasons.map((r) => (
                        <li key={r} className="text-sm text-foreground/90 flex gap-2">
                          <span className="text-cyan-400">•</span>
                          <span>{r}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="flex gap-2 pt-1">
                    <Button size="sm" variant="outline" asChild>
                      <Link href="/network">View on graph</Link>
                    </Button>
                    <Button size="sm" variant="outline" asChild>
                      <Link href="/explainability">Explainability</Link>
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

function Stat({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent?: string;
}) {
  return (
    <Card className="panel-card">
      <CardContent className="pt-4">
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
        <div className={cn("mt-1 text-2xl font-bold", accent ?? "text-white")}>{value}</div>
      </CardContent>
    </Card>
  );
}
