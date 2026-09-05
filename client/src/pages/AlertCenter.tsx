import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  ShieldAlert,
  CheckCircle,
  Loader2,
  Shield,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAlerts, useUpdateAlert, useSocResponse } from "@/hooks/useApi";
import { useWebSocketSync } from "@/hooks/useWebSocketSync";
import { EmptyState } from "@/components/states";
import type { Alert, SocResponse } from "@/lib/api";

const STATUS_OPTIONS = ["open", "investigating", "resolved", "false_positive"] as const;

const SEVERITY_TONE: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  informational: "text-muted-foreground",
};

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      size="sm"
      variant="ghost"
      className="h-6 px-2 text-xs"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
    >
      {copied ? <Check className="h-3 w-3 mr-1" /> : <Copy className="h-3 w-3 mr-1" />}
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

function RuleBlock({ label, rule }: { label: string; rule: string }) {
  return (
    <div className="rounded-md border border-border bg-black/30">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-border">
        <span className="text-xs font-semibold uppercase tracking-wide text-cyan-300">{label}</span>
        <CopyButton text={rule} />
      </div>
      <pre className="p-3 text-xs font-mono text-muted-foreground whitespace-pre-wrap break-words max-h-56 overflow-auto">
        {rule}
      </pre>
    </div>
  );
}

function AlertSocResponse({ alert }: { alert: Alert }) {
  const [open, setOpen] = useState(false);
  const soc = useSocResponse();
  const data = soc.data as SocResponse | undefined;

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next && !soc.data && !soc.isPending) {
      soc.mutate({
        attack_type: alert.attackType || "Generic",
        attack_stage: alert.attackStage,
        threat_level: alert.severity,
        mitre_tactic: alert.mitreTactic,
        mitre_technique: alert.mitreTechnique,
        source_ip: alert.sourceIp,
        target_ip: alert.targetIp,
        protocol: alert.protocol,
      });
    }
  };

  return (
    <div className="mt-4 border-t border-border pt-3">
      <button
        type="button"
        onClick={toggle}
        className="flex items-center gap-2 text-sm font-medium text-cyan-300 hover:text-cyan-200 transition-colors"
      >
        <Shield className="h-4 w-4" />
        SOC Response
        {open ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
      </button>

      {open && (
        <div className="mt-3 space-y-4">
          {soc.isPending && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Generating response bundle…
            </div>
          )}
          {soc.isError && (
            <p className="text-sm text-red-400">
              Failed to generate SOC response. {soc.error instanceof Error ? soc.error.message : ""}
            </p>
          )}
          {data && (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                <div className="rounded-md bg-black/30 border border-border p-2">
                  <div className="text-muted-foreground uppercase">Severity</div>
                  <div className={cn("font-semibold", SEVERITY_TONE[data.severity] || "text-white")}>
                    {data.severity}
                  </div>
                </div>
                <div className="rounded-md bg-black/30 border border-border p-2">
                  <div className="text-muted-foreground uppercase">Kill Chain</div>
                  <div className="font-semibold text-white">{data.kill_chain_stage}</div>
                </div>
                <div className="rounded-md bg-black/30 border border-border p-2">
                  <div className="text-muted-foreground uppercase">MITRE Tactic</div>
                  <div className="font-semibold text-white">{data.mitre.tactic}</div>
                </div>
                <div className="rounded-md bg-black/30 border border-border p-2">
                  <div className="text-muted-foreground uppercase">Technique</div>
                  {data.mitre.technique_url ? (
                    <a
                      href={data.mitre.technique_url}
                      target="_blank"
                      rel="noreferrer"
                      className="font-semibold text-cyan-300 hover:underline"
                    >
                      {data.mitre.technique}
                    </a>
                  ) : (
                    <div className="font-semibold text-white">{data.mitre.technique}</div>
                  )}
                </div>
              </div>

              <div>
                <div className="text-xs font-semibold uppercase text-muted-foreground mb-1">
                  Risk Summary
                </div>
                <p className="text-sm text-foreground">{data.risk_summary}</p>
              </div>

              <div>
                <div className="text-xs font-semibold uppercase text-muted-foreground mb-1">
                  Recommended Response
                </div>
                <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground">
                  {data.recommended_response.map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <RuleBlock label="Firewall (Linux)" rule={data.firewall_rule.linux} />
                <RuleBlock label="Firewall (Windows)" rule={data.firewall_rule.windows} />
                <RuleBlock label="Host Isolation" rule={data.isolation_command} />
                <RuleBlock label="Sigma" rule={data.detection_rules.sigma} />
                <RuleBlock label="Suricata" rule={data.detection_rules.suricata} />
                <RuleBlock label="Snort" rule={data.detection_rules.snort} />
                <RuleBlock label="YARA" rule={data.detection_rules.yara} />
              </div>

              <div>
                <div className="text-xs font-semibold uppercase text-muted-foreground mb-1">
                  Analyst Notes
                </div>
                <p className="text-sm text-muted-foreground italic">{data.analyst_notes}</p>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default function AlertCenter() {
  const { connected } = useWebSocketSync();
  const { data, isLoading } = useAlerts();
  const updateAlert = useUpdateAlert();
  const alerts = data?.alerts ?? [];

  const grouped = {
    critical: alerts.filter((a) => a.severity === "critical"),
    high: alerts.filter((a) => a.severity === "high"),
    medium: alerts.filter((a) => a.severity === "medium"),
    low: alerts.filter((a) => a.severity === "low" || a.severity === "info"),
  };

  return (
    <main className="flex-1 overflow-auto p-6 space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-white">Alert Center</h1>
          <p className="text-muted-foreground mt-1">
            Real-time security alerts from TGNN inference · WebSocket {connected ? "live" : "reconnecting"}
          </p>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {Object.entries(grouped).map(([severity, items]) => (
            <Card key={severity} className="panel-card">
              <CardContent className="p-4 text-center">
                <div className="text-2xl font-bold font-mono">{items.length}</div>
                <div className="text-xs uppercase text-muted-foreground">{severity}</div>
              </CardContent>
            </Card>
          ))}
        </div>

        {isLoading && <Loader2 className="h-6 w-6 animate-spin text-primary mx-auto" />}

        <div className="space-y-3">
          {alerts.map((alert) => (
            <Card key={alert.id} className="panel-card">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base flex items-center gap-2">
                    <ShieldAlert className={cn(
                      "h-4 w-4",
                      alert.severity === "critical" ? "text-red-400" : "text-orange-400",
                    )} />
                    {alert.title}
                  </CardTitle>
                  <Badge variant="outline">{alert.severity}</Badge>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-3">{alert.description}</p>
                <div className="flex flex-wrap gap-2 text-xs font-mono text-muted-foreground mb-4">
                  {alert.attackType && <span>Attack: {alert.attackType}</span>}
                  {alert.attackStage && <span>Stage: {alert.attackStage}</span>}
                  {alert.mitreTactic && <span className="text-cyan-300">MITRE Tactic: {alert.mitreTactic}</span>}
                  {alert.mitreTechnique && <span className="text-cyan-300">Technique: {alert.mitreTechnique}</span>}
                  {alert.sourceIp && <span>Src: {alert.sourceIp}</span>}
                  {alert.targetIp && <span>Dst: {alert.targetIp}</span>}
                  <span>{new Date(alert.createdAt).toLocaleString()}</span>
                </div>
                <div className="flex gap-2">
                  {STATUS_OPTIONS.map((status) => (
                    <Button
                      key={status}
                      size="sm"
                      variant={alert.status === status ? "default" : "outline"}
                      disabled={updateAlert.isPending}
                      onClick={() => updateAlert.mutate({ id: alert.id, status })}
                    >
                      {status === alert.status && <CheckCircle className="h-3 w-3 mr-1" />}
                      {status.replace("_", " ")}
                    </Button>
                  ))}
                </div>
                <AlertSocResponse alert={alert} />
              </CardContent>
            </Card>
          ))}
          {!alerts.length && !isLoading && (
            <EmptyState
              title="No alerts recorded"
              message="Run predictions with elevated threat levels to generate SOC alerts."
            />
          )}
        </div>
      </main>
  );
}
