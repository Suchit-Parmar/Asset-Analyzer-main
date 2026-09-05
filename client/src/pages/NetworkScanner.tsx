import { useCallback, useEffect, useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  ScanSearch,
  Wifi,
  Server,
  Laptop,
  Smartphone,
  Printer,
  Router as RouterIcon,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Search,
  Loader2,
  Activity,
  Cpu,
  HardDrive,
  Network,
  Eye,
  RadioTower,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useAlerts, useDashboardMetrics, useNetworkNodes, useNetworkEdges } from "@/hooks/useApi";
import { useWebSocketSync } from "@/hooks/useWebSocketSync";
import type { Alert, NetworkNode } from "@/lib/api";

type DeviceType = "router" | "server" | "workstation" | "laptop" | "mobile" | "printer" | "iot";

interface ScannedDevice {
  id: string;
  ip: string;
  hostname: string;
  mac: string;
  type: DeviceType;
  status: NetworkNode["status"];
  os: string | null;
  vendor: string | null;
  risk: number;
  openPorts: number[];
  packetsPerSecond: number;
  throughputMbps: number;
  attacks: Array<{ type: string; severity: Alert["severity"]; timestamp: string; details: string }>;
}

const DEVICE_ICONS: Record<DeviceType, typeof RouterIcon> = {
  router: RouterIcon,
  server: Server,
  workstation: Laptop,
  laptop: Laptop,
  mobile: Smartphone,
  printer: Printer,
  iot: Wifi,
};

const NODE_TYPE_MAP: Record<string, DeviceType> = {
  router: "router",
  server: "server",
  host: "workstation",
  ip_address: "workstation",
  switch: "router",
  iot_device: "iot",
  user: "laptop",
};

const STATUS_COLORS: Record<string, string> = {
  online: "bg-green-500/20 text-green-400 border-green-500/30",
  offline: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  suspicious: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  compromised: "bg-red-500/20 text-red-400 border-red-500/30",
};

const SEVERITY_COLORS: Record<string, string> = {
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  info: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

function mapNodeToDevice(node: NetworkNode, alerts: Alert[]): ScannedDevice {
  const nodeAlerts = alerts.filter(
    (a) => a.sourceIp === node.ipAddress || a.targetIp === node.ipAddress,
  );

  return {
    id: node.id,
    ip: node.ipAddress,
    hostname: node.hostname ?? node.ipAddress,
    mac: node.macAddress ?? "—",
    type: NODE_TYPE_MAP[node.nodeType] ?? "workstation",
    status: node.status,
    os: node.os,
    vendor: node.vendor,
    risk: node.riskScore,
    openPorts: node.openPorts ?? [],
    packetsPerSecond: node.packets ?? 0,
    throughputMbps: Math.round((node.bytes ?? 0) / 125000),
    attacks: nodeAlerts.map((a) => ({
      type: a.attackType ?? a.title,
      severity: a.severity,
      timestamp: new Date(a.createdAt).toLocaleString(),
      details: a.description ?? "",
    })),
  };
}

const PAGE_SIZE = 8;

export default function NetworkScanner() {
  useWebSocketSync();
  const [scanActive, setScanActive] = useState(false);
  const { data: nodesData, refetch, isFetching } = useNetworkNodes(undefined, scanActive);
  const { data: edgesData } = useNetworkEdges();
  const { data: alertsData } = useAlerts(undefined, "open");
  const { data: metricsData } = useDashboardMetrics();

  const [scanRange, setScanRange] = useState("192.168.1.0/24");
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [devices, setDevices] = useState<ScannedDevice[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<ScannedDevice | null>(null);
  const [filter, setFilter] = useState<"all" | "compromised" | "suspicious" | "online">("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [page, setPage] = useState(1);
  const [telemetryHistory, setTelemetryHistory] = useState<Array<{ time: string; throughputMbps: number; queueDepth: number; alertsPerMinute: number }>>([]);

  const alerts = alertsData?.alerts ?? [];

  const loadDevices = useCallback(() => {
    const nodes = nodesData?.nodes ?? [];
    const mapped = nodes.map((n) => mapNodeToDevice(n, alerts));
    setDevices(mapped);
    setSelectedDevice((prev) => mapped.find((d) => d.id === prev?.id) ?? mapped[0] ?? null);
  }, [nodesData, alerts]);

  useEffect(() => {
    if (nodesData?.nodes) {
      loadDevices();
    }
  }, [nodesData, loadDevices]);

  useEffect(() => {
    if (devices.length === 0) return;
    setTelemetryHistory((prev) => {
      const next = [
        ...prev,
        {
          time: new Date().toLocaleTimeString("en-US", { hour12: false }),
          throughputMbps: devices.reduce((s, d) => s + d.throughputMbps, 0),
          queueDepth: metricsData?.alerts?.open ?? 0,
          alertsPerMinute: metricsData?.alerts?.total ?? 0,
        },
      ];
      return next.slice(-24);
    });
  }, [devices, metricsData]);

  const startScan = async () => {
    setIsScanning(true);
    setProgress(0);
    setDevices([]);
    setSelectedDevice(null);
    setScanActive(true);

    const progressInterval = setInterval(() => {
      setProgress((p) => Math.min(p + 12, 90));
    }, 200);

    try {
      await refetch();
      setProgress(100);
    } finally {
      clearInterval(progressInterval);
      setTimeout(() => setIsScanning(false), 400);
    }
  };

  const filteredDevices = devices.filter((device) => {
    if (filter !== "all" && device.status !== filter) return false;
    if (searchQuery && !device.ip.includes(searchQuery) && !device.hostname.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false;
    }
    return true;
  });

  const totalPages = Math.max(1, Math.ceil(filteredDevices.length / PAGE_SIZE));
  const paginatedDevices = filteredDevices.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  useEffect(() => {
    setPage(1);
  }, [filter, searchQuery]);

  const edges = edgesData?.edges ?? [];

  const selectedConnections = useMemo(() => {
    if (!selectedDevice) return [];
    return edges.filter(
      (e) => e.sourceNodeId === selectedDevice.id || e.targetNodeId === selectedDevice.id,
    );
  }, [edges, selectedDevice]);

  const protocolBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    selectedConnections.forEach((e) => {
      const proto = e.protocol || "unknown";
      counts[proto] = (counts[proto] ?? 0) + 1;
    });
    return Object.entries(counts).map(([protocol, count]) => ({ protocol, count }));
  }, [selectedConnections]);

  const portBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    selectedConnections.forEach((e) => {
      const key = String(e.weight ?? "flow");
      counts[key] = (counts[key] ?? 0) + 1;
    });
    return Object.entries(counts)
      .map(([port, count]) => ({ port, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [selectedConnections]);

  const stats = useMemo(() => ({
    total: devices.length,
    compromised: devices.filter((d) => d.status === "compromised").length,
    suspicious: devices.filter((d) => d.status === "suspicious").length,
    online: devices.filter((d) => d.status === "online").length,
  }), [devices]);

  const networkHealth = useMemo(() => {
    if (devices.length === 0) return 100;
    const compromisedWeight = stats.compromised * 30;
    const suspiciousWeight = stats.suspicious * 15;
    const avgRisk = devices.reduce((s, d) => s + d.risk, 0) / devices.length;
    return Math.max(0, Math.round(100 - compromisedWeight - suspiciousWeight - avgRisk * 40));
  }, [devices, stats]);

  return (
    <main className="app-main flex-1 overflow-auto p-4 md:p-6 space-y-6">
        <div className="page-header">
          <div className="page-kicker">Live Discovery</div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2">Network Scanner and Threat Lens</h1>
          <p className="text-muted-foreground font-mono text-sm max-w-2xl">
            Discovers devices from the PostgreSQL network topology synced from TGNN graph builder.
            Threat data cross-referenced with open SOC alerts.
          </p>
        </div>

        <Card className="panel-card">
          <CardContent className="p-6">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-end">
              <div className="flex-1">
                <label className="text-sm text-muted-foreground mb-2 block">Target Network Range</label>
                <div className="flex gap-2">
                  <Input
                    value={scanRange}
                    onChange={(event) => setScanRange(event.target.value)}
                    placeholder="192.168.1.0/24"
                    className="bg-background/50 border-border/50 font-mono"
                  />
                  <Button onClick={startScan} disabled={isScanning || isFetching} className="bg-primary/20 hover:bg-primary/30 border border-primary/50">
                    {isScanning || isFetching ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <ScanSearch className="w-4 h-4 mr-2" />}
                    {isScanning ? "Scanning..." : "Refresh Topology"}
                  </Button>
                </div>
              </div>
            </div>

            {isScanning && (
              <div className="mt-4">
                <div className="flex justify-between text-xs text-muted-foreground mb-2">
                  <span>Loading network nodes from /api/network/nodes...</span>
                  <span>{Math.round(progress)}%</span>
                </div>
                <Progress value={progress} className="h-2" />
              </div>
            )}
          </CardContent>
        </Card>

        {devices.length > 0 && (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-4">
              <StatCard icon={Network} label="Total Devices" value={stats.total} color="text-blue-400" />
              <StatCard icon={XCircle} label="Compromised" value={stats.compromised} color="text-red-400" />
              <StatCard icon={AlertTriangle} label="Suspicious" value={stats.suspicious} color="text-yellow-400" />
              <StatCard icon={CheckCircle} label="Online" value={stats.online} color="text-green-400" />
              <StatCard icon={Shield} label="Network Health" value={networkHealth} color={networkHealth >= 70 ? "text-green-400" : networkHealth >= 40 ? "text-yellow-400" : "text-red-400"} suffix="%" />
            </div>

            <Card className="panel-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <RadioTower className="w-5 h-5 text-primary" />
                  Network Telemetry
                </CardTitle>
              </CardHeader>
              <CardContent className="h-80">
                {telemetryHistory.length === 0 ? (
                  <p className="text-muted-foreground font-mono text-sm">Collecting telemetry samples...</p>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={telemetryHistory}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                      <XAxis dataKey="time" stroke="#666" minTickGap={24} />
                      <YAxis stroke="#666" />
                      <Tooltip contentStyle={{ backgroundColor: "#111", borderColor: "#333" }} />
                      <Legend />
                      <Line type="monotone" dataKey="throughputMbps" stroke="hsl(190, 90%, 50%)" strokeWidth={2} dot={false} name="Mbps" />
                      <Line type="monotone" dataKey="queueDepth" stroke="#f59e0b" strokeWidth={2} dot={false} name="Open Alerts" />
                      <Line type="monotone" dataKey="alertsPerMinute" stroke="#ef4444" strokeWidth={2} dot={false} name="Total Alerts (24h)" />
                    </LineChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>

            <div className="panel-subtle flex flex-col gap-4 p-4 lg:flex-row lg:items-center">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search by IP or hostname..."
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                  className="pl-10 bg-background/50 border-border/50"
                />
              </div>
              <div className="flex gap-2 flex-wrap">
                {(["all", "compromised", "suspicious", "online"] as const).map((value) => (
                  <Button
                    key={value}
                    variant={filter === value ? "default" : "outline"}
                    size="sm"
                    onClick={() => setFilter(value)}
                    className={cn(filter === value ? "bg-primary/20 border-primary/50" : "border-border/50", "capitalize")}
                  >
                    {value}
                  </Button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="space-y-3">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Eye className="w-5 h-5 text-primary" />
                  Discovered Devices
                </h3>
                {paginatedDevices.map((device) => {
                  const Icon = DEVICE_ICONS[device.type];
                  return (
                    <Card
                      key={device.id}
                      className={cn(
                        "panel-card cursor-pointer transition-all hover:border-primary/50",
                        selectedDevice?.id === device.id && "border-primary/50 ring-1 ring-primary/30",
                        device.status === "compromised" && "border-red-500/30 bg-red-500/5",
                        device.status === "suspicious" && "border-yellow-500/30 bg-yellow-500/5",
                      )}
                      onClick={() => setSelectedDevice(device)}
                    >
                      <CardContent className="p-4">
                        <div className="flex items-start justify-between">
                          <div className="flex items gap-3">
                            <div className={cn(
                              "p-2 rounded-lg",
                              device.status === "compromised" ? "bg-red-500/20" :
                              device.status === "suspicious" ? "bg-yellow-500/20" : "bg-primary/20",
                            )}>
                              <Icon className={cn(
                                "w-5 h-5",
                                device.status === "compromised" ? "text-red-400" :
                                device.status === "suspicious" ? "text-yellow-400" : "text-primary",
                              )} />
                            </div>
                            <div>
                              <div className="font-mono font-bold text-sm">{device.hostname}</div>
                              <div className="text-xs text-muted-foreground">{device.ip}</div>
                            </div>
                          </div>
                          <Badge className={cn("border", STATUS_COLORS[device.status])}>{device.status}</Badge>
                        </div>
                        <div className="mt-3 flex items-center justify-between text-xs text-muted-foreground">
                          <span>{device.vendor ?? "Unknown vendor"}</span>
                          <span className="font-mono">{Math.round(device.risk * 100)}% Risk</span>
                        </div>
                        <div className="mt-2 text-xs text-muted-foreground">
                          {device.packetsPerSecond.toLocaleString()} pkts | {device.throughputMbps} Mbps
                        </div>
                        {device.openPorts.length > 0 && (
                          <div className="mt-2 flex gap-1 flex-wrap">
                            {device.openPorts.slice(0, 4).map((port) => (
                              <span key={port} className="px-1.5 py-0.5 bg-muted rounded text-xs font-mono text-muted-foreground">{port}</span>
                            ))}
                            {device.openPorts.length > 4 && (
                              <span className="px-1.5 py-0.5 text-xs text-muted-foreground">+{device.openPorts.length - 4}</span>
                            )}
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  );
                })}
                {totalPages > 1 && (
                  <div className="flex items-center justify-between pt-2 text-xs font-mono text-muted-foreground">
                    <span>
                      Page {page} / {totalPages} · {filteredDevices.length} device{filteredDevices.length === 1 ? "" : "s"}
                    </span>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                        Previous
                      </Button>
                      <Button size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                        Next
                      </Button>
                    </div>
                  </div>
                )}
              </div>

              <div>
                <h3 className="text-lg font-semibold flex items-center gap-2 mb-4">
                  <Activity className="w-5 h-5 text-primary" />
                  Device Analysis
                </h3>
                {selectedDevice ? (
                  <Card className="panel-card">
                    <CardContent className="p-6 space-y-6">
                      <div className="flex items-center gap-4">
                        <div className="p-3 rounded-xl bg-primary/20">
                          {(() => {
                            const Icon = DEVICE_ICONS[selectedDevice.type];
                            return <Icon className="w-8 h-8 text-primary" />;
                          })()}
                        </div>
                        <div>
                          <div className="text-xl font-bold">{selectedDevice.hostname}</div>
                          <div className="text-sm text-muted-foreground">{selectedDevice.ip} • {selectedDevice.mac}</div>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-4">
                        <div className="panel-subtle p-3">
                          <div className="text-xs text-muted-foreground mb-1">Risk Level</div>
                          <div className={cn(
                            "text-lg font-bold",
                            selectedDevice.risk > 0.8 ? "text-red-400" :
                            selectedDevice.risk > 0.5 ? "text-yellow-400" : "text-green-400",
                          )}>
                            {selectedDevice.risk > 0.8 ? "CRITICAL" :
                              selectedDevice.risk > 0.5 ? "HIGH" :
                                selectedDevice.risk > 0.3 ? "MEDIUM" : "LOW"}
                          </div>
                        </div>
                        <div className="panel-subtle p-3">
                          <div className="text-xs text-muted-foreground mb-1">Device Score</div>
                          <div className="text-lg font-bold font-mono">{Math.round((1 - selectedDevice.risk) * 100)}/100</div>
                        </div>
                        <div className="panel-subtle p-3">
                          <div className="text-xs text-muted-foreground mb-1">Status</div>
                          <div className="text-lg font-bold capitalize">{selectedDevice.status}</div>
                        </div>
                      </div>

                      <div>
                        <div className="text-xs text-muted-foreground mb-2">Risk Score</div>
                        <Progress
                          value={selectedDevice.risk * 100}
                          className={cn(
                            "h-3",
                            selectedDevice.risk > 0.8 ? "[&>div]:bg-red-500" :
                            selectedDevice.risk > 0.5 ? "[&>div]:bg-yellow-500" : "[&>div]:bg-green-500",
                          )}
                        />
                      </div>

                      <div className="space-y-3">
                        <div className="flex items-center gap-3 text-sm">
                          <Cpu className="w-4 h-4 text-muted-foreground" />
                          <span className="text-muted-foreground">OS:</span>
                          <span>{selectedDevice.os ?? "Unknown"}</span>
                        </div>
                        <div className="flex items-center gap-3 text-sm">
                          <HardDrive className="w-4 h-4 text-muted-foreground" />
                          <span className="text-muted-foreground">Vendor:</span>
                          <span>{selectedDevice.vendor ?? "Unknown"}</span>
                        </div>
                        <div className="flex items-center gap-3 text-sm">
                          <Activity className="w-4 h-4 text-muted-foreground" />
                          <span className="text-muted-foreground">Traffic:</span>
                          <span className="font-mono">{selectedDevice.packetsPerSecond.toLocaleString()} pkts</span>
                        </div>
                      </div>

                      {selectedDevice.openPorts.length > 0 && (
                        <div>
                          <div className="text-sm font-semibold mb-2">Open Ports</div>
                          <div className="flex gap-2 flex-wrap">
                            {selectedDevice.openPorts.map((port) => (
                              <span key={port} className="px-2 py-1 bg-muted rounded text-xs font-mono">{port}</span>
                            ))}
                          </div>
                        </div>
                      )}

                      {protocolBreakdown.length > 0 && (
                        <div>
                          <div className="text-sm font-semibold mb-2">Protocol Analysis</div>
                          <div className="space-y-1 text-xs font-mono">
                            {protocolBreakdown.map((row) => (
                              <div key={row.protocol} className="flex justify-between panel-subtle px-2 py-1 rounded">
                                <span className="uppercase">{row.protocol}</span>
                                <span>{row.count} flow{row.count === 1 ? "" : "s"}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {selectedConnections.length > 0 && (
                        <div>
                          <div className="text-sm font-semibold mb-2">Connection History ({selectedConnections.length})</div>
                          <div className="max-h-36 overflow-y-auto space-y-1 text-xs font-mono">
                            {selectedConnections.slice(0, 12).map((edge) => (
                              <div key={edge.id} className="panel-subtle px-2 py-1 rounded flex justify-between gap-2">
                                <span>{edge.sourceNodeId} → {edge.targetNodeId}</span>
                                <span className="text-muted-foreground">{edge.protocol}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {selectedDevice.attacks.length > 0 && (
                        <div>
                          <div className="text-sm font-semibold mb-3 flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 text-red-400" />
                            Attack Timeline
                          </div>
                          <div className="space-y-2">
                            {selectedDevice.attacks.map((attack, index) => (
                              <div key={`${attack.type}-${index}`} className={cn("p-3 rounded-2xl border", SEVERITY_COLORS[attack.severity])}>
                                <div className="flex justify-between items-start mb-1">
                                  <span className="font-semibold">{attack.type}</span>
                                  <Badge className={cn("border text-xs", SEVERITY_COLORS[attack.severity])}>{attack.severity}</Badge>
                                </div>
                                <div className="text-xs text-muted-foreground">{attack.timestamp}</div>
                                <div className="text-xs mt-1 text-muted-foreground">{attack.details}</div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="flex gap-2 pt-2">
                        <Button className="flex-1 bg-primary/20 hover:bg-primary/30 border border-primary/50">
                          <Shield className="w-4 h-4 mr-2" />
                          Quarantine
                        </Button>
                        <Button variant="outline" className="flex-1 border-border/50">
                          Block IP
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ) : (
                  <Card className="panel-card">
                    <CardContent className="p-12 text-center">
                      <Search className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-50" />
                      <p className="text-muted-foreground">Select a device to view detailed analysis</p>
                    </CardContent>
                  </Card>
                )}
              </div>
            </div>
          </>
        )}

        {devices.length === 0 && !isScanning && (
          <Card className="panel-card">
            <CardContent className="p-12 text-center">
              <ScanSearch className="w-16 h-16 text-muted-foreground mx-auto mb-4 opacity-50" />
              <h3 className="text-xl font-semibold mb-2">Ready to Scan</h3>
              <p className="text-muted-foreground mb-4">Load network topology from PostgreSQL via /api/network/nodes.</p>
              <Button onClick={startScan} className="bg-primary/20 hover:bg-primary/30 border border-primary/50">
                <ScanSearch className="w-4 h-4 mr-2" />
                Refresh Topology ({scanRange})
              </Button>
            </CardContent>
          </Card>
        )}
      </main>
  );
}

function StatCard({ icon: Icon, label, value, color, suffix = "" }: { icon: typeof Network; label: string; value: number; color: string; suffix?: string }) {
  return (
    <Card className="metric-surface rounded-[1.35rem]">
      <CardContent className="p-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-white/5">
            <Icon className={cn("w-5 h-5", color)} />
          </div>
          <div>
            <div className={cn("text-2xl font-bold font-mono", color)}>{value}{suffix}</div>
            <div className="text-xs text-muted-foreground">{label}</div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
