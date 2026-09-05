/**
 * Display-layer helpers for the SOC dashboard.
 * Keeps model/storage labels intact while presenting viva-friendly names and 0–100 risk.
 */

export type DeviceCategory =
  | "laptop"
  | "desktop"
  | "mobile"
  | "server"
  | "router"
  | "gateway"
  | "iot"
  | "website"
  | "unknown";

const ATTACK_ALIASES: Record<string, string> = {
  Probe: "Port Scan",
  probe: "Port Scan",
  R2L: "Remote-to-Local",
  U2R: "User-to-Root",
  "Web Attack": "Web Attack",
  DDoS: "DDoS",
  DoS: "DoS",
  "Brute Force": "Brute Force",
  Botnet: "Botnet / Malware",
  Infiltration: "Infiltration",
  Heartbleed: "Heartbleed",
  Normal: "Normal / Benign",
};

/** Convert stored 0–1 risk (or already 0–100) into integer 0–100. */
export function riskScore100(raw?: number | null): number {
  if (raw == null || Number.isNaN(Number(raw))) return 0;
  const n = Number(raw);
  if (n <= 1) return Math.round(Math.max(0, Math.min(1, n)) * 100);
  return Math.round(Math.max(0, Math.min(100, n)));
}

export function riskLevel(score100: number): "Low" | "Medium" | "High" | "Critical" {
  if (score100 >= 80) return "Critical";
  if (score100 >= 60) return "High";
  if (score100 >= 30) return "Medium";
  return "Low";
}

export function riskLevelClass(level: string): string {
  switch (level) {
    case "Critical":
      return "bg-red-500/15 text-red-400 border-red-500/30";
    case "High":
      return "bg-orange-500/15 text-orange-400 border-orange-500/30";
    case "Medium":
      return "bg-amber-500/15 text-amber-400 border-amber-500/30";
    default:
      return "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";
  }
}

export function attackDisplayName(raw?: string | null): string {
  if (!raw) return "Unknown";
  return ATTACK_ALIASES[raw] ?? raw;
}

/** Map DB node_type (+ optional vendor) to a display device category. */
export function deviceCategory(nodeType?: string | null, vendor?: string | null): DeviceCategory {
  const v = (vendor ?? "").toLowerCase();
  if (v === "website" || v === "external_website" || v.includes("website")) return "website";
  switch ((nodeType ?? "").toLowerCase()) {
    case "iot_device":
      return "iot";
    case "server":
      return "server";
    case "router":
    case "switch":
      return "router";
    case "user":
      return "laptop";
    case "host":
    case "ip_address":
      return "desktop";
    default:
      return "unknown";
  }
}

export function deviceCategoryLabel(cat: DeviceCategory): string {
  const labels: Record<DeviceCategory, string> = {
    laptop: "Laptop",
    desktop: "Desktop",
    mobile: "Mobile",
    server: "Server",
    router: "Router",
    gateway: "Gateway",
    iot: "IoT Device",
    website: "Website / External",
    unknown: "Unknown Device",
  };
  return labels[cat];
}

export function deviceFilterGroup(cat: DeviceCategory): "all" | "computers" | "mobile" | "servers" | "routers" | "iot" | "website" | "unknown" {
  if (cat === "laptop" || cat === "desktop") return "computers";
  if (cat === "mobile") return "mobile";
  if (cat === "server") return "servers";
  if (cat === "router" || cat === "gateway") return "routers";
  if (cat === "iot") return "iot";
  if (cat === "website") return "website";
  return "unknown";
}

/** Plain-language reasons for viva / non-expert users. */
export function plainLanguageReasons(input: {
  risk100: number;
  attackType?: string | null;
  threatLevel?: string | null;
  packets?: number | null;
  connectionCount?: number | null;
  failedLogins?: number | null;
  reasoning?: string | null;
  status?: string | null;
}): string[] {
  const reasons: string[] = [];
  const attack = attackDisplayName(input.attackType);
  if (input.attackType && input.attackType !== "Normal") {
    reasons.push(`Model flagged traffic pattern similar to ${attack}`);
  }
  if (input.risk100 >= 80) reasons.push("Very high risk score from GNN + traffic signals");
  else if (input.risk100 >= 60) reasons.push("Elevated risk compared with typical hosts");
  if ((input.packets ?? 0) > 5000) reasons.push("Unusually high packet volume");
  if ((input.connectionCount ?? 0) > 50) reasons.push("Many distinct connections in a short window");
  if ((input.failedLogins ?? 0) > 3) reasons.push("Repeated failed login attempts");
  if (input.status === "compromised") reasons.push("Marked compromised by prior detections");
  if (input.status === "suspicious") reasons.push("Abnormal communication pattern on the graph");
  if (input.reasoning) {
    const short = input.reasoning.replace(/\s+/g, " ").trim();
    if (short && !reasons.some((r) => r.includes(short.slice(0, 24)))) {
      reasons.push(short.length > 140 ? `${short.slice(0, 137)}…` : short);
    }
  }
  if (!reasons.length) reasons.push("No strong anomaly indicators in the current window");
  return reasons.slice(0, 5);
}

export function formatBytes(n?: number | null): string {
  if (n == null || Number.isNaN(n)) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function isValidHttpUrl(raw: string): boolean {
  try {
    const u = new URL(raw.trim());
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

// Re-export shared host identity helpers for Network page display.
export {
  resolveHostIdentity,
  compactGraphLabel,
  websiteDisplayName,
  extractHostname,
  isWebsiteVendor,
  type HostIdentity,
} from "@shared/host-identity";

