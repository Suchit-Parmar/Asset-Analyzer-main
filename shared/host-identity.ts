/**
 * Host / website display identity helpers.
 * Friendly names come only from hostname + a known-domain map — never guessed.
 */

/** Well-known registrable domains → display names (exact / suffix match). */
const KNOWN_DOMAIN_NAMES: Record<string, string> = {
  "google.com": "Google",
  "www.google.com": "Google",
  "github.com": "GitHub",
  "www.github.com": "GitHub",
  "microsoft.com": "Microsoft",
  "www.microsoft.com": "Microsoft",
  "openai.com": "OpenAI",
  "www.openai.com": "OpenAI",
  "stackoverflow.com": "Stack Overflow",
  "www.stackoverflow.com": "Stack Overflow",
  "youtube.com": "YouTube",
  "www.youtube.com": "YouTube",
  "facebook.com": "Facebook",
  "www.facebook.com": "Facebook",
  "twitter.com": "Twitter",
  "x.com": "X",
  "linkedin.com": "LinkedIn",
  "www.linkedin.com": "LinkedIn",
  "amazon.com": "Amazon",
  "www.amazon.com": "Amazon",
  "cloudflare.com": "Cloudflare",
  "www.cloudflare.com": "Cloudflare",
  "npmjs.com": "npm",
  "www.npmjs.com": "npm",
  "reddit.com": "Reddit",
  "www.reddit.com": "Reddit",
  "wikipedia.org": "Wikipedia",
  "en.wikipedia.org": "Wikipedia",
  "example.com": "Example",
  "www.example.com": "Example",
};

export type HostIdentity = {
  /** Friendly website/device name, or "Unknown" when not mapped. */
  displayName: string;
  /** Hostname / domain / NetBIOS-style name when available. */
  hostname: string | null;
  /** IPv4/IPv6 when distinct from hostname; otherwise null. */
  ip: string | null;
  isWebsite: boolean;
};

function looksLikeIp(value: string): boolean {
  const v = value.trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return true;
  if (v.includes(":") && /^[0-9a-fA-F:]+$/.test(v)) return true;
  return false;
}

/** Extract hostname from a URL or raw host string. */
export function extractHostname(raw: string): string | null {
  const input = raw.trim();
  if (!input) return null;
  try {
    if (input.includes("://")) {
      return new URL(input).hostname.toLowerCase() || null;
    }
  } catch {
    // fall through
  }
  const cleaned = input.replace(/\/.*$/, "").toLowerCase();
  return cleaned || null;
}

/** Resolve a friendly website name from hostname only (no guessing). */
export function websiteDisplayName(hostname: string | null | undefined): string {
  if (!hostname) return "Unknown";
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (KNOWN_DOMAIN_NAMES[host]) return KNOWN_DOMAIN_NAMES[host];

  // Match suffix (e.g. maps.google.com → Google) only for known registrable domains.
  for (const [domain, name] of Object.entries(KNOWN_DOMAIN_NAMES)) {
    if (domain.startsWith("www.")) continue;
    if (host === domain || host.endsWith(`.${domain}`)) return name;
  }
  return "Unknown";
}

export function isWebsiteVendor(vendor?: string | null): boolean {
  const v = (vendor ?? "").toLowerCase();
  return v === "website" || v === "external_website" || v.includes("website");
}

/**
 * Build display identity for graph/tooltip/details.
 * Prefer explicit websiteName from features when present.
 */
export function resolveHostIdentity(input: {
  label?: string | null;
  hostname?: string | null;
  ip?: string | null;
  vendor?: string | null;
  websiteName?: string | null;
  nodeType?: string | null;
}): HostIdentity {
  const website = isWebsiteVendor(input.vendor);
  const rawHost = (input.hostname || input.label || "").trim() || null;
  const rawIp = (input.ip || "").trim() || null;

  let hostname: string | null = rawHost && !looksLikeIp(rawHost) ? rawHost : null;
  let ip: string | null = rawIp && looksLikeIp(rawIp) ? rawIp : null;

  // If ip field holds a domain (legacy website rows), treat it as hostname.
  if (!hostname && rawIp && !looksLikeIp(rawIp)) {
    hostname = rawIp.toLowerCase();
  }
  // If hostname field holds an IP, treat as IP.
  if (!ip && rawHost && looksLikeIp(rawHost)) {
    ip = rawHost;
  }

  if (website) {
    const host = (hostname || extractHostname(rawHost || rawIp || "") || "").toLowerCase() || null;
    const mapped =
      input.websiteName && input.websiteName.trim()
        ? input.websiteName.trim()
        : websiteDisplayName(host);
    return {
      displayName: mapped || "Unknown",
      hostname: host,
      ip,
      isWebsite: true,
    };
  }

  // Local / internal device: prefer human label, then hostname, then IP.
  const deviceName =
    (input.label && !looksLikeIp(input.label) ? input.label.trim() : null) ||
    hostname ||
    "Unknown Device";

  return {
    displayName: deviceName,
    hostname: hostname && hostname !== deviceName ? hostname : hostname,
    ip,
    isWebsite: false,
  };
}

/** Compact two-line graph label (website or device). */
export function compactGraphLabel(identity: HostIdentity): { line1: string; line2: string | null } {
  if (identity.isWebsite) {
    return {
      line1: identity.displayName,
      line2: identity.hostname,
    };
  }
  const line1 = identity.displayName;
  const line2 =
    identity.hostname && identity.hostname !== identity.displayName
      ? identity.hostname
      : identity.ip;
  return { line1, line2: line2 && line2 !== line1 ? line2 : null };
}
