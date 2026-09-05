/**
 * In-memory API / error log ring buffer (Phase 13 Admin).
 * Complements PostgreSQL audit_logs and system_logs for fast admin UI reads.
 */

export type LogLevel = "info" | "warn" | "error";

export interface ApiLogEntry {
  timestamp: string;
  scope: string;
  message: string;
  level: LogLevel;
  meta?: Record<string, unknown>;
}

const MAX_ENTRIES = 500;
const buffer: ApiLogEntry[] = [];

export function pushApiLog(
  scope: string,
  message: string,
  meta?: Record<string, unknown>,
  level: LogLevel = "info",
) {
  buffer.unshift({
    timestamp: new Date().toISOString(),
    scope,
    message,
    meta,
    level,
  });
  if (buffer.length > MAX_ENTRIES) {
    buffer.length = MAX_ENTRIES;
  }
}

export function getApiLogs(limit = 100, level?: LogLevel) {
  const capped = Math.min(Math.max(limit, 1), MAX_ENTRIES);
  const filtered = level ? buffer.filter((e) => e.level === level) : buffer;
  return filtered.slice(0, capped);
}
