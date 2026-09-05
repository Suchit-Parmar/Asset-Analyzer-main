/**
 * Resolve dataset identifiers from the API.
 *
 * Clients may send either:
 * - a PostgreSQL UUID (datasets.id), or
 * - a human slug such as "cicids2017" / "unsw_nb15" (datasets.source)
 *
 * AI loaders always receive the canonical source slug.
 * PostgreSQL FK columns always receive the UUID.
 */
import { eq } from "drizzle-orm";
import { db } from "./db";
import { datasets } from "@shared/schema";

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Map alternate frontend / AI aliases → canonical `datasets.source` value. */
const SLUG_ALIASES: Record<string, string> = {
  cicids2017: "cicids2017",
  cicids: "cicids2017",
  cic_ids_2017: "cicids2017",
  "cic-ids-2017": "cicids2017",

  cse_cic_ids2018: "cse_cic_ids2018",
  cicids2018: "cse_cic_ids2018",
  cic_ids_2018: "cse_cic_ids2018",
  "cse-cic-ids2018": "cse_cic_ids2018",

  unsw_nb15: "unsw_nb15",
  unsw: "unsw_nb15",
  "unsw-nb15": "unsw_nb15",

  ton_iot: "ton_iot",
  ton_iot_live: "ton_iot",
  "ton-iot": "ton_iot",

  nsl_kdd: "nsl_kdd",
  darpa: "nsl_kdd",
  nslkdd: "nsl_kdd",
};

const DISPLAY_NAMES: Record<string, string> = {
  cicids2017: "CICIDS2017",
  cse_cic_ids2018: "CSE-CIC-IDS2018",
  unsw_nb15: "UNSW-NB15",
  ton_iot: "TON-IoT",
  nsl_kdd: "NSL-KDD",
};

export type ResolvedDataset = {
  id: string;
  source: string;
  name: string;
};

export function isUuid(value: string): boolean {
  return UUID_RE.test(value.trim());
}

export function normalizeDatasetSlug(raw: string): string {
  const key = raw.trim().toLowerCase().replace(/\s+/g, "_");
  return SLUG_ALIASES[key] ?? key;
}

/**
 * Resolve a client-provided datasetId (UUID or slug) to a DB row.
 * Creates a registry row for known slugs if missing so FK inserts succeed.
 */
export async function resolveDatasetRef(
  datasetRef: string | undefined | null,
  fallbackSlug = "cicids2017",
): Promise<ResolvedDataset> {
  const raw = (datasetRef ?? fallbackSlug).trim();
  if (!raw) {
    throw new Error("datasetId is required");
  }

  if (isUuid(raw)) {
    const [byId] = await db.select().from(datasets).where(eq(datasets.id, raw)).limit(1);
    if (!byId) {
      throw new Error(`Dataset UUID not found: ${raw}`);
    }
    return { id: byId.id, source: byId.source, name: byId.name };
  }

  const source = normalizeDatasetSlug(raw);
  const [existing] = await db.select().from(datasets).where(eq(datasets.source, source)).limit(1);
  if (existing) {
    return { id: existing.id, source: existing.source, name: existing.name };
  }

  // Auto-register known / requested slug so training & graph FK inserts work
  const [created] = await db
    .insert(datasets)
    .values({
      name: DISPLAY_NAMES[source] ?? source,
      source,
      fileType: "csv",
      status: "pending",
      metadata: { auto_registered: true, requested_as: raw },
    })
    .returning();

  return { id: created.id, source: created.source, name: created.name };
}
