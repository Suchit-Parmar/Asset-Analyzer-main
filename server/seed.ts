import { eq } from "drizzle-orm";
import { db } from "./db";
import { roles, users, datasets } from "@shared/schema";
import { hashPassword, ROLE_PERMISSIONS } from "./auth";

export async function seedDatabase() {
  console.log("[seed] Initializing database...");

  const roleDefinitions = [
    { name: "admin" as const, description: "Full system administrator", permissions: ROLE_PERMISSIONS.admin },
    { name: "analyst" as const, description: "Security analyst with full SOC access", permissions: ROLE_PERMISSIONS.analyst },
    { name: "operator" as const, description: "SOC operator", permissions: ROLE_PERMISSIONS.operator },
    { name: "viewer" as const, description: "Read-only dashboard access", permissions: ROLE_PERMISSIONS.viewer },
  ];

  for (const roleDef of roleDefinitions) {
    const existing = await db.select().from(roles).where(eq(roles.name, roleDef.name)).limit(1);
    if (!existing.length) {
      await db.insert(roles).values(roleDef);
      console.log(`[seed] Created role: ${roleDef.name}`);
    }
  }

  const [adminRole] = await db.select().from(roles).where(eq(roles.name, "admin")).limit(1);
  if (!adminRole) throw new Error("Admin role not found after seed");

  const adminEmail = "admin@gnn-ids.local";
  const existingAdmin = await db.select().from(users).where(eq(users.email, adminEmail)).limit(1);

  if (!existingAdmin.length) {
    const { OTP } = await import("otplib");
    const otp = new OTP({ strategy: "totp" });
    await db.insert(users).values({
      email: adminEmail,
      name: "System Administrator",
      passwordHash: await hashPassword("Admin@123456"),
      roleId: adminRole.id,
      emailVerified: true,
      totpSecret: otp.generateSecret(),
    });
    console.log("[seed] Created admin user: admin@gnn-ids.local / Admin@123456");
  }

  const datasetSources = [
    { name: "UNSW-NB15", source: "unsw_nb15", fileType: "csv" },
    { name: "CICIDS2017", source: "cicids2017", fileType: "csv" },
    { name: "CSE-CIC-IDS2018", source: "cse_cic_ids2018", fileType: "csv" },
    { name: "TON-IoT", source: "ton_iot", fileType: "csv" },
    { name: "NSL-KDD", source: "nsl_kdd", fileType: "csv" },
  ];

  for (const ds of datasetSources) {
    const existing = await db.select().from(datasets).where(eq(datasets.source, ds.source)).limit(1);
    if (!existing.length) {
      await db.insert(datasets).values({
        name: ds.name,
        source: ds.source,
        fileType: ds.fileType,
        status: "pending",
        metadata: { auto_registered: true },
      });
      console.log(`[seed] Registered dataset: ${ds.name}`);
    }
  }

  console.log("[seed] Database initialization complete");
}

/** True when this file is executed directly (e.g. `npm run db:seed` / `tsx server/seed.ts`). */
function isSeedCliEntry(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  return /(?:^|[/\\])seed\.(ts|js|mts|cts|cjs|mjs)$/i.test(entry);
}

if (isSeedCliEntry()) {
  seedDatabase()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error("[seed] Failed:", err);
      process.exit(1);
    });
}
