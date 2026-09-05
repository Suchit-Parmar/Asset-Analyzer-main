import { existsSync } from "fs";
import { resolve } from "path";
import { execSync } from "child_process";
import net from "net";
import pg from "pg";

const DEFAULT_URL = "postgresql://gnn_ids:gnn_ids_secret@localhost:5432/gnn_ids";
const EMBEDDED_PORT = 5432;
const EMBEDDED_USER = "gnn_ids";
const EMBEDDED_PASSWORD = "gnn_ids_secret";
const EMBEDDED_DB = "gnn_ids";

function canConnect(host: string, port: number, timeoutMs = 1500): Promise<boolean> {
  return new Promise((resolvePromise) => {
    const socket = net.createConnection({ host, port });
    const done = (ok: boolean) => {
      socket.removeAllListeners();
      socket.destroy();
      resolvePromise(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
  });
}

async function canQuery(connectionString: string): Promise<boolean> {
  const client = new pg.Client({ connectionString, connectionTimeoutMillis: 2000 });
  try {
    await client.connect();
    await client.query("SELECT 1");
    return true;
  } catch {
    return false;
  } finally {
    await client.end().catch(() => undefined);
  }
}

async function startEmbeddedPostgres(): Promise<{ url: string; isFresh: boolean }> {
  const EmbeddedPostgres = (await import("embedded-postgres")).default;
  const databaseDir = resolve(process.cwd(), "data", "embedded-pg");
  const alreadyInitialized = existsSync(resolve(databaseDir, "PG_VERSION"));

  const embedded = new EmbeddedPostgres({
    databaseDir,
    user: EMBEDDED_USER,
    password: EMBEDDED_PASSWORD,
    port: EMBEDDED_PORT,
    persistent: true,
    onLog: (message) => {
      const text = String(message).trim();
      // Suppress benign "CREATE DATABASE" already-exists noise on restart.
      if (
        !text ||
        /database "gnn_ids" already exists/i.test(text) ||
        /STATEMENT:\s*CREATE DATABASE "gnn_ids"/i.test(text)
      ) {
        return;
      }
      console.log(`[embedded-pg] ${text}`);
    },
    onError: (message) => {
      const text = String(message).trim();
      // Benign on restarts — DB is created only once.
      if (
        !text ||
        /database "gnn_ids" already exists/i.test(text) ||
        /STATEMENT:\s*CREATE DATABASE "gnn_ids"/i.test(text)
      ) {
        return;
      }
      console.error(`[embedded-pg] ${text}`);
    },
  });

  if (!alreadyInitialized) {
    console.log("[ensure-db] Initializing embedded PostgreSQL (first run)...");
    await embedded.initialise();
  }

  console.log("[ensure-db] Starting embedded PostgreSQL on port", EMBEDDED_PORT);
  await embedded.start();

  const url = `postgresql://${EMBEDDED_USER}:${EMBEDDED_PASSWORD}@127.0.0.1:${EMBEDDED_PORT}/${EMBEDDED_DB}`;
  // Prefer connect-check over CREATE — avoids noisy "already exists" ERROR logs on restart.
  if (await canQuery(url)) {
    console.log(`[ensure-db] Database "${EMBEDDED_DB}" already exists — reusing`);
  } else {
    try {
      await embedded.createDatabase(EMBEDDED_DB);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (!/already exists/i.test(msg)) throw err;
      console.log(`[ensure-db] Database "${EMBEDDED_DB}" already exists — reusing`);
    }
  }
  process.env.DATABASE_URL = url;

  const shutdown = async () => {
    try {
      await embedded.stop();
    } catch {
      // ignore
    }
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
  process.once("exit", () => {
    void shutdown();
  });

  return { url, isFresh: !alreadyInitialized };
}

async function schemaExists(connectionString: string): Promise<boolean> {
  const client = new pg.Client({ connectionString, connectionTimeoutMillis: 3000 });
  try {
    await client.connect();
    const result = await client.query(
      `SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users' LIMIT 1`,
    );
    return result.rowCount !== null && result.rowCount > 0;
  } catch {
    return false;
  } finally {
    await client.end().catch(() => undefined);
  }
}

function pushSchema(connectionString: string) {
  console.log("[ensure-db] Applying database schema...");
  execSync("npx drizzle-kit push --force", {
    stdio: "inherit",
    env: { ...process.env, DATABASE_URL: connectionString },
    cwd: process.cwd(),
  });
}

export async function ensureDatabase(): Promise<void> {
  const configuredUrl = process.env.DATABASE_URL || DEFAULT_URL;
  process.env.DATABASE_URL = configuredUrl;

  const portOpen = await canConnect("127.0.0.1", EMBEDDED_PORT);
  if (portOpen && (await canQuery(configuredUrl))) {
    console.log("[ensure-db] Connected to existing PostgreSQL");
    return;
  }

  if (portOpen) {
    throw new Error(
      `Port ${EMBEDDED_PORT} is in use but DATABASE_URL is not reachable. ` +
        `Fix PostgreSQL credentials or free the port.`,
    );
  }

  console.log("[ensure-db] No PostgreSQL detected — starting embedded instance");
  const { url } = await startEmbeddedPostgres();
  if (!(await schemaExists(url))) {
    pushSchema(url);
  } else {
    console.log("[ensure-db] Schema already present — skipping push");
  }
  console.log("[ensure-db] Embedded PostgreSQL is ready");
}
