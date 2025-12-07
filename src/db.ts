// Package Imports
import mysql, {
  type Pool,
  type PoolOptions,
  type ResultSetHeader,
  type RowDataPacket,
} from "mysql2/promise";

// Lib Imports
import type { User } from "./types.ts";

// Main
type PreparedEntries = { setExpr: string; values: unknown[] };

if (typeof Bun === "undefined") {
  throw new Error("The database layer requires the Bun runtime.");
}

let pool: Pool | null = null;
let dailyTimeoutId: ReturnType<typeof setTimeout> | null = null;

function isValidColName(name: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name);
}

function prepareUpdateEntries(
  data: Partial<User>
): PreparedEntries | TypeError | Error {
  if (!data || typeof data !== "object") {
    return new TypeError("data must be a non-null object");
  }

  const entries = Object.entries(data).filter(
    ([, value]) => value !== undefined
  );
  if (entries.length === 0) return { setExpr: "", values: [] };

  for (const [column] of entries) {
    if (!isValidColName(column)) {
      return new Error(
        `Invalid column name: "${column}". Allowed: [A-Za-z_][A-Za-z0-9_]*`
      );
    }
  }

  const setExpr = entries.map(([column]) => `\`${column}\` = ?`).join(", ");
  const values = entries.map(([, value]) => {
    if (value === null) return null;
    if (value instanceof Uint8Array) return value;
    if (typeof value === "object") return JSON.stringify(value);
    return value;
  });

  return { setExpr, values };
}

function ensureEnv(name: string, fallback?: string): string {
  const value = Bun.env[name] ?? fallback;
  if (value === undefined) {
    throw new Error(`Missing required environment variable ${name}`);
  }
  return value;
}

function toNumber(value: unknown): number {
  if (value === null || value === undefined) return 0;
  if (typeof value === "number") return value;
  if (typeof value === "bigint") return Number(value);
  const parsed = Number(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function requireString(value: unknown, field: string): string {
  if (typeof value === "string") return value;
  if (
    typeof value === "number" ||
    typeof value === "boolean" ||
    typeof value === "bigint"
  ) {
    return value.toString();
  }
  throw new TypeError(`${field} must be a string`);
}

function normalizeOptionalString(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value === "string") return value;
  if (
    typeof value === "number" ||
    typeof value === "boolean" ||
    typeof value === "bigint"
  ) {
    return value.toString();
  }
  return undefined;
}

function normalizeAvatar(value: unknown): Uint8Array | null {
  if (value === null || value === undefined) return null;
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer.slice(0));
  }
  if (typeof value === "string") {
    return new TextEncoder().encode(value);
  }
  return null;
}

function normalizeUserRow(row: Record<string, unknown>): User {
  return {
    id: toNumber(row.id),
    public_key: requireString(row.public_key, "public_key"),
    private_key_hash: requireString(row.private_key_hash, "private_key_hash"),
    iota_id: toNumber(row.iota_id),
    token: requireString(row.token, "token"),
    username: requireString(row.username, "username"),
    display: normalizeOptionalString(row.display),
    avatar: normalizeAvatar(row.avatar),
    about: normalizeOptionalString(row.about),
    status: normalizeOptionalString(row.status),
    sub_level: toNumber(row.sub_level),
    sub_end: toNumber(row.sub_end),
  };
}

function ensurePool(): Pool {
  if (!pool) {
    throw new Error("Database not initialized");
  }
  return pool;
}

export async function init(): Promise<void> {
  if (pool) {
    console.log("Database client already initialized.");
    return;
  }

  try {
    const config: PoolOptions = {
      host: Bun.env.DB_HOST ?? "127.0.0.1",
      user: ensureEnv("DB_USER"),
      password: Bun.env.DB_PASSWD ?? undefined,
      database: ensureEnv("DB_NAME"),
      port: Number(Bun.env.DB_PORT ?? "3306"),
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      connectTimeout: 30_000,
      charset: "utf8mb4",
    };

    pool = mysql.createPool(config);

    await createUsersTable();
    await createOmikronUUIDsTable();
    scheduleDailyJob();
    console.log("Database client initialized.");
  } catch (error) {
    if (pool) {
      await pool.end().catch((closeError: unknown) => {
        console.error("Failed to close pool after init error", closeError);
      });
      pool = null;
    }
    console.error(error);
    throw new Error("Database initialization failed");
  }
}

async function createUsersTable(): Promise<void> {
  const sql = `
    CREATE TABLE IF NOT EXISTS users (
      id BIGINT NOT NULL PRIMARY KEY,
      username VARCHAR(15) NOT NULL UNIQUE,
      display VARCHAR(15),
      status VARCHAR(15),
      about VARCHAR(200),
      avatar MEDIUMBLOB,
      sub_level INT NOT NULL,
      sub_end BIGINT NOT NULL,
      public_key TEXT NOT NULL,
      private_key_hash VARCHAR(64) NOT NULL,
      iota_id BIGINT NOT NULL,
      token VARCHAR(256) NOT NULL UNIQUE
    );
  `;

  try {
    await ensurePool().query(sql);
  } catch (error) {
    console.error(error);
    throw error;
  }
}

async function createOmikronUUIDsTable(): Promise<void> {
  const sql = `
    CREATE TABLE IF NOT EXISTS omikron_uuids (
      uuid VARCHAR(36) NOT NULL PRIMARY KEY UNIQUE,
      identification VARCHAR(255) NOT NULL,
      ip VARCHAR(45) NOT NULL
    );
  `;

  try {
    await ensurePool().query(sql);
  } catch (error) {
    console.error(error);
    throw error;
  }
}

export async function add(
  id: number,
  public_key: string,
  private_key_hash: string,
  username: string,
  token: string,
  iota_id: number
): Promise<string | Error> {
  try {
    const [result] = await ensurePool().execute<ResultSetHeader>(
      `
        INSERT INTO users (
          id, public_key, private_key_hash, username, token, iota_id,
          display, avatar, about, status, sub_level, sub_end
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
      `,
      [
        id,
        public_key,
        private_key_hash,
        username,
        token,
        iota_id,
        "",
        null,
        "",
        "",
        0,
        0,
      ]
    );
    return result.affectedRows === 1
      ? "Created User"
      : new Error("Insert failed");
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error));
  }
}

export async function remove(
  id: number,
  token: string
): Promise<string | Error> {
  try {
    const [rows] = await ensurePool().execute<RowDataPacket[]>(
      "SELECT token FROM users WHERE id = ?",
      [id]
    );

    if (rows.length === 0) {
      return new Error("ID not found.");
    }

    const row = rows[0] as RowDataPacket & { token: unknown };
    if (row.token !== token) {
      return new Error("Bad Token");
    }

    await ensurePool().execute("DELETE FROM users WHERE id = ?", [id]);
    return "Deleted User";
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error));
  }
}

export async function id(username: string): Promise<number | Error> {
  try {
    const [rows] = await ensurePool().execute<RowDataPacket[]>(
      "SELECT id FROM users WHERE username = ?",
      [username]
    );

    if (rows.length === 0) {
      return new Error("ID not found.");
    }

    const row = rows[0] as RowDataPacket & { id: unknown };
    return toNumber(row.id);
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error));
  }
}

export async function get(id: number): Promise<User | null | Error> {
  try {
    const [rows] = await ensurePool().execute<RowDataPacket[]>(
      "SELECT * FROM users WHERE id = ?",
      [id]
    );

    const row = rows?.[0] as RowDataPacket | undefined;
    if (!row) return null;
    return normalizeUserRow(row as Record<string, unknown>);
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error));
  }
}

export async function update(
  id: number,
  data: Partial<User>
): Promise<boolean | Error> {
  try {
    const prepared = prepareUpdateEntries(data);
    if (prepared instanceof Error) return prepared;

    const { setExpr, values } = prepared;
    if (!setExpr) return false;

    const [result] = await ensurePool().execute<ResultSetHeader>(
      `UPDATE users SET ${setExpr} WHERE \`id\` = ?`,
      [...values, id]
    );

    return (result.affectedRows ?? 0) > 0;
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error));
  }
}

export async function checkLegitimacy(uuid: string): Promise<boolean | Error> {
  try {
    const [rows] = await ensurePool().execute<RowDataPacket[]>(
      "SELECT uuid FROM omikron_uuids WHERE uuid = ?",
      [uuid]
    );

    if (rows.length === 0) {
      return new Error("UUID not found.");
    }

    const row = rows[0] as RowDataPacket & { uuid: unknown };
    return String(row.uuid) === uuid;
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error));
  }
}

export async function close(): Promise<void> {
  if (dailyTimeoutId !== null) {
    clearTimeout(dailyTimeoutId);
    dailyTimeoutId = null;
  }

  if (pool) {
    await pool.end();
    pool = null;
    console.log("Database client closed.");
  }
}

async function removeOneDayFromEverySubscription(): Promise<void> {
  const now = new Date();
  console.log(
    `Removed 1 day from all subscriptions at ${now.toISOString()} (local time: ${now.toLocaleString()}).`
  );

  try {
    await ensurePool().execute(
      `UPDATE users SET sub_end = GREATEST(0, sub_end - 1);`
    );
    await ensurePool().execute(
      `UPDATE users SET sub_level = 0 WHERE sub_end = 0;`
    );
  } catch (error) {
    console.error("Failed to decrement subscriptions", error);
  }
}

function scheduleDailyJob(): void {
  try {
    const now = new Date();
    const next = new Date(now);
    next.setUTCHours(0, 0, 0, 0);
    if (next.getTime() <= now.getTime()) {
      next.setUTCDate(next.getUTCDate() + 1);
    }

    const kickoffDelay = next.getTime() - now.getTime();
    const oneDayMs = 24 * 60 * 60 * 1000;

    const scheduleNextRun = () => {
      dailyTimeoutId = setTimeout(() => {
        void runJob();
      }, oneDayMs);
    };

    const runJob = async () => {
      try {
        await removeOneDayFromEverySubscription();
      } finally {
        scheduleNextRun();
      }
    };

    dailyTimeoutId = setTimeout(() => {
      void (async () => {
        try {
          await runJob();
        } catch (error) {
          console.error("Error in scheduled daily job", error);
        }
      })();
    }, kickoffDelay);

    console.log("Scheduler started. Job runs daily at 00:00 UTC.");
  } catch (error) {
    console.error("Failed to schedule daily job", error);
  }
}
