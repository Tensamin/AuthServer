// Imports
import mysql from "mysql2/promise";
import "dotenv/config";
import * as schedule from "node-schedule";

// Types
import type {
  Pool,
  RowDataPacket,
  PoolConnection,
  ResultSetHeader,
} from "mysql2/promise";

export type User = {
  uuid?: string;
  public_key: string;
  private_key_hash: string;
  iota_id: string;
  token: string;
  username: string;
  created_at: number;
  display?: string;
  avatar?: Buffer;
  about?: string;
  status?: string;
  sub_level: number;
  sub_end: number;
};

// Database Pool
let pool: Pool | null = null;

// Helper Functions
function isValidColName(name: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name);
}

function prepareUpdateEntries(
  data: Partial<User>
): { setExpr: string; values: any[] } | TypeError | Error {
  if (!data || typeof data !== "object") {
    return new TypeError("data must be a non-null object");
  }

  let entries = Object.entries(data).filter(([, v]) => v !== undefined);
  if (entries.length === 0) return { setExpr: "", values: [] };

  for (let [k] of entries) {
    if (!isValidColName(k)) {
      return new Error(
        `Invalid column name: "${k}". Allowed: [A-Za-z_][A-Za-z0-9_]*`
      );
    }
  }

  let setExpr = entries.map(([k]) => `\`${k}\` = ?`).join(", ");
  let values = entries.map(([, v]) =>
    v === null ? null : typeof v === "object" ? JSON.stringify(v) : v
  );

  return { setExpr, values };
}

export async function init(): Promise<void> {
  if (pool) {
    console.log("Database pool already initialized.");
    return;
  }

  try {
    pool = mysql.createPool({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWD,
      database: process.env.DB_NAME,
      port: parseInt(process.env.DB_PORT || "3306", 10),
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });

    await createUsersTable();
    await createOmikronUUIDsTable();
    console.log("Database pool initialized.");
  } catch (err) {
    console.error("Failed to initialize database pool:", err);
    throw new Error("Database initialization failed.");
  }
}

async function createUsersTable(): Promise<void> {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      uuid VARCHAR(36) NOT NULL PRIMARY KEY,
      public_key TEXT NOT NULL,
      private_key_hash VARCHAR(64) NOT NULL,
      iota_id VARCHAR(36) NOT NULL,
      token VARCHAR(256) NOT NULL UNIQUE,
      username VARCHAR(15) NOT NULL UNIQUE,
      created_at BIGINT NOT NULL,
      display VARCHAR(15),
      avatar MEDIUMBLOB,
      about VARCHAR(268),
      status VARCHAR(15),
      sub_level INT NOT NULL,
      sub_end BIGINT NOT NULL
    );
  `;
  let connection: PoolConnection | null = null;
  try {
    if (!pool) throw new Error("Database not initialized");
    connection = await pool.getConnection();
    await connection.execute(createTableQuery);
  } catch (err) {
    console.error("Error creating users table:", err);
    throw err;
  } finally {
    if (connection) connection.release();
  }
}

async function createOmikronUUIDsTable(): Promise<void> {
  const createOmikronUUIDsTableQuery = `
    CREATE TABLE IF NOT EXISTS omikron_uuids (
      uuid VARCHAR(36) NOT NULL PRIMARY KEY UNIQUE,
      identification VARCHAR(255) NOT NULL,
      ip VARCHAR(45) NOT NULL
    );
  `;
  let connection: PoolConnection | null = null;
  try {
    if (!pool) throw new Error("Database not initialized");
    connection = await pool.getConnection();
    await connection.execute(createOmikronUUIDsTableQuery);
  } catch (err) {
    console.error("Error creating omikron_uuids table:", err);
    throw err;
  } finally {
    if (connection) connection.release();
  }
}

export async function add(
  uuid: string,
  public_key: string,
  private_key_hash: string,
  username: string,
  token: string,
  iota_id: string,
  created_at: number
): Promise<string | Error> {
  let connection: PoolConnection | null = null;
  try {
    if (!pool) throw new Error("Database not initialized");
    connection = await pool.getConnection();
    await connection.execute(
      `
    INSERT INTO users (uuid, public_key, private_key_hash, username, token, iota_id, created_at, display, avatar, about, status, sub_level, sub_end)
    VALUES (?, ?, ?, ?, ?, ?, ?, ? ,? ,? ,?, ?, ?);
  `,
      [
        uuid,
        public_key,
        private_key_hash,
        username,
        token,
        iota_id,
        created_at,
        "",
        "",
        "",
        "",
        0,
        0,
      ]
    );
    return "Created User";
  } catch (err) {
    return err instanceof Error ? err : new Error(String(err));
  } finally {
    if (connection) connection.release();
  }
}

export async function remove(
  uuid: string,
  token: string
): Promise<string | Error> {
  let connection: PoolConnection | null = null;
  try {
    if (!pool) throw new Error("Database not initialized");
    connection = await pool.getConnection();
    interface TokenRow extends RowDataPacket {
      token: string;
    }
    const [rows] = await connection.execute<TokenRow[]>(
      "SELECT token FROM users WHERE uuid = ?",
      [uuid]
    );

    if (rows.length === 0) {
      return new Error("UUID not found.");
    }

    if (rows[0].token !== token) {
      return new Error("Bad Token");
    }

    await connection.execute("DELETE FROM users WHERE uuid = ?", [uuid]);
    return "Deleted User";
  } catch (err) {
    return err instanceof Error ? err : new Error(String(err));
  } finally {
    if (connection) connection.release();
  }
}

export async function uuid(username: string): Promise<string | Error> {
  let connection: PoolConnection | null = null;
  try {
    if (!pool) throw new Error("Database not initialized");
    connection = await pool.getConnection();
    interface UuidRow extends RowDataPacket {
      uuid: string;
    }
    const [rows] = await connection.execute<UuidRow[]>(
      `SELECT uuid FROM users WHERE username = ?;`,
      [username]
    );

    if (rows.length === 0) {
      return new Error("UUID not found.");
    }

    return rows[0].uuid;
  } catch (err) {
    return err instanceof Error ? err : new Error(String(err));
  } finally {
    if (connection) connection.release();
  }
}

export async function get(uuid: string): Promise<User | null | Error> {
  let connection: PoolConnection | null = null;
  try {
    if (!pool) throw new Error("Database not initialized");
    connection = await pool.getConnection();
    type UserRow = RowDataPacket & User;
    const [rows] = await connection.execute<UserRow[]>(
      "SELECT * FROM users WHERE uuid = ?",
      [uuid]
    );

    const row = rows?.[0];
    if (!row) return null;

    // Remove uuid from the result before returning
    delete row.uuid;
    return row;
  } catch (err) {
    return err instanceof Error ? err : new Error(String(err));
  } finally {
    if (connection) connection.release();
  }
}

export async function update(
  uuid: string,
  data: Partial<User>
): Promise<boolean | Error> {
  let connection: PoolConnection | null = null;
  try {
    const prepared = prepareUpdateEntries(data);
    if (prepared instanceof Error) return prepared;

    const { setExpr, values } = prepared;
    if (!setExpr) return false;

    const placeholderCount = (setExpr.match(/\?/g) || []).length;
    if (placeholderCount !== values.length) {
      return new Error(
        `Placeholder/value mismatch: ${placeholderCount} placeholders ` +
          `but ${values.length} values`
      );
    }

    if (!pool) throw new Error("Database not initialized");
    connection = await pool.getConnection();

    const [result] = await connection.execute<ResultSetHeader>(
      "UPDATE users SET " + setExpr + " WHERE `uuid` = ?",
      [...values, uuid]
    );
    return result.affectedRows > 0;
  } catch (err) {
    return err instanceof Error ? err : new Error(String(err));
  } finally {
    if (connection) connection.release();
  }
}

export async function checkLegitimacy(uuid: string): Promise<boolean | Error> {
  let connection: PoolConnection | null = null;
  try {
    if (!pool) throw new Error("Database not initialized");
    connection = await pool.getConnection();
    interface LegitRow extends RowDataPacket {
      uuid: string;
    }
    const [rows] = await connection.execute<LegitRow[]>(
      `SELECT uuid FROM omikron_uuids WHERE uuid = ?;`,
      [uuid]
    );

    if (rows.length === 0) {
      return new Error("UUID not found.");
    }

    return rows[0].uuid === uuid;
  } catch (err) {
    return err instanceof Error ? err : new Error(String(err));
  } finally {
    if (connection) connection.release();
  }
}

export async function close(): Promise<void> {
  if (pool) {
    await pool.end();
    console.log("Database connection pool closed.");
    pool = null;
    process.exit(0);
  }
}

async function removeOneDayFromEverySubscription(): Promise<void> {
  const now = new Date();
  console.log(
    `Removed 1 day from all subscriptions at ${now.toISOString()} (local time: ${now.toLocaleString()}).`
  );
  try {
    if (!pool) {
      console.warn(
        "Database not initialized; skipping subscription decrement job."
      );
      return;
    }
    let connection: PoolConnection | null = null;
    try {
      connection = await pool.getConnection();
      await connection.execute(
        `UPDATE users
SET sub_end = GREATEST(0, sub_end - 1);`,
        []
      );
      await connection.execute(
        `UPDATE users
SET sub_level = 0
WHERE sub_end = 0;`,
        []
      );
    } finally {
      if (connection) connection.release();
    }
  } catch (err) {
    console.error(err);
  }
}

let job: schedule.Job;
try {
  job = schedule.scheduleJob({ hour: 0, minute: 0 }, function () {
    removeOneDayFromEverySubscription();
  });
  console.log("Node.js scheduler started.");
  console.log("Job scheduled to run every day at 00:00 UTC.");
  if (job && typeof job.nextInvocation === "function") {
    const next = job.nextInvocation();
    if (next instanceof Date) {
      console.log("Next scheduled invocation:", next.toISOString());
    }
  }
} catch (e) {
  const msg = e instanceof Error ? e.message : String(e);
  console.warn("Scheduler setup failed:", msg);
}
