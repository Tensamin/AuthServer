import mysql from "mysql2/promise";
import "dotenv/config";
import * as schedule from "node-schedule"

let pool;

export async function init() {
  if (pool) {
    console.log('Database pool already initialized.');
    return;
  }

  try {
    pool = mysql.createPool({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWD,
      database: process.env.DB_NAME,
      port: process.env.DB_PORT,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });

    await createUsersTable();
    await createOmikronUUIDsTable();
    console.log('Database pool initialized.');
  } catch (err) {
    console.error('Failed to initialize database pool:', err);
    throw new Error('Database initialization failed.');
  };
};

async function createUsersTable() {
  let createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      uuid VARCHAR(36) NOT NULL PRIMARY KEY,
      public_key TEXT NOT NULL,
      private_key_hash VARCHAR(128) NOT NULL,
      iota_id VARCHAR(255) NOT NULL,
      token VARCHAR(255) NOT NULL UNIQUE,
      username VARCHAR(15) NOT NULL UNIQUE,
      created_at BIGINT NOT NULL,
      display VARCHAR(15),
      avatar MEDIUMTEXT,
      about VARCHAR(200),
      status VARCHAR(15),
      sub_level INT NOT NULL,
      sub_end BIGINT NOT NULL,
      salt TEXT,
      current_challenge TEXT,
      credentials TEXT
    );
  `;
  try {
    let connection = await pool.getConnection();
    await connection.execute(createTableQuery);
    connection.release();
  } catch (err) {
    console.error('Error creating users table:', err);
    throw err;
  };
};

async function createOmikronUUIDsTable() {
  let createOmikronUUIDsTableQuery = `
    CREATE TABLE IF NOT EXISTS omikron_uuids (
      uuid VARCHAR(36) NOT NULL PRIMARY KEY UNIQUE,
      identification VARCHAR(255) NOT NULL,
      ip VARCHAR(45) NOT NULL
    );
  `;
  try {
    let connection = await pool.getConnection();
    await connection.execute(createOmikronUUIDsTableQuery);
    connection.release();
  } catch (err) {
    console.error('Error creating users table:', err);
    throw err;
  };
};

export async function add(uuid, public_key, private_key_hash, username, token, iota_id, created_at) {
  try {
    let connection = await pool.getConnection();
    await connection.execute(`
    INSERT INTO users (uuid, public_key, private_key_hash, username, token, iota_id, created_at, display, avatar, about, status, sub_level, sub_end)
    VALUES (?, ?, ?, ?, ?, ?, ?, ? ,? ,? ,?, ?, ?);
  `, [uuid, public_key, private_key_hash, username, token, iota_id, created_at, "", "", "", "", 0, 0]);
    connection.release();

    return "Created User";
  } catch (err) {
    throw new Error(err.message);
  };
};

export async function remove(uuid, token) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(
      'SELECT token FROM users WHERE uuid = ?',
      [uuid]
    );
    connection.release();

    if (rows.length === 0) {
      throw new Error('UUID not found.');
    };

    if (rows[0].token !== token) {
      throw new Error('Bad Token');
    };

    await connection.execute('DELETE FROM users WHERE uuid = ?', [uuid]);
    return "Deleted User";
  } catch (err) {
    throw new Error(err.message);
  };
};

export async function uuid(username) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(`SELECT uuid FROM users WHERE username = ?;`, [username]);
    connection.release();

    if (rows.length === 0) {
      throw new Error('UUID not found.')
    };

    return rows[0].uuid;
  } catch (err) {
    throw new Error(err.message);
  };
};

export async function get(uuid) {
  let connection;

  try {
    if (!uuid || typeof uuid !== "string") {
      throw new Error("uuid is required.");
    }

    connection = await pool.getConnection();

    const [rows, fields] = await connection.execute(
      `SELECT * FROM users WHERE uuid = ?;`,
      [uuid]
    );

    if (!Array.isArray(rows) || rows.length === 0) {
      throw new Error("UUID not found.");
    }

    const row = rows[0];

    const MYSQL_TYPE = {
      DECIMAL: 0,
      TINY: 1,
      SHORT: 2,
      LONG: 3,
      FLOAT: 4,
      DOUBLE: 5,
      NULL: 6,
      TIMESTAMP: 7,
      LONGLONG: 8,
      INT24: 9,
      DATE: 10,
      TIME: 11,
      DATETIME: 12,
      YEAR: 13,
      NEWDATE: 14,
      VARCHAR: 15,
      BIT: 16,
      JSON: 245,
      NEWDECIMAL: 246,
      ENUM: 247,
      SET: 248,
      TINY_BLOB: 249,
      MEDIUM_BLOB: 250,
      LONG_BLOB: 251,
      BLOB: 252,
      VAR_STRING: 253,
      STRING: 254,
      GEOMETRY: 255
    };

    const parseBitBuffer = (buf) => {
      let n = 0;
      for (let i = 0; i < buf.length; i++) {
        n = (n << 8) + buf[i];
      }
      return n;
    };

    const normalizeValue = (val, field) => {
      if (val === null) return null;

      const ct = field.columnType;
      const len = field.columnLength || field.length || null;

      if (ct === MYSQL_TYPE.JSON) {
        if (Buffer.isBuffer(val)) {
          try {
            return JSON.parse(val.toString("utf8"));
          } catch (e) {
            return val.toString("utf8");
          }
        }
        if (typeof val === "string") {
          try {
            return JSON.parse(val);
          } catch (e) {
            return val;
          }
        }
        return val;
      }

      if (ct === MYSQL_TYPE.BIT) {
        if (Buffer.isBuffer(val)) {
          const n = parseBitBuffer(val);
          return val.length === 1 ? Boolean(n) : n;
        }
        if (typeof val === "number") {
          return val === 1 ? true : val === 0 ? false : val;
        }
        if (typeof val === "string") {
          if (val === "0") return false;
          if (val === "1") return true;
          const n = Number(val);
          return Number.isNaN(n) ? val : n;
        }
        return val;
      }

      if (ct === MYSQL_TYPE.TINY) {
        if (len === 1) {
          if (typeof val === "number") return Boolean(val);
          if (typeof val === "string") return val === "1";
          if (Buffer.isBuffer(val)) return val[0] === 1;
        }
        if (typeof val === "string" && /^-?\d+$/.test(val)) {
          const n = Number(val);
          return Number.isSafeInteger(n) ? n : val;
        }
        return val;
      }

      if (
        [MYSQL_TYPE.SHORT, MYSQL_TYPE.LONG, MYSQL_TYPE.LONGLONG,
         MYSQL_TYPE.INT24].includes(ct)
      ) {
        if (typeof val === "string" && /^-?\d+$/.test(val)) {
          const n = Number(val);
          return Number.isSafeInteger(n) ? n : val;
        }
        if (Buffer.isBuffer(val)) {
          return parseBitBuffer(val);
        }
        return val;
      }

      if ([MYSQL_TYPE.DECIMAL, MYSQL_TYPE.NEWDECIMAL].includes(ct)) {
        if (typeof val === "string") {
          const n = Number(val);
          return Number.isFinite(n) ? n : val;
        }
        return val;
      }

      if (
        [MYSQL_TYPE.TIMESTAMP, MYSQL_TYPE.DATE, MYSQL_TYPE.TIME,
         MYSQL_TYPE.DATETIME, MYSQL_TYPE.YEAR, MYSQL_TYPE.NEWDATE]
         .includes(ct)
      ) {
        if (val instanceof Date) return val.toISOString();
        if (typeof val === "string") {
          const d = new Date(val);
          if (!Number.isNaN(d.getTime())) return d.toISOString();
          return val;
        }
        return val;
      }

      return val;
    };

    const normalized = {};
    for (const f of fields) {
      const name = f.name || f.orgName;
      normalized[name] = normalizeValue(row[name], f);
    }

    return normalized;
  } catch (err) {
    throw new Error(err.message);
  } finally {
    if (connection) connection.release();
  }
};

export async function update(uuid, user) {
  let connection;

  try {
    if (!uuid || typeof uuid !== 'string') {
      throw new Error('uuid is required.');
    }

    let ALLOWED_USER_FIELDS = new Set([
      'uuid',
      'public_key',
      'private_key_hash',
      'iota_id',
      'token',
      'username',
      'created_at',
      'display',
      'avatar',
      'status',
      'sub_level',
      'sub_end',
      'salt',
      'current_challenge',
      'credentials'
    ]);

    let fields = Object.keys(user || {}).filter(
      (k) =>
        k !== 'uuid' &&
        user[k] !== undefined &&
        ALLOWED_USER_FIELDS.has(k)
    );

    if (fields.length === 0) {
      return 'Nothing to update.';
    }

    let serializeParam = (v) => {
      if (v === undefined || v === null) return null;
      if (typeof v === 'bigint') return v.toString();
      if (typeof v === 'boolean') return v ? 1 : 0;
      if (Buffer.isBuffer(v)) return v;
      if (v instanceof Date) return v;
      if (typeof v === 'object') return JSON.stringify(v);
      return v;
    };

    let placeholders = fields.map((k) => `\`${k}\` = ?`).join(', ');
    let values = fields.map((k) => serializeParam(user[k]));

    connection = await pool.getConnection();

    let [existsRows] = await connection.execute(
      'SELECT 1 FROM `users` WHERE `uuid` = ? LIMIT 1',
      [serializeParam(uuid)]
    );

    if (!Array.isArray(existsRows) || existsRows.length === 0) {
      throw new Error('UUID not found.');
    }

    let [result] = await connection.execute(
      `UPDATE \`users\` SET ${placeholders} WHERE \`uuid\` = ?`,
      [...values, serializeParam(uuid)]
    );

    if (result.changedRows === 0) {
      return 'No changes.';
    }

    return 'User updated.';
  } catch (err) {
    throw err;
  } finally {
    if (connection) connection.release();
  }
}

export async function checkLegitimacy(uuid) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(
      `SELECT uuid FROM omikron_uuids WHERE uuid = ?;`,
      [uuid]
    );
    connection.release();

    if (rows.length === 0) {
      throw new Error('UUID not found.')
    }

    return rows[0].uuid === uuid;
  } catch (err) {
    throw new Error(err.message);
  }
}

export async function close() {
  if (pool) {
    await pool.end();
    console.log('Database connection pool closed.');
    pool = null;
    process.exit(0);
  };
};

async function removeOneDayFromEverySubscription() {
  let now = new Date();
  console.log(`Removed 1 day from all subscriptions at ${now.toISOString()} (local time: ${now.toLocaleString()}).`)
  try {
    let connection = await pool.getConnection();
    await connection.execute(`UPDATE users
SET sub_end = GREATEST(0, sub_end - 1);`, []);
    await connection.execute(`UPDATE users
SET sub_level = 0
WHERE sub_end = 0;`, []);
    connection.release();
  } catch (err) {
    console.error(err)
  }
};

let job = schedule.scheduleJob({ hour: 0, minute: 0 }, function () {
  removeOneDayFromEverySubscription();
});

console.log('Node.js scheduler started.');
console.log('Job scheduled to run every day at 00:00 UTC.');
console.log('Next scheduled invocation:', job.nextInvocation().toISOString());