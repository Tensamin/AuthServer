import mysql from "mysql2/promise";
import "dotenv/config";
import * as schedule from "node-schedule"

let pool;

// Helper Functions
function isValidColName(name) {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name);
}

function prepareUpdateEntries(data) {
  if (!data || typeof data !== 'object') {
    throw new TypeError('data must be a non-null object');
  }

  let entries = Object.entries(data).filter(([, v]) => v !== undefined);
  if (entries.length === 0) return { setExpr: '', values: [] };

  for (let [k] of entries) {
    if (!isValidColName(k)) {
      throw new Error(
        `Invalid column name: "${k}". Allowed: [A-Za-z_][A-Za-z0-9_]*`
      );
    }
  }

  let setExpr = entries.map(([k]) => `\`${k}\` = ?`).join(', ');
  let values = entries.map(([, v]) =>
    v === null ? null : typeof v === 'object' ? JSON.stringify(v) : v
  );

  return { setExpr, values };
}

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
      lambda TEXT,
      current_challenge TEXT,
      credentials LONGTEXT
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
    INSERT INTO users (uuid, public_key, private_key_hash, username, token, iota_id, created_at, display, avatar, about, status, sub_level, sub_end, lambda, current_challenge)
    VALUES (?, ?, ?, ?, ?, ?, ?, ? ,? ,? ,?, ?, ?);
  `, [uuid, public_key, private_key_hash, username, token, iota_id, created_at, "", "", "", "", 0, 0, "", ""]);
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
    connection = await pool.getConnection();
    let [rows] = await connection.execute(
      'SELECT * FROM users WHERE uuid = ?',
      [uuid]
    );

    let row = rows?.[0] ?? null;
    if (!row) return null;

    delete row.uuid;
    return row;
  } catch (err) {
    throw err;
  } finally {
    if (connection) connection.release();
  }
}

export async function update(uuid, data) {
  let connection;
  try {
    let { setExpr, values } = prepareUpdateEntries(data);
    if (!setExpr) return false;

    let placeholderCount = (setExpr.match(/\?/g) || []).length;
    if (placeholderCount !== values.length) {
      throw new Error(
        `Placeholder/value mismatch: ${placeholderCount} placeholders ` +
        `but ${values.length} values`
      );
    }

    connection = await pool.getConnection();

    let [result] = await connection.execute(
      "UPDATE users SET " + setExpr + " WHERE `uuid` = ?",
      [...values, uuid]
    );
    return result.affectedRows > 0;
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