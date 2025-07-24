import mysql from 'mysql2/promise';
import 'dotenv/config';

let pool;

async function init() {
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
      username VARCHAR(255) NOT NULL UNIQUE,
      created_at VARCHAR(255) NOT NULL,
      display VARCHAR(255),
      avatar TEXT,
      about VARCHAR(200),
      status VARCHAR(35)
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

// Main Stuff

async function addUser(uuid, public_key, private_key_hash, username, token, iota_id, created_at) {
  try {
    let connection = await pool.getConnection();
    await connection.execute(`
    INSERT INTO users (uuid, public_key, private_key_hash, username, token, iota_id, created_at, display, avatar, about, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ? ,? ,? ,?);
  `, [uuid, public_key, private_key_hash, username, token, iota_id, created_at, "", "", "", ""]);
    connection.release();

    return { success: true, message: "Created User" };
  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function removeUser(uuid, token) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(
      'SELECT token FROM users WHERE uuid = ?',
      [uuid]
    );
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    if (rows[0].token !== token) {
      return { success: false, message: 'Bad Token' };
    };

    await connection.execute('DELETE FROM users WHERE uuid = ?', [uuid]);
    return { success: true, message: "Deleted User" };
  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function changeUser_username(uuid, newValue) {
  try {
    let connection = await pool.getConnection();
    let [res] = await connection.execute(`
      UPDATE users SET username = ? WHERE uuid = ?  
    `, [newValue, uuid]);
    connection.release();

    if (res.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: "Changed Username" }
  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function changeUser_iota_id(uuid, token, newValue) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(
      'SELECT token FROM users WHERE uuid = ?',
      [uuid]
    );
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    if (rows[0].token !== token) {
      return { success: false, message: 'Bad Token' };
    };

    let tokenPart1 = v7();
    let tokenPart2 = v7();
    let tokenPart3 = v7();
    let newToken = `${tokenPart1}.${tokenPart2}.${tokenPart3}`;

    await connection.execute(`
      UPDATE users SET token = ? WHERE uuid = ?  
    `, [newToken, uuid]);

    await connection.execute(`
      UPDATE users SET iota_id = ? WHERE uuid = ?  
    `, [newValue, uuid]);

    return { success: true, message: newToken };
  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function changeUser_public_key_and_private_key_hash(uuid, token, newPublicKey, newPrivateKeyHash) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(
      'SELECT token FROM users WHERE uuid = ?',
      [uuid]
    );
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    if (rows[0].token !== token) {
      return { success: false, message: 'Bad Token' };
    };

    let tokenPart1 = v7();
    let tokenPart2 = v7();
    let tokenPart3 = v7();
    let newToken = `${tokenPart1}.${tokenPart2}.${tokenPart3}`;

    await connection.execute(`
      UPDATE users SET token = ? WHERE uuid = ?  
    `, [newToken, uuid]);

    await connection.execute(`
      UPDATE users SET public_key = ? WHERE uuid = ?  
    `, [newPublicKey, uuid]);

    await connection.execute(`
      UPDATE users SET private_key_hash = ? WHERE uuid = ?  
    `, [newPrivateKeyHash, uuid]);

    return { success: true, message: newToken };
  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function usernameToUUID(username) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(`SELECT uuid FROM users WHERE username = ?;`, [username]);
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'Username not found.' };
    };

    return { success: true, message: rows[0].uuid };

  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function get_username(uuid) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(`SELECT username FROM users WHERE uuid = ?;`, [uuid]);
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: rows[0].username };

  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function get_display(uuid) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(`SELECT display FROM users WHERE uuid = ?;`, [uuid]);
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: rows[0].display };

  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function get_about(uuid) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(`SELECT about FROM users WHERE uuid = ?;`, [uuid]);
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: rows[0].about };

  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function get_status(uuid) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(`SELECT status FROM users WHERE uuid = ?;`, [uuid]);
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: rows[0].status };

  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function get_avatar(uuid) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(`SELECT avatar FROM users WHERE uuid = ?;`, [uuid]);
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: rows[0].avatar };

  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function get_created_at(uuid) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(`SELECT created_at FROM users WHERE uuid = ?;`, [uuid]);
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: rows[0].created_at };

  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function get_public_key(uuid) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(`SELECT public_key FROM users WHERE uuid = ?;`, [uuid]);
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: rows[0].public_key };

  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function get_private_key_hash(uuid) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(`SELECT private_key_hash FROM users WHERE uuid = ?;`, [uuid]);
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: rows[0].private_key_hash };

  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function get_iota_id(uuid) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(`SELECT iota_id FROM users WHERE uuid = ?;`, [uuid]);
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: rows[0].iota_id };

  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function get_omikron_uuids(uuid) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute('SELECT uuid FROM omikron_uuids WHERE uuid = ?;', [uuid]);
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'Permission Denied' };
    };

    return { success: true, message: rows[0].uuid };

  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function close() {
  if (pool) {
    await pool.end();
    console.log('Database connection pool closed.');
    pool = null;
    process.exit(0);
  };
};

export {
  init,
  close,
  addUser,
  removeUser,
  changeUser_username,
  changeUser_iota_id,
  changeUser_public_key_and_private_key_hash,
  get_created_at,
  get_public_key,
  get_private_key_hash,
  get_iota_id,
  get_omikron_uuids,
  get_username,
  get_display,
  get_avatar,
  get_about,
  get_status,
  usernameToUUID,
};
