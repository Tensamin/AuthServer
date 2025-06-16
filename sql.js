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
  } catch (err) {
    console.error('Failed to initialize database pool:', err);
    throw new Error('Database initialization failed.');
  };
};

async function createUsersTable() {
  let createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      uuid VARCHAR(36) NOT NULL PRIMARY KEY UNIQUE,
      username VARCHAR(255) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL UNIQUE,
      public_key TEXT NOT NULL,
      private_key_hash VARCHAR(128) NOT NULL,
      token VARCHAR(255) NOT NULL UNIQUE,
      iota_uuid VARCHAR(255) NOT NULL UNIQUE,
      created_at VARCHAR(255) NOT NULL
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

async function addUser(uuid, username, email, public_key, private_key_hash, token, iota_uuid, created_at) {
  try {
    let connection = await pool.getConnection();
    await connection.execute(`
    INSERT INTO users (uuid, username, email, public_key, private_key_hash, token, iota_uuid, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
  `, [uuid, username, email, public_key, private_key_hash, token, iota_uuid, created_at]);
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

async function changeUser_email(uuid, newValue) {
  try {
    let connection = await pool.getConnection();
    let [res] = await connection.execute(`
      UPDATE users SET email = ? WHERE uuid = ?  
    `, [newValue, uuid]);
    connection.release();

    if (res.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: "Changed Email" }
  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function changeUser_iota_uuid(uuid, token, newValue) {
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
      UPDATE users SET iota_uuid = ? WHERE uuid = ?  
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

async function UUIDtoUsername(uuid) {
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

async function get_iota_uuid(uuid) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(`SELECT iota_uuid FROM users WHERE uuid = ?;`, [uuid]);
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: rows[0].iota_uuid };

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
  changeUser_email,
  changeUser_iota_uuid,
  changeUser_public_key_and_private_key_hash,
  get_created_at,
  get_public_key,
  get_private_key_hash,
  get_iota_uuid,
  UUIDtoUsername,
  usernameToUUID,
};