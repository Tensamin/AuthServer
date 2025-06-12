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
    console.log('Database connection pool initialized.');

    // Create the users table if it doesn't exist
    await createUsersTable();
    console.log('Users table created or already exists.');

  } catch (error) {
    console.error('Failed to initialize database pool:', error);
    // It's critical if DB connection fails, so re-throw or exit
    throw new Error('Database initialization failed.');
  }
}

async function createUsersTable() {
  let createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      uuid VARCHAR(36) NOT NULL PRIMARY KEY UNIQUE,
      username VARCHAR(255) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL UNIQUE,
      public_key TEXT NOT NULL,
      private_key_hash VARCHAR(128) NOT NULL,
      token VARCHAR(255) NOT NULL UNIQUE,
      selfhost_ip VARCHAR(45) NOT NULL,
      selfhost_port INT NOT NULL,
      created_at VARCHAR(255) NOT NULL
    );
  `;
  try {
    let connection = await pool.getConnection();
    await connection.execute(createTableQuery);
    connection.release();
  } catch (error) {
    console.error('Error creating users table:', error);
    throw error; // Re-throw to be caught by initDb or caller
  }
}

async function addUser(uuid, username, email, public_key, private_key_hash, token, selfhost_ip, selfhost_port, created_at) {
  try {
    let connection = await pool.getConnection();
    let [result] = await connection.execute(`
    INSERT INTO users (uuid, username, email, public_key, private_key_hash, token, selfhost_ip, selfhost_port, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
  `, [uuid, username, email, public_key, private_key_hash, token, selfhost_ip, selfhost_port, created_at]);
    connection.release();
    return result;
  } catch (error) {
    return error.message
  }
}

async function removeUser(uuid, token) {
    try {
        let connection = await pool.getConnection();
        let [rows] = await connection.execute(
            'SELECT token FROM users WHERE uuid = ?',
            [uuid]
        );
        connection.release();

        if (rows.length === 0) {
            return {success: false, message: 'UUID not found.'};
        };

        if (rows[0].token !== token) {
            return {success: false, message: 'Bad Token'};
        };

        await connection.execute('DELETE FROM users WHERE uuid = ?', [uuid]);
        return {success: true, message: "Deleted User"};
    } catch (error) {
        return {success: false, message: error.message};
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

    return {success: true, message: rows[0].uuid}

  } catch (error) {
    return {success: false, message: error.message};
  };
};

async function closeDb() {
  if (pool) {
    await pool.end();
    console.log('Database connection pool closed.');
    pool = null;
  }
}

function validate(input) {
  return input.toLowerCase().replace(/[^a-z0-9.]/g, '');
}

export {
  initDb,
  addUser,
  usernameToUUID,
  closeDb,
  validate,
};

/*
async function addUser(uuid, username, email, public_key, private_key_hash, token, selfhost_ip, selfhost_port, created_at) {
    let query = `INSERT INTO users (uuid, username, email, public_key, private_key_hash, token, selfhost_ip, selfhost_port, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    try {
        let [result] = await connection.execute(
            query,
            [uuid, username, email, public_key, private_key_hash, token, selfhost_ip, selfhost_port, created_at,],
        );
        return result
    } catch (error) {
        console.log(error)
        return error.message
    }
}
*/