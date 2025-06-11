import mysql from 'mysql2/promise';
import 'dotenv/config';

let pool;

async function initDb() {
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
  const createTableQuery = `
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
    const connection = await pool.getConnection();
    await connection.execute(createTableQuery);
    connection.release();
  } catch (error) {
    console.error('Error creating users table:', error);
    throw error; // Re-throw to be caught by initDb or caller
  }
}

async function addUser(uuid, username, email, public_key, private_key_hash, token, selfhost_ip, selfhost_port, created_at) {
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute(`
    INSERT INTO users (uuid, username, email, public_key, private_key_hash, token, selfhost_ip, selfhost_port, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
  `, [uuid, username, email, public_key, private_key_hash, token, selfhost_ip, selfhost_port, created_at]);
    connection.release();


    console.log(`User '${username}' added with ID: ${result.insertId}`);
    return result;
  } catch (error) {
    console.error(`Error adding user '${username}':`, error);
    throw error; // Re-throw for caller to handle
  }
}

async function usernameToUUID(username) {
  const query = `SELECT id, username, email, created_at FROM users WHERE username = ?;`;
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(query, [username]);
    connection.release();
    return rows.length > 0 ? rows[0] : null;
  } catch (error) {
    console.error(`Error getting user by ID ${id}:`, error);
    throw error;
  }
}

async function closeDb() {
  if (pool) {
    await pool.end();
    console.log('Database connection pool closed.');
    pool = null;
  }
}

export {
  initDb,
  addUser,
  usernameToUUID,
  closeDb,
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