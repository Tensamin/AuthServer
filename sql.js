const mysql = require('mysql2/promise');
const dotenv = require('dotenv');

dotenv.config();

let pool;

async function initDb() {
  if (pool) {
    console.log('Database pool already initialized.');
    return;
  }

  try {
    pool = mysql.createPool({
      host: process.env.DB_HOST,
      user: process.env.READWRITE_USER,
      password: process.env.READWRITE_PASS,
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

/**
 * Creates the 'users' table if it does not already exist.
 * This is an internal helper function.
 */
async function createUsersTable() {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

/**
 * Adds a new user to the database.
 * @param {string} username
 * @param {string} email
 * @param {string} password - In a real app, this should be a hashed password.
 * @returns {Promise<Object>} The result of the insert operation, including insertId.
 */
async function addUser(username, email, password) {
  const query = `
    INSERT INTO users (username, email, password)
    VALUES (?, ?, ?);
  `;
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute(query, [username, email, password]);
    connection.release();
    console.log(`User '${username}' added with ID: ${result.insertId}`);
    return result;
  } catch (error) {
    console.error(`Error adding user '${username}':`, error);
    throw error; // Re-throw for caller to handle
  }
}

/**
 * Retrieves all users from the database.
 * @returns {Promise<Array>} An array of user objects.
 */
async function getUsers() {
  const query = `SELECT id, username, email, created_at FROM users;`;
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(query);
    connection.release();
    return rows;
  } catch (error) {
    console.error('Error getting users:', error);
    throw error;
  }
}

/**
 * Retrieves a user by their ID.
 * @param {number} id
 * @returns {Promise<Object|null>} The user object or null if not found.
 */
async function getUserById(id) {
  const query = `SELECT id, username, email, created_at FROM users WHERE id = ?;`;
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.execute(query, [id]);
    connection.release();
    return rows.length > 0 ? rows[0] : null;
  } catch (error) {
    console.error(`Error getting user by ID ${id}:`, error);
    throw error;
  }
}

/**
 * Updates an existing user's email and/or password by username.
 * You might want to update by ID in a real app.
 * @param {string} username The username of the user to update.
 * @param {Object} updates An object containing fields to update (e.g., { email: 'new@example.com', password: 'new_hashed_password' }).
 * @returns {Promise<Object>} The result of the update operation.
 */
async function updateUser(username, updates) {
  let query = 'UPDATE users SET ';
  const params = [];
  const updateParts = [];

  if (updates.email) {
    updateParts.push('email = ?');
    params.push(updates.email);
  }
  if (updates.password) {
    updateParts.push('password = ?');
    params.push(updates.password);
  }

  if (updateParts.length === 0) {
    console.warn('No fields provided for update.');
    return { affectedRows: 0 };
  }

  query += updateParts.join(', ') + ' WHERE username = ?;';
  params.push(username);

  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute(query, params);
    connection.release();
    console.log(`User '${username}' updated. Affected rows: ${result.affectedRows}`);
    return result;
  } catch (error) {
    console.error(`Error updating user '${username}':`, error);
    throw error;
  }
}

/**
 * Deletes a user from the database by their username.
 * @param {string} username The username of the user to delete.
 * @returns {Promise<Object>} The result of the delete operation.
 */
async function deleteUser(username) {
  const query = `DELETE FROM users WHERE username = ?;`;
  try {
    const connection = await pool.getConnection();
    const [result] = await connection.execute(query, [username]);
    connection.release();
    console.log(`User '${username}' deleted. Affected rows: ${result.affectedRows}`);
    return result;
  } catch (error) {
    console.error(`Error deleting user '${username}':`, error);
    throw error;
  }
}

/**
 * Closes the database connection pool.
 * Should be called when the application is shutting down.
 */
async function closeDb() {
  if (pool) {
    await pool.end();
    console.log('Database connection pool closed.');
    pool = null; // Clear pool reference
  }
}

module.exports = {
  initDb,
  addUser,
  getUsers,
  getUserById,
  updateUser,
  deleteUser,
  closeDb // It's good practice to expose this for graceful shutdown
};