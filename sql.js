import mysql from 'mysql2/promise';
import 'dotenv/config';
import * as schedule from "node-schedule"
import sharp from "sharp"

let pool;

async function adjustAvatar(base64Input, bypass = false, quality = 80) {
  if (bypass || !base64Input) {
    return base64Input;
  }
  try {
    let base64Data = base64Input.split(';base64,').pop();
    if (!base64Data) {
      throw new Error('Invalid base64 input string.');
    }
    let inputBuffer = Buffer.from(base64Data, 'base64');
    let compressedBuffer = await sharp(inputBuffer)
      .jpeg({ quality })
      .toBuffer();
    let compressedBase64 = `data:image/jpeg;base64,${compressedBuffer.toString(
      'base64'
    )}`;
    return compressedBase64;
  } catch (error) {
    console.error('Error during Node.js image compression:', error);
    throw error;
  }
}

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
      avatar MEDIUMTEXT,
      about VARCHAR(200),
      status VARCHAR(15),
      sub_level INT NOT NULL,
      sub_end BIGINT NOT NULL
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
    INSERT INTO users (uuid, public_key, private_key_hash, username, token, iota_id, created_at, display, avatar, about, status, sub_level, sub_end)
    VALUES (?, ?, ?, ?, ?, ?, ?, ? ,? ,? ,?, ?, ?);
  `, [uuid, public_key, private_key_hash, username, token, iota_id, created_at, "", "", "", "", 0, 0]);
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

async function change_username(uuid, newValue) {
  try {
    let connection = await pool.getConnection();
    let [res] = await connection.execute(`
      UPDATE users SET username = ? WHERE uuid = ?  
    `, [newValue.toLowerCase(), uuid]);
    connection.release();

    if (res.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: "Changed username" }
  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function change_display(uuid, newValue) {
  try {
    let connection = await pool.getConnection();
    let [res] = await connection.execute(`
      UPDATE users SET display = ? WHERE uuid = ?  
    `, [newValue, uuid]);
    connection.release();

    if (res.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: "Changed display" }
  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function change_avatar(uuid, newValue) {
  try {
    let sub_level = await get_sub_level(uuid)
    if (sub_level.success) {
      let newImage;
      if (sub_level.message === 0) {
        newImage = await adjustAvatar(newValue, false, 90)
      } else {
        newImage = await adjustAvatar(newValue, true, 0)
      }

      let connection = await pool.getConnection();
      let [res] = await connection.execute(`
      UPDATE users SET avatar = ? WHERE uuid = ?  
    `, [newImage, uuid]);
      connection.release();

      if (res.length === 0) {
        return { success: false, message: 'UUID not found.' };
      };

      return { success: true, message: "Changed avatar" }
    } else {
      return { success: false, message: sub_level.message }
    }
  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function change_about(uuid, newValue) {
  try {
    let connection = await pool.getConnection();
    let [res] = await connection.execute(`
      UPDATE users SET about = ? WHERE uuid = ?  
    `, [newValue, uuid]);
    connection.release();

    if (res.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: "Changed about" }
  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function change_status(uuid, newValue) {
  try {
    let connection = await pool.getConnection();
    let [res] = await connection.execute(`
      UPDATE users SET status = ? WHERE uuid = ?  
    `, [newValue, uuid]);
    connection.release();

    if (res.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: "Changed status" }
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

async function get_sub_level(uuid) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(`SELECT sub_level FROM users WHERE uuid = ?;`, [uuid]);
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: rows[0].sub_level };

  } catch (err) {
    return { success: false, message: err.message };
  };
};

async function get_sub_end(uuid) {
  try {
    let connection = await pool.getConnection();
    let [rows] = await connection.execute(`SELECT sub_end FROM users WHERE uuid = ?;`, [uuid]);
    connection.release();

    if (rows.length === 0) {
      return { success: false, message: 'UUID not found.' };
    };

    return { success: true, message: rows[0].sub_end };

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
}

let job = schedule.scheduleJob('0 0 * * *', { tz: 'UTC' }, () => {
  removeOneDayFromEverySubscription();
});

console.log('Node.js scheduler started.');
console.log('Job scheduled to run every day at 00:00 UTC.');
console.log(
  'Next scheduled invocation:',
  job.nextInvocation().toISOString()
);

export {
  init,
  close,
  addUser,
  removeUser,
  changeUser_iota_id,
  changeUser_public_key_and_private_key_hash,
  change_username,
  change_display,
  change_avatar,
  change_about,
  change_status,
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
  get_sub_level,
  get_sub_end,
  usernameToUUID,
};
