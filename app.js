import express from 'express';
import fs from 'fs';
import { v7 } from 'uuid';
import { decrypt_json_using_privkey } from './encryption.js';
import "dotenv/config";
import db from './sql.js'

let publicKey = fs.readFileSync('public.pem', 'utf8');
let privateKey = fs.readFileSync('private.pem', 'utf8');
let port = 9187

let app = express();

app.use(express.text());

class UserCreationProcess {
    constructor() {
        this.uuid = v7();
    }
}



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

async function usernameToUUID(username) {
    let query = 'SELECT uuid FROM users WHERE username = ? LIMIT 1';
    try {
        let [result] = await connection.execute(
            query,
            [username],
        );
        return result
    } catch (error) {
        console.log(error)
        return error.message
    }
}

async function changeName(new_username, token) {
    
    // TOken Check
    // Wenn TOken gut dann änder Username und mach neues Token
    // Schick neues Token zurück
  const updateQuery = `UPDATE users SET name = ? WHERE email = ?`;
  const [result] = await connection.execute(updateQuery, [newName, email]);

  console.log(`Updated ${result.affectedRows} row(s)`);
}

function closeConnection(){
    connection.end();
}

let users = {}
let userCreations = {}

app.get('/api/create-user/start', (req, res) => {
    let newUser = new UserCreationProcess();
    userCreations[newUser.uuid] = newUser;
    res.send(newUser.uuid)
})

app.get('/api/create-user/servers-public-key', (req, res) => {
    res.send(publicKey)
})

app.post('/api/create-user/finish', async (req, res) => {
    let data = await decrypt_json_using_privkey(req.body, privateKey);
    if ("uuid" in data &&
        "username" in data &&
        "email" in data &&
        "public_key" in data &&
        "private_key_hash" in data &&
        "selfhost_ip" in data &&
        "selfhost_port" in data) {
        let tokenPart1 = v7();
        let tokenPart2 = v7();
        let tokenPart3 = v7();
        let token = `${tokenPart1}${tokenPart2}${tokenPart3}`
        console.log(token)
        if (userCreations[data.uuid]) {
            addUser(
                data.uuid,
                data.username,
                data.email,
                data.public_key,
                data.private_key_hash,
                token,
                data.selfhost_ip,
                data.selfhost_port,
                new Date().getTime(),
            );
            delete userCreations[data.uuid];
        } else {
            res.send("UUID Invalid!");
        }
        res.send("Created User!");
    } else {
        res.send("Missing Value!");
    };
});

app.post('/api/username-to-uuid', async (req, res) => {
    let data = await decrypt_json_using_privkey(req.body, privateKey);
    let uuid;
    for (let user in users) {
        if (users[user].username === data.username) {
            uuid = users[user].uuid;
        };
    }
    res.send(uuid);
});

app.post('/api/login', async (req, res) => {
    let data = await decrypt_json_using_privkey(req.body, privateKey);

    if (users[data.uuid]) {
        if (users[data.uuid].private_key_hash === data.private_key_hash) {
            res.json({ success: true, message: "Private Key hash matches" });
        } else {
            res.json({ success: false, message: "Private Key hash does not match" });
        };
    } else {
        res.send({ success: false, message: "User does not exist" })
    };
})

app.listen(port, async () => {
    await db.initDb();
    console.log('\n--- All Users ---');
    const allUsers = await db.getUsers();
    allUsers.forEach(user => {
      console.log(`ID: ${user.id}, Username: ${user.username}, Email: ${user.email}`);
    });
    console.log('-------------------\n');
    console.log(`> Started at http://0.0.0.0:${port} / https://auth-tensamin.methanium.net`);
});

async function gracefulShutdown() {
    if (connection) {
        try {
            await connection.end();
            console.log('Database connection closed.');
        } catch (err) {
            console.error('Error closing database connection:', err);
        }
        connection = null; // Prevent future use
    }
    process.exit(0);
}

// Handle process termination signals
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

// Handle uncaught exceptions
process.on('uncaughtException', async (err) => {
    console.error('Uncaught Exception:', err);
    await gracefulShutdown();
});