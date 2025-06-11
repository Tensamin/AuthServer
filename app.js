import express from 'express';
import fs from 'fs';
import { v7 } from 'uuid';
import { decrypt_json_using_privkey } from './encryption.js';
import "dotenv/config";
import * as db from './sql.js'
import cors from "cors"

let publicKey = fs.readFileSync('public.pem', 'utf8');
let privateKey = fs.readFileSync('private.pem', 'utf8');
let port = 9187
let app = express();
let users = {}
let userCreations = {}
let connection;

app.use(cors())
app.use(express.text());

class UserCreationProcess {
    constructor() {
        this.uuid = v7();
    }
}

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
        let token = `${tokenPart1}.${tokenPart2}.${tokenPart3}`
        console.log(token)
        if (userCreations[data.uuid]) {
            db.addUser(
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
        connection = null;
    }
    process.exit(0);
}
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);
process.on('uncaughtException', async (err) => {
    console.error('Uncaught Exception:', err);
    await gracefulShutdown();
});