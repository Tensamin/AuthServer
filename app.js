// Imports
import express from 'express';
import fs from 'fs';
import { v7 } from 'uuid';
import "dotenv/config";
import * as db from './sql.js';
import cors from "cors";
import { dirname } from "path";
import { fileURLToPath } from 'url';

// Variables
let __filename = fileURLToPath(import.meta.url);
let __dirname = dirname(__filename);
let publicKey = fs.readFileSync('public.pem', 'utf8');
let privateKey = fs.readFileSync('private.pem', 'utf8');
let port = process.env.PORT || 9187;
let app = express();
let userCreations = {};

// Environment
app.use(cors());
app.use(express.json());

// API Endpoints
app.get('/api/register/init', async (req, res) => {
    class UserCreationProcess {
        constructor() { this.uuid = v7() };
    };

    let newUser = new UserCreationProcess();
    userCreations[newUser.uuid] = newUser;
    res.send(newUser.uuid);

    setTimeout(() => {
        if (userCreations[newUser.uuid]) {
            delete userCreations[newUser.uuid];
        };
    }, 3600000);
});

app.post('/api/register/complete', async (req, res) => {
    try {
        if ("uuid" in req.body &&
            "username" in req.body &&
            "email" in req.body &&
            "public_key" in req.body &&
            "private_key_hash" in req.body) {

            let tokenPart1 = v7();
            let tokenPart2 = v7();
            let tokenPart3 = v7();
            let token = `${tokenPart1}.${tokenPart2}.${tokenPart3}`;

            let iotaPart1 = v7();
            let iotaPart2 = v7();
            let iotaPart3 = v7();
            let iota = `${iotaPart1}.${iotaPart2}.${iotaPart3}`;

            if (userCreations[req.body.uuid]) {
                db.addUser(
                    req.body.uuid,
                    req.body.username,
                    req.body.email,
                    req.body.public_key,
                    req.body.private_key_hash,
                    token,
                    iota,
                    new Date().getTime(),
                );
                delete userCreations[req.body.uuid];
            } else {
                res.status(400).send({ success: false, message: "UUID Invalid" });
            }
            res.json({ success: true, message: "Created User" });
        } else {
            res.status(400).send({ success: false, message: "Missing Value" });
        };
    } catch (err) {
        res.status(500).send({ success: false, message: err.message })
    }
});

app.post('/api/login', async (req, res) => {
    try {
        let data = req.body

        if (data.uuid && data.private_key_hash) {
            let private_key_hash_db = await db.get_private_key_hash(data.uuid)
            let iota_communication_token = await db.get_iota_communication_token(data.uuid)
            if (private_key_hash_db.success) {
                if (private_key_hash_db.message === data.private_key_hash) {
                    // SUccess
                    res.json({ success: true, message: "Hash matches", data: {
                        iota_communication_token: iota_communication_token
                    } })
                } else {
                    res.json({ success: false, message: "Hash does not match" })
                }
            } else {
                res.status(500).send({ success: false, message: private_key_hash_db.message })
            }
        } else {
            res.json({ success: false, message: "Missing Value" })
        }
    } catch (err) {
        res.status(500).send({ success: false, message: err.message })
    }
});

app.get('/api/uuid-for/:user', async (req, res) => {
    let user = req.params.user;

    try {
        res.json(await db.usernameToUUID(user))
    } catch (err) {
        res.status(505).json({ success: false, message: err.message })
    }
})

app.get('/api/:uuid/username', async (req, res) => {
    let uuid = req.params.uuid;

    try {
        res.json(await db.UUIDtoUsername(uuid))
    } catch (err) {
        res.status(505).json({ success: false, message: err.message })
    }
})

app.get('/api/:uuid/public-key', async (req, res) => {
    let uuid = req.params.uuid;

    try {
        res.json(await db.get_public_key(uuid))
    } catch (err) {
        res.status(505).json({ success: false, message: err.message })
    }
})

app.get('/api/:uuid/created-at', async (req, res) => {
    let uuid = req.params.uuid;

    try {
        res.json(await db.get_created_at(uuid))
    } catch (err) {
        res.status(505).json({ success: false, message: err.message })
    }
})

// Files
app.get('/file/encryption/public-key', (req, res) => {
    res.send(publicKey)
})

app.get('/file/encryption/javascript', (req, res) => {
    res.sendFile(__dirname + '/encryption.js')
})

app.get('/file/license', (req, res) => {
    res.sendFile(__dirname + '/LICENSE')
})

app.get('/file/privacy-policy', (req, res) => {
    res.sendFile(__dirname + '/PRIVACY-POLICY')
})

app.get('/file/terms-of-service', (req, res) => {
    res.sendFile(__dirname + '/TERMS-OF-SERVICE')
})

// Start Server
app.listen(port, async () => {
    await db.init();
    console.log(`> Started at http://0.0.0.0:${port} / https://auth-tensamin.methanium.net`);
});


// Database Disconnect Cleanup
process.on('SIGINT', db.close);
process.on('SIGTERM', db.close);
process.on('uncaughtException', async (err) => {
    console.error('Uncaught Exception:', err);
    await db.close();
});