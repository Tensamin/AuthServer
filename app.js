// Imports
import express from 'express';
import fs from 'fs';
import { v7 } from 'uuid';
import { decrypt_json_using_privkey } from './encryption.js';
import "dotenv/config";
import * as db from './sql.js'
import cors from "cors"
import { dirname } from "path"
import { fileURLToPath } from 'url';

// Variables
let __filename = fileURLToPath(import.meta.url);
let __dirname = dirname(__filename);
let publicKey = fs.readFileSync('public.pem', 'utf8');
let privateKey = fs.readFileSync('private.pem', 'utf8');
let port = process.env.PORT || 9187
let app = express();
let userCreations = {};

// Environment
app.use(cors())
app.use(express.text());

// API Endpoints
app.get('/api/register/init', (req, res) => {
    class UserCreationProcess {
        constructor() {this.uuid = v7()}
    };

    let newUser = new UserCreationProcess();
    userCreations[newUser.uuid] = newUser;
    res.send(newUser.uuid)
})

/* */ // ENCRYPTED TRANSFER //
/* */ app.post('/api/register/complete', async (req, res) => {
/* */     let data = await decrypt_json_using_privkey(req.body, privateKey);
/* */     if ("uuid" in data &&
/* */         "username" in data &&
/* */         "email" in data &&
/* */         "public_key" in data &&
/* */         "private_key_hash" in data &&
/* */         "selfhost_ip" in data &&
/* */         "selfhost_port" in data) {
/* */ 
/* */         let tokenPart1 = v7();
/* */         let tokenPart2 = v7();
/* */         let tokenPart3 = v7();
/* */         let token = `${tokenPart1}.${tokenPart2}.${tokenPart3}`;
/* */ 
/* */         if (userCreations[data.uuid]) {
/* */             db.addUser(
/* */                 data.uuid,
/* */                 data.username,
/* */                 data.email,
/* */                 data.public_key,
/* */                 data.private_key_hash,
/* */                 token,
/* */                 data.selfhost_ip,
/* */                 data.selfhost_port,
/* */                 new Date().getTime(),
/* */             );
/* */             delete userCreations[data.uuid];
/* */         } else {
/* */             res.send("UUID Invalid!");
/* */         }
/* */         res.send("Created User!");
/* */     } else {
/* */         res.send("Missing Value!");
/* */     };
/* */ });
/* */ // ENCRYPTED TRANSFER //

/* */ // ENCRYPTED TRANSFER //
/* */ app.post('/api/login', async (req, res) => {
/* */     let data = await decrypt_json_using_privkey(req.body, privateKey);
/* */ 
/* */     if (users[data.uuid]) {
/* */         if (users[data.uuid].private_key_hash === data.private_key_hash) {
/* */             res.json({ success: true, message: "Private Key hash matches" });
/* */         } else {
/* */             res.json({ success: false, message: "Private Key hash does not match" });
/* */         };
/* */     } else {
/* */         res.send({ success: false, message: "User does not exist" });
/* */     };
/* */ });
/* */ // ENCRYPTED TRANSFER //

app.post('/api/:user/uuid', async (req, res) => {
    let user = db.validate(req.params.user);
    let response;

    try {
        response = await db.usernameToUUID(user)
        res.json(response)
    } catch(err) {
        res.status(505).json({success: false, message: err.message})
    }
})

app.post('/api/:user/public-key', async (req, res) => {
    let user = db.validate(req.params.user);
    let public_key;

    try {
        public_key = await db.get_public_key(user)
        res.json({success: true, message: public_key})
    } catch(err) {
        res.status(505).json({success: false, message: err.message})
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