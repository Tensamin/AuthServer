import express from 'express';
import fs from 'fs';
import { v7 } from 'uuid';
import { decrypt_json_using_privkey } from './public/encryption.js';

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
    let data = await decrypt_json_using_privkey(req.body, privateKey)
    if ("uuid" in data &&
        "public_key" in data &&
        "private_key_hash" in data &&
        "username" in data) {
        users[data.uuid] = data;
        res.send("Created User!")
    } else {
        res.send("Missing Value!")
    }
})

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

app.listen(port, () => {
    console.log(`> Started at http://0.0.0.0:${port} / https://auth-tensamin.methanium.net`);
});