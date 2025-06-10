let net = require('net');
let express = require('express')
let WebSocket = require('ws');
let fs = require('fs');
let https = require('https');
let http = require('http');
let { v7: uuidv7 } = require('uuid');
let crypto = require('crypto');

let { decrypt_json_using_privkey, sha256, encrypt_json_using_pubkey } = require('./public/encryption')

let publicKey = fs.readFileSync('public.pem', 'utf8');
let privateKey = fs.readFileSync('private.pem', 'utf8');

let port = 5000
let app = express()
app.use(express.json());
app.use(express.text());
app.use(express.static('public'))

let serverOptions = {
    key: fs.readFileSync("ssl/private.key"),
    cert: fs.readFileSync("ssl/certificate.crt"),
};

//let server = https.createServer(serverOptions, app);
let server = http.createServer(app);
let wss = new WebSocket.Server({ server });

wss.on("connection", (ws) => {
    ws.on("message", (message) => {
        console.log("Received: " + message);
    });
});

// HTTP STUFF
class UserCreationProcess {
    constructor() {
        this.uuid = uuidv7();
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
        "password_hash" in data &&
        "public_key" in data &&
        "username" in data) {
        users[data.username] = data;
        res.send("Created User!")
    } else {
        res.send("Missing Value!")
    }
})

let sessions = {}

// Create New Session
app.post('/api/login', async (req, res) => {
    let data = await decrypt_json_using_privkey(req.body, privateKey)
    setTimeout(async () => {
        if ("username" in data &&
            "password_hash" in data &&
            "fingerprint" in data) {
            if (data.password_hash === users[data.username].password_hash) {
                // Create Session
                let sessionId = uuidv7()

                // Get Date in one month
                let expireDate = new Date()
                expireDate.setMonth(expireDate.getMonth() + 1)

                // Create Session Data
                let session = {
                    id: sessionId,
                    expires: expireDate.toISOString(),
                    creation: new Date().toISOString(),
                    fingerprint: req.body.fingerprint,
                }

                // Add Session to Sessions
                sessions[sessionId] = session;

                // Send Session to Client
                res.json({
                    id: session.id,
                    expires: session.expires,
                    creation: session.creation,
                });
            }
        } else {
            res.send("Missing Value!")
        }
    }, 5000)
})

server.listen(port, () => {
    console.log(`HTTPS server with WSS and Express running on https://localhost:${port}`);
});