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
    res.send({
        type: "message",
        log: {
            message: "Started user registration progress",
            log_level: 0,
        },
        data: {
            uuid: newUser.uuid,
        },
    });

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
            "public_key" in req.body &&
            "private_key_hash" in req.body &&
            "username" in req.body) {

            let tokenPart1 = v7();
            let tokenPart2 = v7();
            let tokenPart3 = v7();
            let reset_token = `${tokenPart1}.${tokenPart2}.${tokenPart3}`;

            let iota_uuid = v7();

            if (userCreations[req.body.uuid]) {
                db.addUser(
                    req.body.uuid,
                    req.body.public_key,
                    req.body.private_key_hash,
                    req.body.username,
                    reset_token,
                    iota_uuid,
                    new Date().getTime(),
                );
                delete userCreations[req.body.uuid];
            } else {
                res.status(400).json({
                    type: "error",
                    log: {
                        message: "User creation failed do to invalid UUID",
                        log_level: 1,
                    },
                    data: {},
                });
            }
            res.json({
                type: "message",
                log: {
                    message: `Created User: ${req.body.uuid}`,
                    log_level: 0,
                },
                data: {},
            });
        } else {
            res.status(400).json({
                type: "error",
                log: {
                    message: "User creation failed do to missing values",
                    log_level: 1,
                },
                data: {},
            });
        };
    } catch (err) {
        res.status(500).json({
            type: "error",
            log: {
                message: err.message,
                log_level: 2,
            },
            data: {},
        })
    }
});

//app.post('/api/login', async (req, res) => {
//    try {
//        let data = req.body
//
//        if (data.uuid && data.private_key_hash) {
//            let private_key_hash_db = await db.get_private_key_hash(data.uuid)
//            let iota_uuid = await db.get_iota_uuid(data.uuid)
//            if (private_key_hash_db.success) {
//                if (private_key_hash_db.message === data.private_key_hash) {
//                    // SUccess
//                    res.json({
//                        success: true, message: "Hash matches", data: {
//                            iota_uuid: iota_uuid,
//                        }
//                    })
//                } else {
//                    res.json({ success: false, message: "Hash does not match" })
//                }
//            } else {
//                res.status(500).json({ success: false, message: private_key_hash_db.message })
//            }
//        } else {
//            res.json({ success: false, message: "Missing Value" })
//        }
//    } catch (err) {
//        res.status(500).json({ success: false, message: err.message })
//    }
//});

app.get('/api/:uuid/username', async (req, res) => {
    let uuid = req.params.uuid;

    try {
        let data = await db.UUIDtoUsername(uuid);
        if (data.success) {
            res.json({
                type: "message",
                log: {
                    message: `Get username for ${uuid}: ${data.message}`,
                    log_level: 0,
                },
                data: {
                    username: data.message,
                }
            })
        } else {
            res.status(500).json({
                type: "error",
                log: {
                    message: `Failed to get username for ${uuid}: ${data.message}`,
                    log_level: 2,
                },
                data: {},
            })
        }
    } catch (err) {
        res.status(500).json({
            type: "error",
            log: {
                message: `Failed to get username for ${uuid}: ${err.message}`,
                log_level: 2,
            },
            data: {},
        })
    }
})

app.get('/api/:uuid/public-key', async (req, res) => {
    let uuid = req.params.uuid;

    try {
        let data = await db.get_public_key(uuid)
        if (data.success) {
            res.json({
                type: "message",
                log: {
                    message: `Get public_key for ${uuid}: ${data.message}`,
                    log_level: 0,
                },
                data: {
                    public_key: data.message,
                }
            })
        } else {
            res.status(500).json({
                type: "error",
                log: {
                    message: `Failed to get public_key for ${uuid}: ${data.message}`,
                    log_level: 2,
                },
                data: {},
            })
        }
    } catch (err) {
        res.status(500).json({
            type: "error",
            log: {
                message: `Failed to get public_key for ${uuid}: ${err.message}`,
                log_level: 2,
            },
            data: {},
        })
    }
})

app.get('/api/:uuid/iota-uuid', async (req, res) => {
    let uuid = req.params.uuid;
    if (req.headers.authorization) {
        let omikron_exists = await db.get_omikron_uuids(req.headers.authorization)

        if (omikron_exists.success) {
            try {
                let data = await db.get_iota_uuid(uuid)
                if (data.success) {
                    res.json({
                        type: "message",
                        log: {
                            message: `Get iota_uuid for ${uuid}: ${data.message}`,
                            log_level: 0,
                        },
                        data: {
                            iota_uuid: data.message,
                        }
                    })
                } else {
                    res.status(500).json({
                        type: "error",
                        log: {
                            message: `Failed to get iota_uuid for ${uuid}: ${data.message}`,
                            log_level: 2,
                        },
                        data: {},
                    })
                }
            } catch (err) {
                res.status(500).json({
                    type: "error",
                    log: {
                        message: `Failed to get iota_uuid for ${uuid}: ${err.message}`,
                        log_level: 2,
                    },
                    data: {},
                })
            }
        } else {
            res.status(401).json({
                type: "error",
                log: {
                    message: `Tried to access IOTA UUID for ${uuid}: Permission Denied`,
                    log_level: 2,
                },
                data: {},
            })
        }
    } else {
        res.status(401).json({
            type: "error",
            log: {
                message: `Tried to access IOTA UUID for ${uuid}: Permission Denied`,
                log_level: 2,
            },
            data: {},
        })
    }
})

app.get('/api/:uuid/created-at', async (req, res) => {
    let uuid = req.params.uuid;

    try {
        let data = await db.get_created_at(uuid)
        if (data.success) {
            res.json({
                type: "message",
                log: {
                    message: `Get created_at for ${uuid}: ${data.message}`,
                    log_level: 0,
                },
                data: {
                    created_at: data.message,
                }
            })
        } else {
            res.status(500).json({
                type: "error",
                log: {
                    message: `Failed to get created_at for ${uuid}: ${data.message}`,
                    log_level: 2,
                },
                data: {},
            })
        }
    } catch (err) {
        res.status(500).json({
            type: "error",
            log: {
                message: `Failed to get created_at for ${uuid}: ${err.message}`,
                log_level: 2,
            },
            data: {},
        })
    }
})

app.get('/encryption-module', (req, res) => {
    res.jsonFile(__dirname + '/encryption.js')
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
