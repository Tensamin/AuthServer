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
            user_id: newUser.uuid,
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
            "username" in req.body &&
            "iota_id" in req.body) {

            let tokenPart1 = v7();
            let tokenPart2 = v7();
            let tokenPart3 = v7();
            let reset_token = `${tokenPart1}.${tokenPart2}.${tokenPart3}`;

            let newUsername = req.body.username.toLowerCase().replace(/[^a-z0-9_]/g, '');

            if (userCreations[req.body.uuid]) {
                db.addUser(
                    req.body.uuid,
                    req.body.public_key,
                    req.body.private_key_hash,
                    newUsername,
                    reset_token,
                    req.body.iota_id,
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
                log_level: 1,
            },
            data: {},
        })
    }
});

app.post('/api/login', async (req, res) => {
    try {
        let data = req.body

        if (data.uuid && data.private_key_hash) {
            let private_key_hash = await db.get_private_key_hash(data.uuid)
            let iota_id = await db.get_iota_id(data.uuid)
            if (private_key_hash.success) {
                if (private_key_hash.message === data.private_key_hash) {
                    res.json({
                        type: "message",
                        log: {
                            message: "User login: Hash matches",
                            log_level: 0
                        },
                        data: {
                            iota_id: iota_id
                        }
                    })
                } else {
                    res.json({
                        type: "error",
                        log: {
                            message: "Hash does not match",
                            log_level: 1
                        },
                        data: {}
                    })
                }
            } else {
                res.status(500).json({
                    type: "error",
                    log: {
                        message: private_key_hash.message,
                        log_level: 1
                    },
                    data: {}
                })
            }
        } else {
            res.json({
                type: "error",
                log: {
                    message: "Failed do to missing values",
                    log_level: 1
                },
                data: {}
            })
        }
    } catch (err) {
        res.status(500).json({
            type: "error",
            log: {
                message: err.message,
                log_level: 1
            },
            data: {}
        })
    }
});

app.get('/api/:uuid', async (req, res) => {
    let uuid = req.params.uuid;

    try {
        let createdAtData = await db.get_created_at(uuid);
        let usernameData  = await db.get_username(uuid);
        let displayData   = await db.get_display(uuid);
        let avatarData    = await db.get_avatar(uuid);
        let aboutData     = await db.get_about(uuid);
        let statusData    = await db.get_status(uuid);
        let publicKeyData    = await db.get_public_key(uuid);

        if (createdAtData.success && usernameData.success && displayData.success && avatarData.success && aboutData.success && statusData.success && publicKeyData.success) {
            res.json({
                type: "message",
                log: {
                    message: `Get user for ${uuid}`,
                    log_level: 0,
                },
                data: {
                    created_at: createdAtData.message,
                    username: usernameData.message,
                    display: displayData.message,
                    avatar: avatarData.message,
                    about: aboutData.message,
                    status: statusData.message,
                    public_key: publicKeyData.message,
                },
            })
        }
    } catch (err) {
        res.status(500).json({
            type: "error",
            log: {
                message: `Failed to get user for ${uuid}: ${err.message}`,
                log_level: 1,
            },
            data: {},
        })
    }
})

app.get('/api/:uuid/username', async (req, res) => {
    let uuid = req.params.uuid;

    try {
        let data = await db.get_username(uuid);
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
                    log_level: 1,
                },
                data: {},
            })
        }
    } catch (err) {
        res.status(500).json({
            type: "error",
            log: {
                message: `Failed to get username for ${uuid}: ${err.message}`,
                log_level: 1,
            },
            data: {},
        })
    }
})

app.get('/api/:uuid/display', async (req, res) => {
    let uuid = req.params.uuid;

    try {
        let data = await db.get_display(uuid);
        if (data.success) {
            res.json({
                type: "message",
                log: {
                    message: `Get display for ${uuid}: ${data.message}`,
                    log_level: 0,
                },
                data: {
                    display: data.message,
                }
            })
        } else {
            res.status(500).json({
                type: "error",
                log: {
                    message: `Failed to get display for ${uuid}: ${data.message}`,
                    log_level: 1,
                },
                data: {},
            })
        }
    } catch (err) {
        res.status(500).json({
            type: "error",
            log: {
                message: `Failed to get display for ${uuid}: ${err.message}`,
                log_level: 1,
            },
            data: {},
        })
    }
})

app.get('/api/:uuid/avatar', async (req, res) => {
    let uuid = req.params.uuid;

    try {
        let data = await db.get_avatar(uuid);
        if (data.success) {
            res.json({
                type: "message",
                log: {
                    message: `Get avatar for ${uuid}: ${data.message}`,
                    log_level: 0,
                },
                data: {
                    avatar: data.message,
                }
            })
        } else {
            res.status(500).json({
                type: "error",
                log: {
                    message: `Failed to get avatar for ${uuid}: ${data.message}`,
                    log_level: 1,
                },
                data: {},
            })
        }
    } catch (err) {
        res.status(500).json({
            type: "error",
            log: {
                message: `Failed to get avatar for ${uuid}: ${err.message}`,
                log_level: 1,
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
                    log_level: 1,
                },
                data: {},
            })
        }
    } catch (err) {
        res.status(500).json({
            type: "error",
            log: {
                message: `Failed to get public_key for ${uuid}: ${err.message}`,
                log_level: 1,
            },
            data: {},
        })
    }
})

app.get('/api/:uuid/iota-id', async (req, res) => {
    let uuid = req.params.uuid;
    if (req.headers.authorization) {
        let omikron_exists = await db.get_omikron_uuids(req.headers.authorization)

        if (omikron_exists.success) {
            try {
                let data = await db.get_iota_id(uuid)
                if (data.success) {
                    res.json({
                        type: "message",
                        log: {
                            message: `Get iota_id for ${uuid}: ${data.message}`,
                            log_level: 0,
                        },
                        data: {
                            iota_id: data.message,
                        }
                    })
                } else {
                    res.status(500).json({
                        type: "error",
                        log: {
                            message: `Failed to get iota_id for ${uuid}: ${data.message}`,
                            log_level: 1,
                        },
                        data: {},
                    })
                }
            } catch (err) {
                res.status(500).json({
                    type: "error",
                    log: {
                        message: `Failed to get iota_id for ${uuid}: ${err.message}`,
                        log_level: 1,
                    },
                    data: {},
                })
            }
        } else {
            res.status(401).json({
                type: "error",
                log: {
                    message: `Tried to access IOTA UUID for ${uuid}: Permission Denied`,
                    log_level: 1,
                },
                data: {},
            })
        }
    } else {
        res.status(401).json({
            type: "error",
            log: {
                message: `Tried to access IOTA UUID for ${uuid}: Permission Denied`,
                log_level: 1,
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
                    log_level: 1,
                },
                data: {},
            })
        }
    } catch (err) {
        res.status(500).json({
            type: "error",
            log: {
                message: `Failed to get created_at for ${uuid}: ${err.message}`,
                log_level: 1,
            },
            data: {},
        })
    }
})

app.get('/encryption-module', (req, res) => {
    res.sendFile(__dirname + '/encryption.js')
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
