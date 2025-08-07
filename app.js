// Imports
import express from "express";
import cors from "cors";
import sharp from "sharp"
import { v7 } from "uuid";
import * as db from "./db.js";
import "dotenv/config";

import { randomBytes } from 'crypto'
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from '@simplewebauthn/server'

// Variables
let port = process.env.PORT || 9187;
let app = express();
let userCreations = [];
let rpID = 'ma-at-home.hackrland.dev';
let rpName = 'Tensamin';
let origin = "https://ma-at-home.hackrland.dev";

// Environment
app.use(cors({ origin: origin, credentials: true }));
app.use(express.json({ limit: "16mb" }));
app.use(express.urlencoded({ extended: true, limit: "16mb" }));

// Avatar Function
async function adjustAvatar(base64Input, bypass = false, quality = 80) {
    if (bypass) {
        return base64Input;
    }
    try {
        let base64Data = base64Input.split(';base64,').pop();
        if (!base64Data) {
            throw new Error('Invalid base64 input string.');
        }
        let inputBuffer = Buffer.from(base64Data, 'base64');
        let compressedBuffer = await sharp(inputBuffer)
            .webp({ quality })
            .toBuffer();
        let compressedBase64 = `data:image/webp;base64,${compressedBuffer.toString(
            'base64'
        )}`;
        return compressedBase64;
    } catch (err) {
        throw new Error(err.message);
    }
}

// User Endpoints
app.get('/api/get/uuid/:username', async (req, res) => {
    let username = req.params.username;

    try {
        let uuid = await db.uuid(username);
        res.json({
            type: "success",
            log: {
                message: `Got uuid for ${username}`,
                log_level: 0,
            },
            data: {
                uuid,
            }
        })
    } catch (err) {
        res.json({
            type: "error",
            log: {
                message: `Failed to get uuid for ${username}: ${err.message}`,
                log_level: 1,
            }
        })
    }
})

app.get('/api/get/:uuid', async (req, res) => {
    let uuid = req.params.uuid;
    try {
        let { created_at, username, display, avatar, about, status, public_key, sub_level, sub_end } = await db.get(uuid);
        res.json({
            type: "success",
            log: {
                message: `Got user ${uuid}`,
                log_level: 0,
            },
            data: {
                created_at,
                username,
                display,
                avatar,
                about,
                status,
                public_key,
                sub_level,
                sub_end,
            },
        })
    } catch (err) {
        res.json({
            type: "error",
            log: {
                message: `Failed to get user for ${uuid}: ${err.message}`,
                log_level: 1,
            }
        })
    }
});

app.post('/api/change/username/:uuid', async (req, res) => {
    let uuid = req.params.uuid;
    try {
        if ("private_key_hash" in req.body && "username" in req.body) {
            let user = await db.get(uuid);
            if (req.body.private_key_hash === user.private_key_hash) {
                user.username = req.body.username.toLowerCase().replaceAll(/[^a-z0-9_]/g, "");
                await db.update(uuid, user);
                res.json({
                    type: "success",
                    log: {
                        message: `Changed username for ${uuid}`,
                        log_level: 0,
                    }
                })
            } else throw new Error("Permission Denied")
        } else throw new Error("Missing Values")
    } catch (err) {
        res.json({
            type: "error",
            log: {
                message: `Failed to change username for ${uuid}: ${err.message}`,
                log_level: 0,
            }
        })
    }
});

app.post('/api/change/display/:uuid', async (req, res) => {
    let uuid = req.params.uuid;
    try {
        if ("private_key_hash" in req.body && "display" in req.body) {
            let user = await db.get(uuid);
            if (req.body.private_key_hash === user.private_key_hash) {
                user.display = req.body.display;
                await db.update(uuid, user);
                res.json({
                    type: "success",
                    log: {
                        message: `Changed display for ${uuid}`,
                        log_level: 0,
                    }
                })
            } else throw new Error("Permission Denied")
        } else throw new Error("Missing Values")
    } catch (err) {
        res.json({
            type: "error",
            log: {
                message: `Failed to change display for ${uuid}: ${err.message}`,
                log_level: 0,
            }
        })
    }
});

app.post('/api/change/avatar/:uuid', async (req, res) => {
    let uuid = req.params.uuid;
    try {
        if ("private_key_hash" in req.body && "avatar" in req.body) {
            let user = await db.get(uuid);
            if (req.body.private_key_hash === user.private_key_hash) {
                user.avatar = await adjustAvatar(req.body.avatar, user.sub_level >= 1);
                await db.update(uuid, user);
                res.json({
                    type: "success",
                    log: {
                        message: `Changed avatar for ${uuid}`,
                        log_level: 0,
                    }
                })
            } else throw new Error("Permission Denied")
        } else throw new Error("Missing Values")
    } catch (err) {
        res.json({
            type: "error",
            log: {
                message: `Failed to change avatar for ${uuid}: ${err.message}`,
                log_level: 0,
            }
        })
    }
});

app.post('/api/change/about/:uuid', async (req, res) => {
    let uuid = req.params.uuid;
    try {
        if ("private_key_hash" in req.body && "about" in req.body) {
            let user = await db.get(uuid);
            if (req.body.private_key_hash === user.private_key_hash) {
                user.about = btoa(req.body.about);
                await db.update(uuid, user);
                res.json({
                    type: "success",
                    log: {
                        message: `Changed about for ${uuid}`,
                        log_level: 0,
                    }
                })
            } else throw new Error("Permission Denied")
        } else throw new Error("Missing Values")
    } catch (err) {
        res.json({
            type: "error",
            log: {
                message: `Failed to change about for ${uuid}: ${err.message}`,
                log_level: 0,
            }
        })
    }
});

app.post('/api/change/status/:uuid', async (req, res) => {
    let uuid = req.params.uuid;
    try {
        if ("private_key_hash" in req.body && "status" in req.body) {
            let user = await db.get(uuid);
            if (req.body.private_key_hash === user.private_key_hash) {
                user.status = req.body.status;
                await db.update(uuid, user);
                res.json({
                    type: "success",
                    log: {
                        message: `Changed status for ${uuid}`,
                        log_level: 0,
                    }
                })
            } else throw new Error("Permission Denied")
        } else throw new Error("Missing Values")
    } catch (err) {
        res.json({
            type: "error",
            log: {
                message: `Failed to change status for ${uuid}: ${err.message}`,
                log_level: 0,
            }
        })
    }
});

app.post('/api/register/options/:uuid', async (req, res) => {
    let uuid = req.params.uuid;

    try {
        let user = await db.get(uuid);
        if (req.body.private_key_hash === user.private_key_hash) {
            let saltB64 = randomBytes(32).toString('base64')
            user.salt = saltB64
            user.credentials = []
            let options = await generateRegistrationOptions({
                rpName,
                rpID,
                userName: user.username,
                userDisplayName: user.display,
                attestationType: 'none',
                authenticatorSelection: { userVerification: 'required' },
                supportedAlgorithmIDs: [-7],            // ES256
                extensions: { hmacCreateSecret: true }, // request hmac‐secret
            })
            user.current_challenge = options.challenge

            await db.update(uuid, user)

            res.json({
                type: "success",
                log: {
                    message: `Got registration options for ${uuid}`,
                    log_level: 2
                },
                data: {
                    options,
                    salt: saltB64
                }
            })
        } else throw new Error("Permission Denied")
    } catch (err) {
        res.json({
            type: "error",
            log: {
                message: `Failed to get registration options for ${uuid}: ${err.message}`,
                log_level: 2
            }
        })
    }
});

app.post('/api/register/verify/:uuid', async (req, res) => {
    let uuid = req.params.uuid;

    try {
        if (!req.body) {
            throw new Error('Missing request body');
        }

        let user = await db.get(uuid);
        if (!user) throw new Error('User not found');

        if (req.body.private_key_hash !== user.private_key_hash) {
            throw new Error('Permission Denied');
        }

        if (!user.current_challenge) {
            throw new Error('Stored challenge missing for user');
        }
        if (!req.body.attestation) {
            throw new Error('Missing attestation in request body');
        }

        let verification = await verifyRegistrationResponse({
            response: req.body.attestation,
            expectedChallenge: user.current_challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            requireUserVerification: true,
        });

        let { verified, registrationInfo } = verification || {};
        if (!verified) {
            throw new Error('WebAuthn verification failed');
        }

        if (!registrationInfo) {
            throw new Error('No registrationInfo returned from verification');
        }

        let { credential } = registrationInfo;
        if (!credential) {
            throw new Error('No credential data returned from verification');
        }

        let { id: credentialID, publicKey: credentialPublicKey, counter } = credential;
        if (!credentialID || !credentialPublicKey) {
            throw new Error(
                `Missing credential data - credentialID: ${!!credentialID}, credentialPublicKey: ${!!credentialPublicKey}`
            );
        }

        if (!Array.isArray(user.credentials)) user.credentials = [];

        user.credentials.push({
            credID: credentialID,
            publicKey: Buffer.from(credentialPublicKey).toString('base64'),
            counter: counter || 0,
        });

        user.current_challenge = "";
        await db.update(uuid, user);

        res.json({
            type: 'success',
            log: { message: `Verified ${uuid}`, log_level: 2 },
        });
    } catch (err) {
        res.json({
            type: 'error',
            log: {
                message: `Failed to verify ${uuid}: ${err.message}`,
                log_level: 2,
            },
        });
    }
});

app.get('/api/login/options/:uuid', async (req, res) => {
    let uuid = req.params.uuid;

    try {
        let user = await db.get(uuid);
        let cred = user.credentials[0];
        if (!user?.credentials?.length) {
            throw new Error("No credentials registered for this user");
        }
        console.log(user.credentials)
        let options = await generateAuthenticationOptions({
            allowCredentials: [
                {
                    id: cred.credID,
                    transports: ['usb', 'ble', 'nfc', 'internal']
                }
            ],
            userVerification: 'required',
            rpID,
        })
        options.extensions = {
            hmacGetSecret: { salt1: Buffer.from(user.salt, "base64") },
        }
        user.current_challenge = options.challenge;
        await db.update(uuid, user);
        res.json({
            type: "success",
            log: {
                message: `Got login options for ${uuid}`,
                log_level: 2
            },
            data: {
                options,
                salt: user.salt,
                credential_id: cred.credID,
            }
        })
    } catch (err) {
        res.json({
            type: "error",
            log: {
                message: `Failed to get login options for ${uuid}: ${err.message}`,
                log_level: 2
            }
        })
    }
});

app.post('/api/login/verify/:uuid', async (req, res) => {
    let uuid = req.params.uuid;

    try {
        if (req.body.assertion) {
            let user = await db.get(uuid)
            let cred = user.credentials[0];
            console.log("CRED CREDID", cred.credID)
            let verification = await verifyAuthenticationResponse({
                response: req.body.assertion,
                expectedChallenge: user.current_challenge,
                expectedOrigin: origin,
                expectedRPID: rpID,
                authenticator: {
                    publicKey: Buffer.from(cred.publicKey, "base64"),
                    credentialID: Buffer.from(cred.credID, "base64"),
                    counter: cred.counter,
                },
                requireUserVerification: true,
            })
            let { verified, authenticationInfo } = verification;
            if (verified) {
                cred.counter = authenticationInfo.newCounter
                user.current_challenge = "";
                await db.update(uuid, user)
                res.json({
                    type: "success",
                    log: {
                        message: `Verified ${uuid}`,
                        log_level: 2
                    }
                })
            } else throw new Error("Verification Failed")
        } else throw new Error("Missing Values");
    } catch (err) {
        res.json({
            type: "error",
            log: {
                message: `Failed to verify ${uuid}: ${err.message}`,
                log_level: 2
            }
        })
    }
});

// Deprecated
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

// Iota Endpoints
app.get('/api/register/init', async (req, res) => {
    let newUser = v7();
    userCreations.push(newUser);
    res.send({
        type: "success",
        log: {
            message: "Started user registration progress",
            log_level: 0,
        },
        data: {
            user_id: newUser,
        },
    });

    setTimeout(() => {
        if (userCreations.includes(newUser)) {
            userCreations.shift(newUser);
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

            let newUsername = req.body.username.toLowerCase().replaceAll(/[^a-z0-9_]/g, '');

            if (userCreations.includes(req.body.uuid)) {
                db.add(
                    req.body.uuid,
                    req.body.public_key,
                    req.body.private_key_hash,
                    newUsername,
                    reset_token,
                    req.body.iota_id,
                    Date.now(),
                );
                userCreations.shift(req.body.uuid);
            } else {
                res.status(400).json({
                    type: "error",
                    log: {
                        message: "User creation failed do to invalid UUID",
                        log_level: 1,
                    }
                });
            }
            // Success Message
            res.json({
                type: "success",
                log: {
                    message: `Created User: ${req.body.uuid}`,
                    log_level: 0,
                }
            });
        } else {
            res.status(400).json({
                type: "error",
                log: {
                    message: "User creation failed do to missing values",
                    log_level: 1,
                }
            });
        };
    } catch (err) {
        res.status(500).json({
            type: "error",
            log: {
                message: err.message,
                log_level: 1,
            }
        })
    }
});

// Omikron Endpoints
app.get('/api/get/private-key-hash/:uuid', async (req, res) => {
    let uuid = req.params.uuid;
    try {
        if (req.headers.authorization && req.headers.privatekeyhash) {
            let isLegitOmikron = await db.checkLegitimacy(req.headers.authorization)
            if (isLegitOmikron) {
                let { private_key_hash } = await db.get(uuid);
                res.json({
                    type: "success",
                    log: {
                        message: `Got private key hash for ${uuid}`,
                        log_level: 1,
                    },
                    data: {
                        matches: req.headers.privatekeyhash === private_key_hash,
                    },
                })
            } else throw new Error("Permission Denied")
        } else throw new Error("Permission Denied")
    } catch (err) {
        res.json({
            type: "error",
            log: {
                message: `Failed to get private key hash for ${uuid}: ${err.message}`,
                log_level: 1,
            }
        })
    }
});

app.get('/api/get/iota-id/:uuid', async (req, res) => {
    let uuid = req.params.uuid;
    try {
        if (req.headers.authorization) {
            let isLegitOmikron = await db.checkLegitimacy(req.headers.authorization)
            if (isLegitOmikron) {
                let { iota_id } = await db.get(uuid);
                res.json({
                    type: "success",
                    log: {
                        message: `Got iota id for ${uuid}`,
                        log_level: 1,
                    },
                    data: {
                        iota_id,
                    },
                })
            } else throw new Error("Permission Denied")
        } else throw new Error("Permission Denied")
    } catch (err) {
        res.json({
            type: "error",
            log: {
                message: `Failed to get private key hash for ${uuid}: ${err.message}`,
                log_level: 1,
            }
        })
    }
});

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
