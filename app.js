// Imports
import express from "express";
import cors from "cors";
import sharp from "sharp"
import { v7 } from "uuid";
import * as db from "./db.js";
import "dotenv/config";128

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

// Helper Functions
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

function base64ToUint8Array(base64String) {
  let binaryString = atob(base64String);
  let len = binaryString.length;
  let bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  return bytes;
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
            let options = await generateRegistrationOptions({
                rpName,
                rpID,
                userName: user.username,
                userDisplayName: user.display,
                attestationType: 'none',
                authenticatorSelection: { 
                    userVerification: 'required',
                    authenticatorAttachment: 'platform'
                },
                preferredAuthenticatorType: 'localDevice',
                supportedAlgorithmIDs: [-7],
            })

            user.lambda = randomBytes(128).toString("base64")
            user.current_challenge = options.challenge

            await db.update(uuid, user)

            res.json({
                type: "success",
                log: {
                    message: `Got registration options for ${uuid}`,
                    log_level: 2
                },
                data: {
                    options: btoa(JSON.stringify(options))
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
    let user = await db.get(uuid);

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

    let { verified, registrationInfo } = verification;
    if (!verified) {
      throw new Error('WebAuthn verification failed');
    }

    let { credential } = registrationInfo;
    console.log("RegisterInfo", registrationInfo)
    console.log("Register", credential)
    let {
      id,
      publicKey,
      counter,
      transports,
    } = credential;

    if (!id || !publicKey) {
      throw new Error('Missing credential data');
    }

    let cred_id = v7();

    user.credentials = JSON.parse(user.credentials)

    user.credentials[cred_id] = {
      id,
      publicKey: Buffer.from(publicKey).toString('base64'),
      counter,
      transports: JSON.stringify(transports),
    };

    let lambda = user.lambda;

    user.current_challenge = '';
    await db.update(uuid, user);

    res.json({
      type: 'success',
      log: {
        message: `Verified ${uuid}`,
        log_level: 2
      },
      data: {
        lambda,
        cred_id
      }
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

app.get('/api/login/options/:uuid/:id', async (req, res) => {
    let uuid = req.params.uuid;
    let cred_id = req.params.id;

    try {
        let user = await db.get(uuid);
        user.credentials = JSON.parse(user.credentials)
        if (user.credentials[cred_id] === undefined) throw new Error("Credential does not exist")
        let cred = user.credentials[cred_id];

        let options = await generateAuthenticationOptions({
            allowCredentials: [
                {
                    id: cred.id,
                    transports: ['internal', 'usb', 'nfc', 'smart-card', 'hybrid', 'cable', 'ble']
                }
            ],
            userVerification: 'required',
            rpID,
        })

        user.current_challenge = options.challenge;
        await db.update(uuid, user);
        res.json({
            type: "success",
            log: {
                message: `Got login options for ${uuid}`,
                log_level: 2
            },
            data: {
                options: btoa(JSON.stringify(options))
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

app.post('/api/login/verify/:uuid/:id', async (req, res) => {
  let uuid = req.params.uuid;
  let cred_id = req.params.id;

  try {
    let user = await db.get(uuid);

    if (!user.current_challenge) {
      throw new Error('Stored challenge missing for user');
    }

    if (!req.body.attestation) {
      throw new Error('Missing attestation in request body');
    }

    user.credentials = JSON.parse(user.credentials);
    if (user.credentials === undefined) throw new Error("Credential does not exist")
    let cred = user.credentials[cred_id];

    let { id, publicKey, counter, transports } = cred;
    if (!id || !publicKey) {
      throw new Error('Missing credential data');
    }

    let verification = await verifyAuthenticationResponse({
      response: req.body.attestation,
      expectedChallenge: user.current_challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        publicKey: base64ToUint8Array(publicKey),
        id,
        counter,
        transports: JSON.parse(transports),
      },
      requireUserVerification: true,
    });

    let { verified, authenticationInfo } = verification;
    if (!verified) {
      throw new Error('WebAuthn verification failed');
    }

    let lambda = user.lambda;

    user.credentials[cred_id].counter = authenticationInfo.newCounter;
    user.current_challenge = '';

    await db.update(uuid, user);

    res.json({
      type: 'success',
      log: {
        message: `Verified ${uuid}`,
        log_level: 2,
      },
      data: {
        lambda,
      },
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
