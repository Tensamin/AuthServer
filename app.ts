// Imports
import express from "express";
import cors from "cors";
import sharp from "sharp";
import { v7 } from "uuid";
import * as db from "./db.ts";
import * as logger from "./logger.ts";
import "dotenv/config";

// Types
import type { CorsOptions } from "cors";
import type { Request, Response } from "express";

// Variables
const port: number = Number(process.env.PORT) || 9187;
const app = express();
const userCreations: string[] = [];
const primaryOrigin: string =
  process.env.ORIGIN || "https://tensamin.methanium.net";
const allowedOrigins = new Set<string>([
  primaryOrigin,
  "app://dist",
  "http://localhost:3000",
]);

await logger.initLogger();

const corsOptions: CorsOptions = {
  origin: (
    incomingOrigin: string | undefined,
    callback: (err: Error | null, allow?: boolean) => void
  ) => {
    try {
      if (!incomingOrigin) return callback(null, true);

      if (allowedOrigins.has(incomingOrigin)) return callback(null, true);

      try {
        const parsed = new URL(incomingOrigin);
        const host = parsed.hostname;
        if (host === "localhost" || host === "127.0.0.1" || host === "::1") {
          return callback(null, true);
        }
      } catch {}

      return callback(
        new Error(
          `Not allowed by CORS policy for origin: ${String(incomingOrigin)}`
        ),
        false
      );
    } catch (err) {
      return callback(err as Error, false);
    }
  },
  credentials: true,
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  allowedHeaders: "Content-Type,Authorization",
};

// Environment
app.use(cors(corsOptions));
app.use(express.json({ limit: "16mb" }));
app.use(express.urlencoded({ extended: true, limit: "16mb" }));

// Helper Functions
async function adjustAvatar(
  base64Input: string,
  bypass: boolean
): Promise<Buffer> {
  const quality = bypass ? 100 : 30;

  try {
    const base64Data = base64Input.split(";base64,").pop();
    if (!base64Data) {
      throw new Error("Invalid base64 input string.");
    }
    const inputBuffer = Buffer.from(base64Data, "base64");
    const compressedBuffer = await sharp(inputBuffer)
      .resize({ width: 450, height: 450, fit: "inside" })
      .webp({ quality, effort: 6 })
      .toBuffer();
    return compressedBuffer;
  } catch (err) {
    throw err instanceof Error ? err : new Error(String(err));
  }
}

function sendSuccess(
  res: Response,
  message: string,
  log_level: number,
  data?: Record<string, any>,
  statusCode?: number
): void {
  const payload: any = {
    type: "success",
    log: { message, log_level },
  };
  if (data !== undefined) payload.data = data;
  if (statusCode) res.status(statusCode).json(payload);
  else res.json(payload);
}

type SendErrorOptions = {
  statusCode?: number;
  error?: unknown;
  logMessage?: string;
};

function sendError(
  res: Response,
  message: string,
  log_level: number,
  statusCodeOrOptions?: number | SendErrorOptions,
  maybeError?: unknown
): void {
  let statusCode: number | undefined;
  let capturedError: unknown;
  let logMessage: string | undefined;

  if (typeof statusCodeOrOptions === "number") {
    statusCode = statusCodeOrOptions;
    capturedError = maybeError;
  } else if (statusCodeOrOptions && typeof statusCodeOrOptions === "object") {
    statusCode = statusCodeOrOptions.statusCode;
    capturedError = statusCodeOrOptions.error;
    logMessage = statusCodeOrOptions.logMessage;
  }

  const payload = {
    type: "error",
    log: { message, log_level },
  };

  if (statusCode) res.status(statusCode).json(payload);
  else res.json(payload);

  logger.logError(logMessage ?? message, capturedError);
}

function hasKeys(obj: any, keys: string[]): boolean {
  return keys.every((k) => Object.prototype.hasOwnProperty.call(obj, k));
}

function sanitizeUsername(s: string): string {
  return s.toLowerCase().replaceAll(/[^a-z0-9_]/g, "");
}

async function updateUser(uuid: string, user: db.User): Promise<void> {
  unwrap(await db.update(uuid, user));
}

async function ensureOmikronAuth(authHeader: unknown): Promise<boolean> {
  if (typeof authHeader !== "string") return false;
  return unwrap<boolean>(await db.checkLegitimacy(authHeader));
}

function btoa(str: string): string {
  return Buffer.from(str, "utf8").toString("base64");
}

function isBase64(str: unknown): boolean {
  if (typeof str !== "string") return false;
  let s = str.trim();
  if (s.length === 0) return true;
  if (s.length % 4 !== 0) return false;
  if (
    !/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.test(
      s
    )
  )
    return false;

  try {
    let buf = Buffer.from(s, "base64");
    let reencoded = buf.toString("base64");
    return reencoded === s || reencoded.replace(/=+$/, "") === s;
  } catch {
    return false;
  }
}

function unwrapGet(
  result: db.User | null | Error,
  notFoundMsg = "Not found"
): db.User {
  if (result instanceof Error) throw result;
  if (!result) throw new Error(notFoundMsg);
  return result;
}

function unwrap<T>(result: T | Error, msg = "Operation failed"): T {
  if (result instanceof Error) throw result;
  return result;
}

// User Endpoints
app.get("/api/get/uuid/:username", async (req: Request, res: Response) => {
  const username = req.params.username;

  try {
    const result = await db.uuid(username);
    const userUuid = unwrap<string>(result, "UUID lookup failed");
    res.json({
      type: "success",
      log: {
        message: `Got uuid for ${username}`,
        log_level: 0,
      },
      data: {
        user_id: userUuid,
      },
    });
  } catch (err) {
    const errorDetail = err instanceof Error ? err.message : String(err);
    const clientMessage = "Failed to get uuid for supplied username";
    sendError(res, `${clientMessage}: ${errorDetail}`, 1, {
      error: err,
      logMessage: clientMessage,
    });
  }
});

app.get("/api/get/:uuid", async (req: Request, res: Response) => {
  const uuid = req.params.uuid;
  try {
    const u = unwrapGet(await db.get(uuid), "User not found");
    const {
      created_at,
      username,
      display,
      avatar,
      about,
      status,
      public_key,
      sub_level,
      sub_end,
    } = u as any;
    res.json({
      type: "success",
      log: {
        message: "Got user",
        log_level: 0,
      },
      data: {
        created_at,
        username,
        display,
        avatar: avatar
          ? `data:image/webp;base64,${avatar.toString("base64")}`
          : null,
        about,
        status,
        public_key,
        sub_level,
        sub_end,
      },
    });
  } catch (err) {
    const errorDetail = err instanceof Error ? err.message : String(err);
    const clientMessage = "Failed to retrieve user profile";
    sendError(res, `${clientMessage}: ${errorDetail}`, 1, {
      error: err,
      logMessage: clientMessage,
    });
  }
});

app.post("/api/change/:uuid", async (req: Request, res: Response) => {
  const uuid = req.params.uuid;
  try {
    if (!hasKeys(req.body, ["private_key_hash"]))
      throw new Error("Missing Values");
    const user = unwrapGet(await db.get(uuid));
    if (req.body.private_key_hash !== user.private_key_hash)
      throw new Error("Permission Denied");

    for (const key of Object.keys(req.body)) {
      switch (key) {
        case "username":
          user.username = sanitizeUsername(req.body.username);
          break;
        case "display":
          user.display = req.body.display;
          break;
        case "about":
          user.about = isBase64(req.body.about)
            ? req.body.about
            : btoa(String(req.body.about));
          break;
        case "status":
          user.status = req.body.status;
          break;
        case "avatar": {
          if (req.body.avatar === "") {
            user.avatar = undefined;
            break;
          }
          user.avatar = await adjustAvatar(
            req.body.avatar,
            (user.sub_level ?? 0) >= 1
          );
          break;
        }
      }
    }

    await updateUser(uuid, user);
    sendSuccess(res, "Changed user", 0, {
      ...user,
      avatar: user.avatar
        ? `data:image/webp;base64,${user.avatar.toString("base64")}`
        : null,
    });
  } catch (err) {
    const errorDetail = err instanceof Error ? err.message : String(err);
    sendError(res, `Failed to change user: ${errorDetail}`, 0, {
      error: err,
      logMessage: "Failed to change user",
    });
  }
});

app.post("/api/change/iota-id/:uuid", async (req: Request, res: Response) => {
  const uuid = req.params.uuid;
  try {
    if (!hasKeys(req.body, ["reset_token", "new_token", "iota_id"]))
      throw new Error(
        `Missing Values, got: ${
          ("reset_token" in req.body && "Reset Token") || ""
        } ${("new_token" in req.body && "New Token") || ""} ${
          ("iota_id" in req.body && "Iota ID") || ""
        }`
      );
    const user = unwrapGet(await db.get(uuid));
    if (req.body.reset_token !== user.token)
      throw new Error("Permission Denied");
    user.iota_id = req.body.iota_id;
    user.token = req.body.new_token;
    await updateUser(uuid, user);
    console.log("Updated iota id for user:", uuid);
    sendSuccess(res, "Changed iota id", 0);
  } catch (err) {
    const errorDetail = err instanceof Error ? err.message : String(err);
    sendError(res, `Failed to change iota id: ${errorDetail}`, 0, {
      error: err,
      logMessage: "Failed to change iota id",
    });
  }
});

app.post("/api/change/keys/:uuid", async (req: Request, res: Response) => {
  const uuid = req.params.uuid;
  try {
    if (
      !hasKeys(req.body, [
        "reset_token",
        "new_token",
        "private_key_hash",
        "public_key",
      ])
    )
      throw new Error("Missing Values");
    const user = unwrapGet(await db.get(uuid));
    if (req.body.reset_token !== user.token)
      throw new Error("Permission Denied");
    user.private_key_hash = req.body.private_key_hash;
    user.public_key = req.body.public_key;
    user.token = req.body.new_token;
    await updateUser(uuid, user);
    sendSuccess(res, "Changed keys", 0);
  } catch (err) {
    const errorDetail = err instanceof Error ? err.message : String(err);
    sendError(res, `Failed to change keys: ${errorDetail}`, 0, {
      error: err,
      logMessage: "Failed to change keys",
    });
  }
});

// Iota Endpoints
app.get("/api/register/init", async (_req: Request, res: Response) => {
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
      const idx = userCreations.indexOf(newUser);
      if (idx >= 0) userCreations.splice(idx, 1);
    }
  }, 3600000);
});

app.post("/api/register/complete", async (req: Request, res: Response) => {
  try {
    if (
      "uuid" in req.body &&
      "username" in req.body &&
      "public_key" in req.body &&
      "private_key_hash" in req.body &&
      "iota_id" in req.body &&
      "reset_token" in req.body
    ) {
      let newUsername = sanitizeUsername(String(req.body.username));

      if (userCreations.includes(req.body.uuid)) {
        db.add(
          req.body.uuid,
          req.body.public_key,
          req.body.private_key_hash,
          newUsername,
          req.body.reset_token,
          req.body.iota_id,
          Date.now()
        );
        {
          const idx = userCreations.indexOf(req.body.uuid);
          if (idx >= 0) userCreations.splice(idx, 1);
        }
      } else {
        sendError(res, "User creation failed do to invalid UUID", 1, 400);
        return;
      }
      // Success Message
      sendSuccess(res, `Created User: ${req.body.uuid}`, 0);
    } else {
      sendError(res, "User creation failed do to missing values", 1, 400);
    }
  } catch (err) {
    const errorDetail = err instanceof Error ? err.message : String(err);
    const clientMessage = "User registration failed";
    sendError(res, `${clientMessage}: ${errorDetail}`, 1, {
      statusCode: 500,
      error: err,
      logMessage: clientMessage,
    });
  }
});

app.post("/api/delete/:uuid", async (req: Request, res: Response) => {
  const uuid = req.params.uuid;

  try {
    if ("reset_token" in req.body) {
      unwrap(await db.remove(uuid, req.body.reset_token));
      sendSuccess(res, `Deleted User: ${uuid}`, 0);
    } else {
      sendError(res, "User creation failed do to missing values", 1, 400);
    }
  } catch (err) {
    const errorDetail = err instanceof Error ? err.message : String(err);
    const clientMessage = "User deletion failed";
    sendError(res, `${clientMessage}: ${errorDetail}`, 1, {
      statusCode: 500,
      error: err,
      logMessage: clientMessage,
    });
  }
});

// Omikron Endpoints
app.get(
  "/api/get/private-key-hash/:uuid",
  async (req: Request, res: Response) => {
    const uuid = req.params.uuid;

    try {
      if (
        typeof req.headers.authorization === "string" &&
        typeof req.headers.privatekeyhash === "string"
      ) {
        let isLegitOmikron = await ensureOmikronAuth(req.headers.authorization);
        if (isLegitOmikron) {
          const user = unwrapGet(await db.get(uuid));
          const { private_key_hash } = user as any;
          sendSuccess(res, "Got private key hash", 1, {
            matches: req.headers.privatekeyhash === private_key_hash,
          });
        } else throw new Error("Permission Denied");
      } else throw new Error("Permission Denied");
    } catch (err) {
      const errorDetail = err instanceof Error ? err.message : String(err);
      const clientMessage = "Failed to get private key hash";
      sendError(res, `${clientMessage}: ${errorDetail}`, 1, {
        error: err,
        logMessage: clientMessage,
      });
    }
  }
);

app.get("/api/get/iota-id/:uuid", async (req: Request, res: Response) => {
  const uuid = req.params.uuid;
  try {
    if (typeof req.headers.authorization === "string") {
      let isLegitOmikron = await ensureOmikronAuth(req.headers.authorization);
      if (isLegitOmikron) {
        const user = unwrapGet(await db.get(uuid));
        const { iota_id } = user as any;
        sendSuccess(res, "Got iota id", 1, { iota_id });
      } else throw new Error("Permission Denied");
    } else throw new Error("Permission Denied");
  } catch (err) {
    const errorDetail = err instanceof Error ? err.message : String(err);
    const clientMessage = "Failed to get iota id";
    sendError(res, `${clientMessage}: ${errorDetail}`, 1, {
      error: err,
      logMessage: clientMessage,
    });
  }
});

// Start Server
app.listen(port, async () => {
  await db.init();
  console.log(
    `> Started at http://0.0.0.0:${port} / https://auth-tensamin.methanium.net`
  );
});

// Database Disconnect Cleanup
process.on("SIGINT", db.close);
process.on("SIGTERM", db.close);
process.on("uncaughtException", async (err: unknown) => {
  logger.logError("Uncaught exception", err);
  await db.close();
});

process.on("unhandledRejection", (reason: unknown) => {
  logger.logError("Unhandled promise rejection", reason);
});
