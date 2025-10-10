// Imports
import { load } from "@std/dotenv";
import { decodeBase64 } from "@std/encoding/base64";
import { generate as generateUuidV7 } from "@std/uuid/unstable-v7";
import sharp from "sharp";
import { Buffer } from "node:buffer";

// Modules
import * as db from "./db.ts";
import { User, JsonRecord } from "./types.ts";
import { hasKeys, sanitizeUsername, avatarToDataUri } from "./utils.ts";

// Main
await load({ export: true, allowEmptyValues: true }).catch((error) => {
  console.warn("Failed to load .env file", error);
});

await db.init();

const port = Number(Deno.env.get("PORT") ?? "9187");
const primaryOrigin = "https://tensamin.methanium.net";
const allowedOrigins = new Set<string>([
  primaryOrigin,
  "app://dist",
  "http://localhost:3000",
]);

const userCreations = new Set<string>();

function resolveCorsOrigin(request: Request): string | null {
  const origin = request.headers.get("Origin");
  if (!origin) return primaryOrigin;
  if (allowedOrigins.has(origin)) return origin;
  try {
    const parsed = new URL(origin);
    const host = parsed.hostname;
    if (host === "localhost" || host === "127.0.0.1" || host === "::1") {
      return origin;
    }
  } catch (error) {
    console.error("Failed to parse CORS origin", error);
  }
  return null;
}

function buildCorsHeaders(
  origin: string | null,
  includeContentType = true
): Headers {
  const headers = new Headers({
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS",
    Vary: "Origin",
  });
  if (includeContentType) {
    headers.set("Content-Type", "application/json; charset=utf-8");
  }
  if (origin) {
    headers.set("Access-Control-Allow-Origin", origin);
  }
  return headers;
}

function buildJsonResponse(
  body: unknown,
  origin: string | null,
  status = 200
): Response {
  const headers = buildCorsHeaders(origin, true);
  return new Response(JSON.stringify(body), { status, headers });
}

function sendSuccess(
  origin: string | null,
  message: string,
  logLevel: number,
  data?: JsonRecord,
  status = 200
): Response {
  const payload: JsonRecord = {
    type: "success",
    log: { message, log_level: logLevel },
  };
  if (data !== undefined) {
    payload.data = data;
  }
  return buildJsonResponse(payload, origin, status);
}

function sendError(
  origin: string | null,
  message: string,
  logLevel: number,
  options: {
    status?: number;
    error?: unknown;
    logMessage?: string;
  } = {}
): Response {
  const { status = 500, error, logMessage } = options;
  console.error(logMessage ?? message, error);
  const payload = {
    type: "error",
    log: { message, log_level: logLevel },
  };
  return buildJsonResponse(payload, origin, status);
}

async function adjustAvatar(
  base64Input: string,
  bypass: boolean
): Promise<Uint8Array | null> {
  if (!base64Input || base64Input === "") return null;

  const quality = bypass ? 100 : 30;

  try {
    const base64Data = base64Input.split(";base64,").pop() ?? base64Input;
    const input = decodeBase64(base64Data);
    const processed = await sharp(Buffer.from(input))
      .resize({ width: 450, height: 450, fit: "inside" })
      .webp({ quality, effort: 6 })
      .toBuffer();
    return new Uint8Array(processed);
  } catch (error) {
    throw error instanceof Error ? error : new Error(String(error));
  }
}

async function updateUser(uuid: string, user: User): Promise<void> {
  unwrap(await db.update(uuid, user));
}

async function ensureOmikronAuth(authHeader: unknown): Promise<boolean> {
  if (typeof authHeader !== "string") return false;
  return unwrap<boolean>(await db.checkLegitimacy(authHeader));
}

function unwrapGet(
  result: User | null | Error,
  notFoundMsg = "Not found"
): User {
  if (result instanceof Error) throw result;
  if (!result) throw new Error(notFoundMsg);
  return result;
}

function unwrap<T>(result: T | Error, msg = "Operation failed"): T {
  if (result instanceof Error) {
    throw new Error(`${msg}: ${result.message}`);
  }
  return result;
}

function buildForbiddenResponse(): Response {
  const headers = buildCorsHeaders(null, true);
  return new Response(
    JSON.stringify({
      type: "error",
      log: { message: "CORS origin rejected", log_level: 1 },
    }),
    { status: 403, headers }
  );
}

const handler: Deno.ServeHandler = async (request) => {
  const origin = resolveCorsOrigin(request);

  if (request.method === "OPTIONS") {
    if (!origin) {
      return new Response(null, {
        status: 403,
        headers: buildCorsHeaders(null, false),
      });
    }
    return new Response(null, {
      status: 204,
      headers: buildCorsHeaders(origin, false),
    });
  }

  if (!origin) {
    return buildForbiddenResponse();
  }

  const url = new URL(request.url);
  const { pathname } = url;

  try {
    if (request.method === "GET") {
      if (pathname.startsWith("/api/get/uuid/")) {
        const match = pathname.match(/^\/api\/get\/uuid\/([^/]+)$/);
        if (!match) {
          return sendError(origin, "Invalid username path", 1, { status: 400 });
        }
        const username = decodeURIComponent(match[1]);
        try {
          const result = await db.uuid(username);
          const userUuid = unwrap<string>(result, "UUID lookup failed");
          return sendSuccess(origin, `Got uuid for ${username}`, 0, {
            user_id: userUuid,
          });
        } catch (error) {
          const message =
            error instanceof Error ? error.message : String(error);
          return sendError(
            origin,
            `Failed to get uuid for supplied username: ${message}`,
            1,
            {
              error,
              logMessage: "Failed to get uuid for supplied username",
            }
          );
        }
      }

      if (pathname.startsWith("/api/get/")) {
        const match = pathname.match(/^\/api\/get\/([^/]+)$/);
        if (!match) {
          return sendError(origin, "Invalid user path", 1, { status: 400 });
        }
        const userId = decodeURIComponent(match[1]);
        try {
          const user = unwrapGet(await db.get(userId), "User not found");
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
          } = user;

          return sendSuccess(origin, "Got user", 0, {
            created_at,
            username,
            display,
            avatar: avatarToDataUri(avatar),
            about,
            status,
            public_key,
            sub_level,
            sub_end,
          });
        } catch (error) {
          const message =
            error instanceof Error ? error.message : String(error);
          return sendError(
            origin,
            `Failed to retrieve user profile: ${message}`,
            1,
            {
              error,
              logMessage: "Failed to retrieve user profile",
            }
          );
        }
      }

      if (pathname === "/api/register/init") {
        const newUser = generateUuidV7();
        userCreations.add(newUser);
        setTimeout(() => {
          userCreations.delete(newUser);
        }, 3_600_000);

        return sendSuccess(origin, "Started user registration progress", 0, {
          user_id: newUser,
        });
      }

      if (pathname.startsWith("/api/get/private-key-hash/")) {
        const match = pathname.match(/^\/api\/get\/private-key-hash\/([^/]+)$/);
        if (!match) {
          return sendError(origin, "Invalid user path", 1, { status: 400 });
        }
        const userId = decodeURIComponent(match[1]);
        try {
          const authorization = request.headers.get("authorization");
          const privateKeyHash = request.headers.get("privatekeyhash");
          if (!authorization || !privateKeyHash) {
            throw new Error("Permission Denied");
          }
          const isLegit = await ensureOmikronAuth(authorization);
          if (!isLegit) throw new Error("Permission Denied");

          const user = unwrapGet(await db.get(userId));
          return sendSuccess(origin, "Got private key hash", 1, {
            matches: privateKeyHash === user.private_key_hash,
          });
        } catch (error) {
          const message =
            error instanceof Error ? error.message : String(error);
          return sendError(
            origin,
            `Failed to get private key hash: ${message}`,
            1,
            {
              error,
              logMessage: "Failed to get private key hash",
            }
          );
        }
      }

      if (pathname.startsWith("/api/get/iota-id/")) {
        const match = pathname.match(/^\/api\/get\/iota-id\/([^/]+)$/);
        if (!match) {
          return sendError(origin, "Invalid user path", 1, { status: 400 });
        }
        const userId = decodeURIComponent(match[1]);
        try {
          const authorization = request.headers.get("authorization");
          if (!authorization) {
            throw new Error("Permission Denied");
          }
          const isLegit = await ensureOmikronAuth(authorization);
          if (!isLegit) throw new Error("Permission Denied");

          const user = unwrapGet(await db.get(userId));
          return sendSuccess(origin, "Got iota id", 1, {
            iota_id: user.iota_id,
          });
        } catch (error) {
          const message =
            error instanceof Error ? error.message : String(error);
          return sendError(origin, `Failed to get iota id: ${message}`, 1, {
            error,
            logMessage: "Failed to get iota id",
          });
        }
      }
    }

    if (request.method === "POST") {
      if (pathname.startsWith("/api/change/iota-id/")) {
        const match = pathname.match(/^\/api\/change\/iota-id\/([^/]+)$/);
        if (!match) {
          return sendError(origin, "Invalid user path", 1, { status: 400 });
        }
        const userId = decodeURIComponent(match[1]);
        const body = await request.json().catch(() => null);

        try {
          if (!hasKeys(body, ["reset_token", "new_token", "iota_id"])) {
            throw new Error("Missing Values");
          }

          const user = unwrapGet(await db.get(userId));
          if (body.reset_token !== user.token) {
            throw new Error("Permission Denied");
          }

          user.iota_id = String(body.iota_id);
          user.token = String(body.new_token);

          await updateUser(userId, user);
          console.log("Updated iota id for user:", userId);
          return sendSuccess(origin, "Changed iota id", 0);
        } catch (error) {
          const message =
            error instanceof Error ? error.message : String(error);
          return sendError(origin, `Failed to change iota id: ${message}`, 0, {
            error,
            logMessage: "Failed to change iota id",
          });
        }
      }

      if (pathname.startsWith("/api/change/keys/")) {
        const match = pathname.match(/^\/api\/change\/keys\/([^/]+)$/);
        if (!match) {
          return sendError(origin, "Invalid user path", 1, { status: 400 });
        }
        const userId = decodeURIComponent(match[1]);
        const body = await request.json().catch(() => null);

        try {
          if (
            !hasKeys(body, [
              "reset_token",
              "new_token",
              "private_key_hash",
              "public_key",
            ])
          ) {
            throw new Error("Missing Values");
          }

          const user = unwrapGet(await db.get(userId));
          if (body.reset_token !== user.token) {
            throw new Error("Permission Denied");
          }

          user.private_key_hash = String(body.private_key_hash);
          user.public_key = String(body.public_key);
          user.token = String(body.new_token);

          await updateUser(userId, user);
          return sendSuccess(origin, "Changed keys", 0);
        } catch (error) {
          const message =
            error instanceof Error ? error.message : String(error);
          return sendError(origin, `Failed to change keys: ${message}`, 0, {
            error,
            logMessage: "Failed to change keys",
          });
        }
      }

      if (pathname.startsWith("/api/change/")) {
        const match = pathname.match(/^\/api\/change\/([^/]+)$/);
        if (!match) {
          return sendError(origin, "Invalid user path", 1, { status: 400 });
        }
        const userId = decodeURIComponent(match[1]);
        const body = await request.json().catch(() => null);

        try {
          if (!hasKeys(body, ["private_key_hash"])) {
            throw new Error("Missing Values");
          }

          const user = unwrapGet(await db.get(userId));
          if (body.private_key_hash !== user.private_key_hash) {
            throw new Error("Permission Denied");
          }

          for (const [key, value] of Object.entries(body)) {
            switch (key) {
              case "username":
                user.username = sanitizeUsername(String(value));
                break;
              case "display":
                user.display = typeof value === "string" ? value : undefined;
                break;
              case "about":
                user.about =
                  typeof value === "string" ? value : String(value ?? "");
                break;
              case "status":
                user.status = typeof value === "string" ? value : undefined;
                break;
              case "avatar":
                user.avatar = await adjustAvatar(
                  String(value ?? ""),
                  (user.sub_level ?? 0) >= 1
                );
                break;
            }
          }

          await updateUser(userId, user);
          return sendSuccess(origin, "Changed user", 0, {
            ...user,
            avatar: avatarToDataUri(user.avatar),
          });
        } catch (error) {
          const message =
            error instanceof Error ? error.message : String(error);
          return sendError(origin, `Failed to change user: ${message}`, 0, {
            error,
            logMessage: "Failed to change user",
          });
        }
      }

      if (pathname === "/api/register/complete") {
        const body = await request.json().catch(() => null);

        try {
          if (
            !hasKeys(body, [
              "uuid",
              "username",
              "public_key",
              "private_key_hash",
              "iota_id",
              "reset_token",
            ])
          ) {
            throw new Error("User creation failed due to missing values");
          }

          const newUsername = sanitizeUsername(String(body.username));
          const userId = String(body.uuid);

          if (!userCreations.has(userId)) {
            throw new Error("User creation failed due to invalid UUID");
          }

          unwrap(
            await db.add(
              userId,
              String(body.public_key),
              String(body.private_key_hash),
              newUsername,
              String(body.reset_token),
              String(body.iota_id),
              Date.now()
            )
          );
          userCreations.delete(userId);

          return sendSuccess(origin, `Created User: ${userId}`, 0);
        } catch (error) {
          const message =
            error instanceof Error ? error.message : String(error);
          return sendError(origin, `User registration failed: ${message}`, 1, {
            status: 500,
            error,
            logMessage: "User registration failed",
          });
        }
      }

      if (pathname.startsWith("/api/delete/")) {
        const match = pathname.match(/^\/api\/delete\/([^/]+)$/);
        if (!match) {
          return sendError(origin, "Invalid user path", 1, { status: 400 });
        }
        const userId = decodeURIComponent(match[1]);
        const body = await request.json().catch(() => null);

        try {
          if (!hasKeys(body, ["reset_token"])) {
            throw new Error("User deletion failed due to missing values");
          }

          unwrap(await db.remove(userId, String(body.reset_token)));
          return sendSuccess(origin, `Deleted User: ${userId}`, 0);
        } catch (error) {
          const message =
            error instanceof Error ? error.message : String(error);
          return sendError(origin, `User deletion failed: ${message}`, 1, {
            status: 500,
            error,
            logMessage: "User deletion failed",
          });
        }
      }
    }

    return sendError(origin, "Route not found", 1, { status: 404 });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return sendError(origin, `Internal server error: ${message}`, 1, {
      status: 500,
      error,
      logMessage: "Unhandled request error",
    });
  }
};

self.addEventListener("error", (event) => {
  console.error("Unhandled error", event.error);
});

self.addEventListener("unhandledrejection", (event) => {
  console.error("Unhandled promise rejection", event.reason);
});

Deno.serve(
  {
    hostname: "0.0.0.0",
    port,
    onListen: ({ hostname, port }) => {
      console.log(
        `> Started at http://${hostname}:${port} / https://auth-tensamin.methanium.net`
      );
    },
  },
  handler
);

Deno.addSignalListener("SIGINT", async () => {
  await db.close();
  Deno.exit();
});

Deno.addSignalListener("SIGTERM", async () => {
  await db.close();
  Deno.exit();
});
