// Package Imports
import { serve } from "bun";
import { Buffer } from "node:buffer";
import sharp from "sharp";
import { AccessToken } from "livekit-server-sdk";
import * as Sentry from "@sentry/bun";

// Lib Imports
import * as db from "./db";
import type { User, JsonRecord } from "./types";
import { hasKeys, sanitizeUsername, avatarToDataUri } from "./utils";

// Main
if (typeof Bun === "undefined") {
  throw new Error("This service requires the Bun runtime.");
}

Sentry.init({
  dsn: "https://f78b74dd4d581032911e8f5c01d5a8c5@o4510490767851520.ingest.de.sentry.io/4510490775781456",
});

await db.init();

const port = Number(Bun.env.PORT ?? "9187");
const primaryOrigin = "https://app.tensamin.net";
const allowedOrigins = new Set<string>([
  primaryOrigin,
  "http://localhost:3000",
  "app://.",
]);

const userCreations = new Set<number>();
let isShuttingDown = false;

function assertString(value: unknown, field: string): string {
  if (typeof value === "string") {
    return value;
  }
  throw new TypeError(`${field} must be a string`);
}

async function readJsonBody(request: Request): Promise<unknown> {
  try {
    return await (request.json() as Promise<unknown>);
  } catch {
    return null;
  }
}

function decodeBase64(input: string): Uint8Array {
  return new Uint8Array(Buffer.from(input, "base64"));
}

function toUserPayload(user: User): JsonRecord {
  const {
    id,
    username,
    display,
    avatar,
    about,
    status,
    public_key,
    sub_level,
    sub_end,
  } = user;

  return {
    id,
    username,
    display,
    avatar: avatarToDataUri(avatar),
    about,
    status,
    public_key,
    sub_level,
    sub_end,
  } satisfies JsonRecord;
}

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
  } catch {}
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
  data?: JsonRecord,
  status = 200
): Response {
  const payload: JsonRecord = {
    type: "success",
  };
  if (data !== undefined) {
    payload.data = data;
  }
  return buildJsonResponse(payload, origin, status);
}

function sendError(
  origin: string | null,
  options: {
    status?: number;
    error?: unknown;
    logMessage?: string;
  } = {}
): Response {
  const { status = 500, error, logMessage } = options;
  const payload = {
    type: "error",
    data: {
      error,
      logMessage,
    },
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
      .resize({
        width: bypass ? 450 : 250,
        height: bypass ? 450 : 250,
        fit: "cover",
      })
      .webp({ quality, effort: 6 })
      .toBuffer();
    return new Uint8Array(processed);
  } catch (error) {
    throw error instanceof Error ? error : new Error(String(error));
  }
}

async function updateUser(id: number, user: Partial<User>): Promise<void> {
  unwrap(await db.update(id, user));
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

function splitPathSegments(pathname: string): string[] {
  return pathname.split("/").filter(Boolean);
}

function handleRegisterInit(origin: string): Response {
  const newUser = Date.now();
  userCreations.add(newUser);
  setTimeout(() => {
    userCreations.delete(newUser);
  }, 3_600_000);

  return sendSuccess(origin, {
    user_id: newUser,
  });
}

async function handleGetRoutes(
  segments: string[],
  request: Request,
  origin: string
): Promise<Response | null> {
  if (segments.length === 0) {
    return null;
  }

  const [resource, ...rest] = segments;

  if (resource === "register") {
    if (rest.length === 1 && rest[0] === "init") {
      return handleRegisterInit(origin);
    }
    return null;
  }

  if (resource === "get") {
    return handleGetResource(rest, request, origin);
  }

  return null;
}

async function handleGetResource(
  segments: string[],
  request: Request,
  origin: string
): Promise<Response> {
  if (segments.length === 0) {
    return sendError(origin, { status: 400, logMessage: "Invalid user path" });
  }

  const [subResource, ...rest] = segments;

  switch (subResource) {
    case "id":
      if (rest.length !== 1) {
        return sendError(origin, {
          status: 400,
          logMessage: "Invalid username path",
        });
      }
      return handleGetId(rest[0], origin);
    case "private-key-hash":
      if (rest.length !== 1) {
        return sendError(origin, {
          status: 400,
          logMessage: "Invalid user path",
        });
      }
      return handleGetPrivateKeyHash(rest[0], request, origin);
    case "iota-id":
      if (rest.length !== 1) {
        return sendError(origin, {
          status: 400,
          logMessage: "Invalid user path",
        });
      }
      return handleGetIotaId(rest[0], request, origin);
    default:
      if (rest.length !== 0) {
        return sendError(origin, {
          status: 400,
          logMessage: "Invalid user path",
        });
      }
      return handleGetUserProfile(subResource, origin);
  }
}

async function handleGetId(
  identifierSegment: string,
  origin: string
): Promise<Response> {
  const identifier = decodeURIComponent(identifierSegment);
  const identifierLooksLikeId = /^\d+$/.test(identifier);

  try {
    if (identifierLooksLikeId) {
      return sendSuccess(origin, {
        user_id: Number(identifier),
      });
    }

    const result = await db.id(identifier);
    const userId = unwrap<number>(result, "ID lookup failed");
    return sendSuccess(origin, {
      user_id: userId,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return sendError(origin, {
      error,
      logMessage: message,
    });
  }
}

async function handleGetPrivateKeyHash(
  userIdSegment: string,
  request: Request,
  origin: string
): Promise<Response> {
  const userId = Number(decodeURIComponent(userIdSegment));

  try {
    const authorization = request.headers.get("authorization");
    const privateKeyHash = request.headers.get("privatekeyhash");
    if (!authorization || !privateKeyHash) {
      throw new Error("Permission Denied");
    }
    const isLegit = await ensureOmikronAuth(authorization);
    if (!isLegit) throw new Error("Permission Denied");

    const user = unwrapGet(await db.get(userId));
    return sendSuccess(origin, {
      matches: privateKeyHash === user.private_key_hash,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return sendError(origin, {
      error,
      logMessage: message,
    });
  }
}

async function handleGetIotaId(
  userIdSegment: string,
  request: Request,
  origin: string
): Promise<Response> {
  const userId = Number(decodeURIComponent(userIdSegment));

  try {
    const authorization = request.headers.get("authorization");
    if (!authorization) {
      throw new Error("Permission Denied");
    }
    const isLegit = await ensureOmikronAuth(authorization);
    if (!isLegit) throw new Error("Permission Denied");

    const user = unwrapGet(await db.get(userId));
    return sendSuccess(origin, {
      iota_id: user.iota_id,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return sendError(origin, {
      error,
      logMessage: message,
    });
  }
}

async function handleGetUserProfile(
  userIdSegment: string,
  origin: string
): Promise<Response> {
  const userId = Number(decodeURIComponent(userIdSegment));

  try {
    const user = unwrapGet(await db.get(userId), "User not found");
    return sendSuccess(origin, toUserPayload(user));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return sendError(origin, {
      error,
      logMessage: message,
    });
  }
}

async function handlePostRoutes(
  segments: string[],
  request: Request,
  origin: string
): Promise<Response | null> {
  if (segments.length === 0) {
    return null;
  }

  const [resource, ...rest] = segments;

  if (resource === "change") {
    return handleChangeRoutes(rest, request, origin);
  }

  if (resource === "register" && rest.length === 1 && rest[0] === "complete") {
    return handleRegisterComplete(request, origin);
  }

  if (resource === "delete" && rest.length === 1) {
    return handleDeleteUser(rest[0], request, origin);
  }

  if (resource === "call_token") {
    return handleGetCallToken(request, origin);
  }

  return null;
}

async function handleGetCallToken(
  request: Request,
  origin: string
): Promise<Response> {
  const body = await readJsonBody(request);

  try {
    if (!hasKeys(body, ["call_id", "user_id", "private_key_hash"])) {
      throw new Error("Missing Values");
    }

    const callId = body.call_id as string;
    const userId = Number(body.user_id);
    const privateKeyHash = body.private_key_hash;

    const user = unwrapGet(await db.get(userId));
    if (user.private_key_hash !== privateKeyHash) {
      throw new Error("Permission Denied");
    }

    const token = new AccessToken(
      process.env.LIVEKIT_API_KEY!,
      process.env.LIVEKIT_API_SECRET!,
      {
        identity: String(userId),
        ttl: "10m",
      }
    );

    token.addGrant({
      roomJoin: true,
      room: callId,
      canUpdateOwnMetadata: true,
    });

    return sendSuccess(origin, {
      token: await token.toJwt(),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return sendError(origin, {
      status: 400,
      error,
      logMessage: message,
    });
  }
}

async function handleChangeRoutes(
  segments: string[],
  request: Request,
  origin: string
): Promise<Response> {
  if (segments.length === 0) {
    return sendError(origin, { status: 400, logMessage: "Invalid user path" });
  }

  const [subResource, ...rest] = segments;

  if (subResource === "iota-id") {
    if (rest.length !== 1) {
      return sendError(origin, {
        status: 400,
        logMessage: "Invalid user path",
      });
    }
    return handleChangeIotaId(rest[0], request, origin);
  }

  if (subResource === "keys") {
    if (rest.length !== 1) {
      return sendError(origin, {
        status: 400,
        logMessage: "Invalid user path",
      });
    }
    return handleChangeKeys(rest[0], request, origin);
  }

  if (rest.length === 0) {
    return handleChangeUser(subResource, request, origin);
  }

  return sendError(origin, { status: 400, logMessage: "Invalid user path" });
}

async function handleChangeIotaId(
  userIdSegment: string,
  request: Request,
  origin: string
): Promise<Response> {
  const userId = Number(decodeURIComponent(userIdSegment));
  const body = await readJsonBody(request);

  try {
    if (!hasKeys(body, ["reset_token", "new_token", "iota_id"])) {
      throw new Error("Missing Values");
    }

    const user = unwrapGet(await db.get(userId));
    const resetToken = assertString(body.reset_token, "reset_token");
    if (resetToken !== user.token) {
      throw new Error("Permission Denied");
    }

    user.iota_id = body.iota_id as number;
    user.token = assertString(body.new_token, "new_token");

    await updateUser(userId, user);
    return sendSuccess(origin);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return sendError(origin, {
      error,
      logMessage: message,
    });
  }
}

async function handleChangeKeys(
  userIdSegment: string,
  request: Request,
  origin: string
): Promise<Response> {
  const userId = Number(decodeURIComponent(userIdSegment));
  const body = await readJsonBody(request);

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
    const resetToken = assertString(body.reset_token, "reset_token");
    if (resetToken !== user.token) {
      throw new Error("Permission Denied");
    }

    user.private_key_hash = assertString(
      body.private_key_hash,
      "private_key_hash"
    );
    user.public_key = assertString(body.public_key, "public_key");
    user.token = assertString(body.new_token, "new_token");

    await updateUser(userId, user);
    return sendSuccess(origin);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return sendError(origin, {
      error,
      logMessage: message,
    });
  }
}

async function handleChangeUser(
  userIdSegment: string,
  request: Request,
  origin: string
): Promise<Response> {
  const userId = Number(decodeURIComponent(userIdSegment));
  const body = await readJsonBody(request);

  try {
    if (!hasKeys(body, ["private_key_hash"])) {
      throw new Error("Missing Values");
    }

    const user = unwrapGet(await db.get(userId));
    const providedHash = assertString(
      body.private_key_hash,
      "private_key_hash"
    );
    if (providedHash !== user.private_key_hash) {
      throw new Error("Permission Denied");
    }

    for (const [key, value] of Object.entries(body)) {
      switch (key) {
        case "username":
          user.username = sanitizeUsername(assertString(value, "username"));
          break;
        case "display":
          if (typeof value === "string") {
            user.display = value;
          } else if (value === null || value === undefined) {
            user.display = undefined;
          }
          break;
        case "about":
          if (typeof value === "string") {
            user.about = value;
          } else if (value === null || value === undefined) {
            user.about = "";
          }
          break;
        case "status":
          if (typeof value === "string") {
            user.status = value;
          } else if (value === null || value === undefined) {
            user.status = undefined;
          }
          break;
        case "avatar":
          if (typeof value === "string") {
            user.avatar = await adjustAvatar(value, (user.sub_level ?? 0) >= 1);
          } else if (value === null || value === undefined) {
            user.avatar = null;
          }
          break;
      }
    }

    await updateUser(userId, user);
    return sendSuccess(origin, {
      ...user,
      avatar: avatarToDataUri(user.avatar),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return sendError(origin, {
      error,
      logMessage: message,
    });
  }
}

async function handleRegisterComplete(
  request: Request,
  origin: string
): Promise<Response> {
  const body = await readJsonBody(request);

  try {
    if (
      !hasKeys(body, [
        "id",
        "username",
        "public_key",
        "private_key_hash",
        "iota_id",
        "reset_token",
      ])
    ) {
      throw new Error("User creation failed due to missing values");
    }

    const newUsername = sanitizeUsername(
      assertString(body.username, "username")
    );
    const userId = Number(body.id);

    if (!userCreations.has(userId)) {
      throw new Error("User creation failed due to invalid ID");
    }

    unwrap(
      await db.add(
        userId,
        assertString(body.public_key, "public_key"),
        assertString(body.private_key_hash, "private_key_hash"),
        newUsername,
        assertString(body.reset_token, "reset_token"),
        body.iota_id as number
      )
    );
    userCreations.delete(userId);

    return sendSuccess(origin);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return sendError(origin, {
      status: 500,
      error,
      logMessage: message,
    });
  }
}

async function handleDeleteUser(
  userIdSegment: string,
  request: Request,
  origin: string
): Promise<Response> {
  const userId = Number(decodeURIComponent(userIdSegment));
  const body = await readJsonBody(request);

  try {
    if (!hasKeys(body, ["reset_token"])) {
      throw new Error("User deletion failed due to missing values");
    }

    unwrap(
      await db.remove(userId, assertString(body.reset_token, "reset_token"))
    );
    return sendSuccess(origin);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return sendError(origin, {
      status: 500,
      error,
      logMessage: message,
    });
  }
}

const handler = async (request: Request): Promise<Response> => {
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

  const { pathname } = new URL(request.url);
  const segments = splitPathSegments(pathname);

  if (segments[0] !== "api") {
    return sendError(origin, { status: 404, logMessage: "Route not found" });
  }

  const resourceSegments = segments.slice(1);

  try {
    const { method } = request;

    if (method === "GET") {
      const response = await handleGetRoutes(resourceSegments, request, origin);
      if (response) return response;
    } else if (method === "POST") {
      const response = await handlePostRoutes(
        resourceSegments,
        request,
        origin
      );
      if (response) return response;
    }

    if (resourceSegments[0] === "get" && method !== "GET") {
      return handleGetResource(resourceSegments.slice(1), request, origin);
    }

    return sendError(origin, { status: 404, logMessage: "Route not found" });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return sendError(origin, {
      status: 500,
      error,
      logMessage: message,
    });
  }
};

const server = serve({
  hostname: "0.0.0.0",
  port,
  fetch: handler,
  error(error: unknown) {
    console.error("Unhandled server error", error);
    return new Response("Internal Server Error", { status: 500 });
  },
});

console.log(
  `> Started at http://${server.hostname}:${server.port} / https://auth.${primaryOrigin}`
);

const shutdown = async (): Promise<void> => {
  if (isShuttingDown) return;
  isShuttingDown = true;

  try {
    await db.close();
  } finally {
    await server.stop(true);
    process.exit(0);
  }
};

process.once("SIGINT", () => {
  void shutdown().catch((error) => {
    console.error("Failed to shutdown gracefully after SIGINT", error);
  });
});

process.once("SIGTERM", () => {
  void shutdown().catch((error) => {
    console.error("Failed to shutdown gracefully after SIGTERM", error);
  });
});
