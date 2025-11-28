import { Buffer } from "node:buffer";
import type { JsonRecord } from "./types.ts";

const activeChallenge = new Map<
  string,
  {
    hash: string;
    expiresAt: number;
    userId: string;
  }
>();

export function hasKeys(obj: unknown, keys: string[]): obj is JsonRecord {
  if (!obj || typeof obj !== "object") return false;
  return keys.every((key) => Object.prototype.hasOwnProperty.call(obj, key));
}

export function sanitizeUsername(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9_]/g, "");
}

export function avatarToDataUri(
  avatar: Uint8Array | null | undefined
): string | null {
  if (!avatar) return null;
  return `data:image/webp;base64,${Buffer.from(avatar).toString("base64")}`;
}

export async function getChallenge(userId: string) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const challengeHex = Buffer.from(challenge).toString("hex");

  // Store hashed challenge (never store plaintext)
  const hash = await hashChallenge(challengeHex);
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 min expiry

  activeChallenge.set(hash, { hash, expiresAt, userId });

  return {
    challenge: challengeHex,
    expiresIn: 5 * 60, // seconds
  };
}

export async function verifyChallenge(
  userId: string,
  challenge: string,
  signature: string,
  publicKeyPem: string
) {
  const hash = await hashChallenge(challenge);
  const stored = activeChallenge.get(hash);

  // Verify challenge exists and isn't expired
  if (!stored || Date.now() > stored.expiresAt) {
    throw new Error("Invalid or expired challenge");
  }

  // Verify user matches
  if (stored.userId !== userId) {
    throw new Error("Challenge mismatch");
  }

  // Verify signature using public key
  const isValid = await verifySignature(challenge, signature, publicKeyPem);

  if (!isValid) {
    throw new Error("Invalid signature");
  }

  // Mark challenge as used (delete it)
  activeChallenge.delete(hash);

  return { authenticated: true };
}

async function hashChallenge(challenge: string): Promise<string> {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(challenge)
  );
  return Buffer.from(hash).toString("hex");
}

async function verifySignature(
  challenge: string,
  signatureHex: string,
  publicKeyPem: string
): Promise<boolean> {
  const publicKey = await crypto.subtle.importKey(
    "spki",
    pemToArrayBuffer(publicKeyPem),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  return await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    Buffer.from(signatureHex, "hex"),
    new TextEncoder().encode(challenge)
  );
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const binaryString = atob(pem.replace(/-----[\w\s]+-----/g, ""));
  return new Uint8Array([...binaryString].map((c) => c.charCodeAt(0))).buffer;
}
