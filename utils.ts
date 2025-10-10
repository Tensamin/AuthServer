import { encodeBase64 } from "@std/encoding/base64";

import { JsonRecord } from "./types.ts";

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
  return `data:image/webp;base64,${encodeBase64(avatar)}`;
}
