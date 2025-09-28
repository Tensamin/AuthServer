import { promises as fs } from "fs";
import path from "path";

const MAX_SESSION_LINES = 1000;
const LOG_DIR = path.resolve(process.cwd(), "logs");
const ERROR_DIR = path.join(LOG_DIR, "errors");
const SESSION_LOG_PATH = path.join(LOG_DIR, "session.log");

const uuidRegex = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const emailRegex = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;

type LogLevel = "INFO" | "ERROR";

let initialized = false;
let sessionLines: string[] = [];
let sessionWriteQueue: Promise<void> = Promise.resolve();
let lastErrorBase = "";
let duplicateCounter = 0;

const originalConsoleLog = console.log.bind(console);
const originalConsoleError = console.error.bind(console);

export async function initLogger(): Promise<void> {
  if (initialized) return;

  await fs.mkdir(ERROR_DIR, { recursive: true });
  await fs.writeFile(SESSION_LOG_PATH, "", "utf8");
  sessionLines = [];
  overrideConsole();
  initialized = true;
}

export function logError(message: string, error?: unknown): void {
  const now = new Date();
  const sanitizedMessage = redactSensitive(message);
  const sanitizedTrace = redactSensitive(extractTrace(error));
  const filePath = allocateErrorFilePath(now);
  const body = [
    `Timestamp: ${formatTimestamp(now)}`,
    `Message: ${sanitizedMessage}`,
    "",
    "Trace:",
    sanitizedTrace || "[no trace available]",
    "",
  ].join("\n");

  void fs.writeFile(filePath, body, "utf8").catch((err) => {
    originalConsoleError("Failed to write error log:", err);
  });

  const combined = sanitizedTrace
    ? `${sanitizedMessage}\n${sanitizedTrace}`
    : sanitizedMessage;
  console.error(combined);
}

function overrideConsole(): void {
  console.log = (...args: unknown[]) => {
    originalConsoleLog(...args);
    const message = normalizeArgs(args);
    queueSessionLine("INFO", message);
  };

  console.error = (...args: unknown[]) => {
    originalConsoleError(...args);
    const message = normalizeArgs(args);
    queueSessionLine("ERROR", message);
  };
}

function normalizeArgs(args: unknown[]): string {
  return args
    .map((arg) => {
      if (typeof arg === "string") return arg;
      if (arg instanceof Error) return arg.stack ?? arg.message;
      try {
        return JSON.stringify(arg);
      } catch {
        return String(arg);
      }
    })
    .join(" ")
    .trim();
}

function queueSessionLine(level: LogLevel, rawMessage: string): void {
  const message = sanitizeForSession(rawMessage);
  const timestamp = formatTimestamp();
  const line = `[${timestamp}] ${level} ${message}`.trim();
  sessionLines.push(line);
  let trimmed = false;

  if (sessionLines.length > MAX_SESSION_LINES) {
    sessionLines.splice(0, sessionLines.length - MAX_SESSION_LINES);
    trimmed = true;
  }

  scheduleSessionWrite(async () => {
    if (trimmed) {
      await fs.writeFile(SESSION_LOG_PATH, sessionLines.join("\n") + "\n", "utf8");
    } else {
      await fs.appendFile(SESSION_LOG_PATH, line + "\n", "utf8");
    }
  });
}

function scheduleSessionWrite(task: () => Promise<void>): void {
  sessionWriteQueue = sessionWriteQueue
    .catch(() => {})
    .then(task)
    .catch((err) => {
      originalConsoleError("Failed to persist session log:", err);
    });
}

function redactSensitive(input: string): string {
  return input
    .replace(uuidRegex, "[redacted-uuid]")
    .replace(emailRegex, "[redacted-email]")
    .trim();
}

function sanitizeForSession(input: string): string {
  return redactSensitive(input).replace(/[\r\n]+/g, " | ").trim();
}

function extractTrace(error: unknown): string {
  if (!error) return "";
  if (error instanceof Error) return error.stack ?? error.message;
  if (typeof error === "string") return error;
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

function allocateErrorFilePath(date: Date): string {
  const base = formatFilenameTimestamp(date);
  if (base === lastErrorBase) {
    duplicateCounter += 1;
  } else {
    lastErrorBase = base;
    duplicateCounter = 0;
  }
  const suffix = duplicateCounter > 0 ? `-${duplicateCounter}` : "";
  return path.join(ERROR_DIR, `${base}${suffix}.log`);
}

function formatTimestamp(date: Date = new Date()): string {
  const pad = (value: number, size = 2) => String(value).padStart(size, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}`;
}

function formatFilenameTimestamp(date: Date = new Date()): string {
  const pad = (value: number, size = 2) => String(value).padStart(size, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}_${pad(date.getHours())}-${pad(date.getMinutes())}-${pad(date.getSeconds())}-${pad(date.getMilliseconds(), 3)}`;
}
