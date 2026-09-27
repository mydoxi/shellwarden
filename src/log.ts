import fs from "node:fs";
import path from "node:path";
import type { Verdict } from "./engine.js";
import { redactSecrets } from "./rules/files.js";

export interface LogEntry {
  time: string;
  decision: "deny" | "ask";
  tool: string;
  rules: string[];
  /** The shell command (secrets redacted, truncated) or the file path written. */
  subject: string;
  cwd: string;
}

const MAX_BYTES = 1_000_000;
const MAX_SUBJECT = 300;

export function defaultLogPath(home: string): string {
  const state = process.env.XDG_STATE_HOME || path.join(home, ".local", "state");
  return path.join(state, "shellwarden", "log.jsonl");
}

/** Describe what a tool call was doing, without file contents and with secrets redacted. */
export function subjectOf(toolName: string, toolInput: unknown): string {
  const input = (toolInput && typeof toolInput === "object" ? toolInput : {}) as Record<string, unknown>;
  const text = toolName === "Bash" && typeof input.command === "string" ? input.command : String(input.file_path ?? input.notebook_path ?? "");
  const redacted = redactSecrets(text);
  return redacted.length > MAX_SUBJECT ? `${redacted.slice(0, MAX_SUBJECT - 1)}…` : redacted;
}

/** Append a flagged action to the log. Logging must never break the hook, so errors are swallowed. */
export function appendLog(file: string, verdict: Verdict, toolName: string, toolInput: unknown, cwd: string): void {
  if (verdict.decision === "allow") return;
  const entry: LogEntry = {
    time: new Date().toISOString(),
    decision: verdict.decision,
    tool: toolName,
    rules: verdict.findings.map((f) => f.ruleId),
    subject: subjectOf(toolName, toolInput),
    cwd,
  };
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    if (fs.existsSync(file) && fs.statSync(file).size > MAX_BYTES) fs.renameSync(file, `${file}.1`);
    fs.appendFileSync(file, `${JSON.stringify(entry)}\n`);
  } catch {
    // Ignore: a read-only home directory should not stop the safety check.
  }
}

export function readLog(file: string, limit: number): LogEntry[] {
  if (!fs.existsSync(file)) return [];
  const entries: LogEntry[] = [];
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      entries.push(JSON.parse(line) as LogEntry);
    } catch {
      // Skip a partially written line.
    }
  }
  return entries.slice(-limit);
}
