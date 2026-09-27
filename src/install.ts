import fs from "node:fs";
import path from "node:path";

export const HOOK_MATCHER = "Bash|Write|Edit|MultiEdit|NotebookEdit";

interface HookEntry {
  type?: string;
  command?: string;
  [key: string]: unknown;
}

interface MatcherGroup {
  matcher?: string;
  hooks?: HookEntry[];
  [key: string]: unknown;
}

type Settings = Record<string, unknown> & { hooks?: Record<string, MatcherGroup[] | undefined> };

function isOurs(entry: HookEntry): boolean {
  return typeof entry.command === "string" && /\bshellwarden\b/.test(entry.command);
}

function readSettings(file: string): Settings {
  if (!fs.existsSync(file)) return {};
  const text = fs.readFileSync(file, "utf8");
  if (text.trim() === "") return {};
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${file} does not contain a JSON object`);
  }
  return parsed as Settings;
}

function writeSettings(file: string, settings: Settings): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(settings, null, 2)}\n`);
}

export interface InstallResult {
  file: string;
  changed: boolean;
  settings: Settings;
}

/** Add the shellwarden PreToolUse hook to a Claude Code settings file. Idempotent. */
export function install(file: string, command: string, opts: { dryRun?: boolean } = {}): InstallResult {
  const settings = readSettings(file);
  const hooks = (settings.hooks ??= {});
  const groups = (hooks.PreToolUse ??= []);
  const existing = groups.flatMap((g) => g.hooks ?? []).find(isOurs);
  if (existing) {
    if (existing.command === command) return { file, changed: false, settings };
    existing.command = command;
  } else {
    groups.push({ matcher: HOOK_MATCHER, hooks: [{ type: "command", command, timeout: 10 }] });
  }
  if (!opts.dryRun) writeSettings(file, settings);
  return { file, changed: true, settings };
}

/** Remove every shellwarden hook from a settings file, pruning empty groups. */
export function uninstall(file: string, opts: { dryRun?: boolean } = {}): InstallResult {
  const settings = readSettings(file);
  const groups = settings.hooks?.PreToolUse;
  if (!groups) return { file, changed: false, settings };
  let changed = false;
  const kept: MatcherGroup[] = [];
  for (const g of groups) {
    const remaining = (g.hooks ?? []).filter((h) => !isOurs(h));
    if (remaining.length !== (g.hooks ?? []).length) changed = true;
    if (remaining.length > 0) kept.push({ ...g, hooks: remaining });
  }
  if (!changed) return { file, changed, settings };
  if (kept.length > 0) settings.hooks!.PreToolUse = kept;
  else delete settings.hooks!.PreToolUse;
  if (Object.keys(settings.hooks!).length === 0) delete settings.hooks;
  if (!opts.dryRun) writeSettings(file, settings);
  return { file, changed, settings };
}
