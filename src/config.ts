import fs from "node:fs";
import path from "node:path";
import type { Decision } from "./rules/types.js";

export type RuleSetting = Decision | "off";

export interface CustomRule {
  id: string;
  /** Regular expression tested against each shell command and each written file path. */
  pattern: string;
  decision?: Decision;
  reason?: string;
  /** Which tool calls the rule applies to. Defaults to both. */
  applies?: ("bash" | "file")[];
}

export interface Config {
  /** Per-rule overrides keyed by rule id, or `category.*` for a whole category. */
  rules: Record<string, RuleSetting>;
  /** Regular expressions; a command or file path matching one is never flagged by built-in rules. */
  allow: string[];
  custom: CustomRule[];
  /** Record flagged actions to the local log read by `shellwarden log`. Defaults to true. */
  log?: boolean;
}

export const PROJECT_CONFIG = ".shellwarden.json";

export function emptyConfig(): Config {
  return { rules: {}, allow: [], custom: [] };
}

export function userConfigPath(home: string): string {
  return path.join(home, ".config", "shellwarden", "config.json");
}

/** Walk up from `cwd` to find a project config, stopping at the home directory or root. */
export function findProjectConfig(cwd: string, home: string): string | null {
  let dir = path.resolve(cwd);
  for (;;) {
    const candidate = path.join(dir, PROJECT_CONFIG);
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir || dir === home) return null;
    dir = parent;
  }
}

function isSetting(v: unknown): v is RuleSetting {
  return v === "deny" || v === "ask" || v === "off";
}

/** Validate untrusted JSON into a Config, collecting problems instead of throwing. */
export function parseConfig(raw: unknown, source: string, warnings: string[]): Config {
  const cfg = emptyConfig();
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    warnings.push(`${source}: expected a JSON object`);
    return cfg;
  }
  const obj = raw as Record<string, unknown>;
  if (obj.rules !== undefined) {
    if (typeof obj.rules === "object" && obj.rules !== null && !Array.isArray(obj.rules)) {
      for (const [id, v] of Object.entries(obj.rules)) {
        if (isSetting(v)) cfg.rules[id] = v;
        else warnings.push(`${source}: rules.${id} must be "deny", "ask" or "off"`);
      }
    } else warnings.push(`${source}: "rules" must be an object`);
  }
  if (obj.allow !== undefined) {
    if (Array.isArray(obj.allow)) {
      for (const p of obj.allow) {
        if (typeof p === "string" && compiles(p)) cfg.allow.push(p);
        else warnings.push(`${source}: allow entry ${JSON.stringify(p)} is not a valid regular expression`);
      }
    } else warnings.push(`${source}: "allow" must be an array`);
  }
  if (obj.log !== undefined) {
    if (typeof obj.log === "boolean") cfg.log = obj.log;
    else warnings.push(`${source}: "log" must be true or false`);
  }
  if (obj.custom !== undefined) {
    if (Array.isArray(obj.custom)) {
      for (const c of obj.custom) {
        const r = c as Partial<CustomRule> | null;
        if (r && typeof r.id === "string" && typeof r.pattern === "string" && compiles(r.pattern) && (r.decision === undefined || r.decision === "deny" || r.decision === "ask")) {
          cfg.custom.push({ id: r.id, pattern: r.pattern, decision: r.decision, reason: typeof r.reason === "string" ? r.reason : undefined, applies: Array.isArray(r.applies) ? r.applies : undefined });
        } else warnings.push(`${source}: invalid custom rule ${JSON.stringify(c)}`);
      }
    } else warnings.push(`${source}: "custom" must be an array`);
  }
  return cfg;
}

function compiles(pattern: string): boolean {
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}

export function mergeConfigs(...configs: Config[]): Config {
  const out = emptyConfig();
  for (const c of configs) {
    Object.assign(out.rules, c.rules);
    if (c.log !== undefined) out.log = c.log;
    out.allow.push(...c.allow);
    out.custom.push(...c.custom);
  }
  return out;
}

/**
 * Load the user config and the nearest project config. A broken config file
 * is reported as a warning and skipped, so the built-in rules keep working.
 */
export function loadConfig(cwd: string, home: string): { config: Config; warnings: string[] } {
  const warnings: string[] = [];
  const configs: Config[] = [];
  const files = [userConfigPath(home), findProjectConfig(cwd, home)];
  for (const file of files) {
    if (!file || !fs.existsSync(file)) continue;
    try {
      configs.push(parseConfig(JSON.parse(fs.readFileSync(file, "utf8")), file, warnings));
    } catch (err) {
      warnings.push(`${file}: ${(err as Error).message}`);
    }
  }
  return { config: mergeConfigs(...configs), warnings };
}
