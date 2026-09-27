import { analyzeCommand, positionals, resolvePath, type CommandContext, type Env } from "./analyze.js";
import { emptyConfig, type Config } from "./config.js";
import { builtinRules } from "./rules/index.js";
import type { Decision, FileContext, Hit, Rule } from "./rules/types.js";

export interface Finding {
  ruleId: string;
  decision: Decision;
  reason: string;
  suggestion?: string;
}

export interface Verdict {
  decision: "allow" | Decision;
  findings: Finding[];
}

/** Tools that write files, and therefore get file rules. */
export const WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);

function settingFor(rule: Rule, config: Config) {
  return config.rules[rule.id] ?? config.rules[`${rule.id.split(".")[0]}.*`];
}

function toFinding(rule: Rule, hit: Hit, config: Config): Finding {
  const setting = settingFor(rule, config);
  const decision = setting === "deny" || setting === "ask" ? setting : (hit.decision ?? rule.decision);
  return { ruleId: rule.id, decision, reason: hit.reason, suggestion: hit.suggestion };
}

function active(rules: Rule[], config: Config): Rule[] {
  return rules.filter((r) => settingFor(r, config) !== "off");
}

function allowed(text: string, config: Config): boolean {
  return config.allow.some((p) => new RegExp(p).test(text));
}

function verdict(findings: Finding[]): Verdict {
  const seen = new Set<string>();
  const unique = findings.filter((f) => {
    const key = `${f.ruleId}\0${f.reason}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const decision = unique.some((f) => f.decision === "deny") ? "deny" : unique.length > 0 ? "ask" : "allow";
  return { decision, findings: unique };
}

const HARMLESS_TARGETS = new Set(["/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"]);

/** Files a shell command writes to or deletes, as far as we can tell statically. */
export function writeTargets(cmd: CommandContext): string[] {
  const out = cmd.redirects.filter((r) => /^(>|>>|>\||&>|&>>|<>)$/.test(r.op)).map((r) => r.target);
  const pos = positionals(cmd.args);
  switch (cmd.program) {
    case "tee":
    case "rm":
    case "unlink":
    case "truncate":
    case "shred":
      out.push(...pos);
      break;
    case "sed":
    case "perl":
      if (cmd.args.some((a) => /^-[a-zA-Z]*i/.test(a) || a.startsWith("--in-place"))) {
        const scriptGiven = cmd.args.includes("-e") || cmd.args.includes("--expression");
        out.push(...(scriptGiven ? pos : pos.slice(1)));
      }
      break;
    case "cp":
    case "mv":
    case "install":
    case "ln":
    case "rsync":
      if (pos.length >= 2) out.push(pos[pos.length - 1]!);
      break;
  }
  return out.filter((t) => !HARMLESS_TARGETS.has(t) && !t.startsWith("/dev/fd/"));
}

export function evaluateCommand(command: string, env: Env, config: Config = emptyConfig(), rules: Rule[] = builtinRules): Verdict {
  const enabled = active(rules, config);
  const findings: Finding[] = [];

  if (!allowed(command, config)) {
    for (const rule of enabled) {
      if (rule.kind !== "raw") continue;
      const hit = rule.check(command);
      if (hit) findings.push(toFinding(rule, hit, config));
    }
  }

  for (const cmd of analyzeCommand(command, env)) {
    if (allowed(cmd.text, config)) continue;
    for (const rule of enabled) {
      if (rule.kind === "command") {
        const hit = rule.check(cmd);
        if (hit) findings.push(toFinding(rule, hit, config));
      }
    }
    for (const target of writeTargets(cmd)) {
      findings.push(...fileFindings({ tool: "Bash", path: resolvePath(target, env), content: "", env }, target, enabled, config));
    }
  }

  for (const c of config.custom) {
    if (c.applies && !c.applies.includes("bash")) continue;
    if (new RegExp(c.pattern).test(command)) findings.push(customFinding(c));
  }
  return verdict(findings);
}

function customFinding(c: Config["custom"][number]): Finding {
  return { ruleId: `custom.${c.id}`, decision: c.decision ?? "ask", reason: c.reason ?? `Matches custom rule \`${c.id}\`.` };
}

function fileFindings(file: FileContext, rawPath: string, rules: Rule[], config: Config): Finding[] {
  if (allowed(rawPath, config) || allowed(file.path, config)) return [];
  const out: Finding[] = [];
  for (const rule of rules) {
    if (rule.kind !== "file") continue;
    const hit = rule.check(file);
    if (hit) out.push(toFinding(rule, hit, config));
  }
  return out;
}

export interface FileWrite {
  tool: string;
  path: string;
  content: string;
}

export function evaluateFileWrite(write: FileWrite, env: Env, config: Config = emptyConfig(), rules: Rule[] = builtinRules): Verdict {
  const enabled = active(rules, config);
  const file: FileContext = { tool: write.tool, path: resolvePath(write.path, env), content: write.content, env };
  const findings = fileFindings(file, write.path, enabled, config);
  for (const c of config.custom) {
    if (c.applies && !c.applies.includes("file")) continue;
    if (new RegExp(c.pattern).test(write.path) || new RegExp(c.pattern).test(file.path)) findings.push(customFinding(c));
  }
  return verdict(findings);
}

/** Keys in a write tool's input that are not new file content. */
const NON_CONTENT_KEYS = new Set(["file_path", "notebook_path", "path", "old_string", "old_str", "description", "cell_id", "cell_type", "edit_mode", "replace_all"]);

function collectContent(value: unknown, out: string[]): void {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const v of value) collectContent(v, out);
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) if (!NON_CONTENT_KEYS.has(k)) collectContent(v, out);
  }
}

function collectPaths(input: Record<string, unknown>): string[] {
  const paths: string[] = [];
  for (const key of ["file_path", "notebook_path", "path"]) {
    const v = input[key];
    if (typeof v === "string") paths.push(v);
  }
  if (Array.isArray(input.edits)) {
    for (const e of input.edits) {
      const p = (e as Record<string, unknown> | null)?.file_path;
      if (typeof p === "string") paths.push(p);
    }
  }
  return [...new Set(paths)];
}

/** Evaluate one Claude Code tool call. Tools shellwarden doesn't understand are allowed. */
export function evaluateToolCall(toolName: string, toolInput: unknown, env: Env, config: Config = emptyConfig()): Verdict {
  const input = (toolInput && typeof toolInput === "object" ? toolInput : {}) as Record<string, unknown>;
  if (toolName === "Bash" && typeof input.command === "string") {
    return evaluateCommand(input.command, env, config);
  }
  if (WRITE_TOOLS.has(toolName)) {
    const content: string[] = [];
    collectContent(input, content);
    const findings = collectPaths(input).flatMap((p) => evaluateFileWrite({ tool: toolName, path: p, content: content.join("\n") }, env, config).findings);
    return verdict(findings);
  }
  return { decision: "allow", findings: [] };
}
