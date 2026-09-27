import os from "node:os";
import { loadConfig, type Config } from "./config.js";
import { evaluateToolCall, type Verdict } from "./engine.js";

export interface HookResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/** Text Claude sees when a call is blocked or needs approval. */
export function formatReason(v: Verdict): string {
  const lead = v.decision === "deny" ? "shellwarden blocked this action:" : "shellwarden wants the user to confirm this action:";
  const lines = v.findings.map((f) => `- [${f.ruleId}] ${f.reason}${f.suggestion ? ` Safer: ${f.suggestion}` : ""}`);
  const tail =
    v.decision === "deny"
      ? "Do not try to work around this check. If the action is really needed, explain why to the user and let them run it themselves."
      : "";
  return [lead, ...lines, tail].filter(Boolean).join("\n");
}

/**
 * Handle one PreToolUse hook invocation. Never throws: if the input can't be
 * understood, the call is left to Claude Code's normal permission flow and a
 * warning is written to stderr.
 */
export function runHook(stdin: string, opts: { home?: string; config?: Config } = {}): HookResult {
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(stdin) as Record<string, unknown>;
  } catch {
    return { stdout: "", stderr: "shellwarden: could not parse hook input as JSON; skipping checks.\n", exitCode: 1 };
  }
  const toolName = typeof payload.tool_name === "string" ? payload.tool_name : "";
  const cwd = typeof payload.cwd === "string" && payload.cwd !== "" ? payload.cwd : process.cwd();
  const home = opts.home ?? os.homedir();

  let config = opts.config;
  let stderr = "";
  if (!config) {
    const loaded = loadConfig(process.env.CLAUDE_PROJECT_DIR ?? cwd, home);
    config = loaded.config;
    if (loaded.warnings.length > 0) stderr = loaded.warnings.map((w) => `shellwarden: ignoring config: ${w}\n`).join("");
  }

  const verdict = evaluateToolCall(toolName, payload.tool_input, { cwd, home }, config);
  if (verdict.decision === "allow") return { stdout: "", stderr, exitCode: 0 };

  const output = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: verdict.decision,
      permissionDecisionReason: formatReason(verdict),
    },
  };
  return { stdout: `${JSON.stringify(output)}\n`, stderr, exitCode: 0 };
}
