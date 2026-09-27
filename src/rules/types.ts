import type { CommandContext, Env } from "../analyze.js";

export type Decision = "deny" | "ask";

export interface Hit {
  reason: string;
  /** A safer alternative, shown to Claude so it can change course. */
  suggestion?: string;
  /** Overrides the rule's default decision for this particular hit. */
  decision?: Decision;
}

export interface FileContext {
  tool: string;
  /** Absolute path, with `~` expanded. */
  path: string;
  /** New content being written; empty when unknown (e.g. a shell redirect). */
  content: string;
  env: Env;
}

interface RuleBase {
  /** Stable identifier, `category.name`. Used in config overrides. */
  id: string;
  description: string;
  decision: Decision;
}

export interface CommandRule extends RuleBase {
  kind: "command";
  check(cmd: CommandContext): Hit | null;
  /** Commands this rule must flag and must not flag. Run as tests. */
  examples: { flag: string[]; pass: string[] };
}

export interface FileRule extends RuleBase {
  kind: "file";
  check(file: FileContext): Hit | null;
  examples: {
    flag: { path: string; content?: string }[];
    pass: { path: string; content?: string }[];
  };
}

/** A rule over the whole raw command string, for patterns the parser would split apart. */
export interface RawRule extends RuleBase {
  kind: "raw";
  check(command: string): Hit | null;
  examples: { flag: string[]; pass: string[] };
}

export type Rule = CommandRule | FileRule | RawRule;
