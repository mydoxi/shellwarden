import path from "node:path";
import { parseShell, type Pipeline, type Redirect } from "./shell.js";

export interface Env {
  cwd: string;
  home: string;
}

/** A single command, unwrapped from `sudo`, `env`, `xargs` and friends. */
export interface CommandContext {
  /** Program name without directory, e.g. `rm` for `/bin/rm`. */
  program: string;
  args: string[];
  redirects: Redirect[];
  heredocs: string[];
  /** Raw text of the command as written. */
  text: string;
  /** True when the command runs through `sudo` or `doas`. */
  elevated: boolean;
  /** The other commands in the same pipeline, in order. */
  pipeline: CommandContext[];
  /** Position of this command in its pipeline. */
  index: number;
  env: Env;
}

const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish", "ash"]);
const KEYWORDS = new Set(["if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "command", "builtin", "exec", "nohup", "fi", "done"]);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** Options that consume the following word, per wrapper program. */
const WRAPPER_OPTS_WITH_ARG: Record<string, Set<string>> = {
  sudo: new Set(["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T", "--user", "--group", "--host", "--prompt", "--chdir"]),
  doas: new Set(["-u", "-C"]),
  env: new Set(["-u", "-C", "-S", "--unset", "--chdir", "--split-string"]),
  nice: new Set(["-n", "--adjustment"]),
  ionice: new Set(["-c", "-n", "-p", "--class", "--classdata"]),
  timeout: new Set(["-s", "-k", "--signal", "--kill-after"]),
  xargs: new Set(["-I", "-L", "-n", "-P", "-d", "-E", "-s", "-a", "--max-args", "--max-procs", "--delimiter", "--arg-file", "--replace"]),
  stdbuf: new Set(["-i", "-o", "-e"]),
  watch: new Set(["-n", "-d", "--interval"]),
  time: new Set(["-f", "-o", "--format", "--output"]),
};

export function basename(program: string): string {
  const p = program.replace(/^\\/, "");
  const idx = p.lastIndexOf("/");
  return idx === -1 ? p : p.slice(idx + 1);
}

/** Strip wrappers such as `sudo -u root env FOO=1 nice -n 5 rm ...`. */
export function unwrap(argv: string[]): { argv: string[]; elevated: boolean } {
  let words = argv.slice();
  let elevated = false;
  for (let guard = 0; guard < 20 && words.length > 0; guard++) {
    const first = words[0]!;
    if (ASSIGNMENT.test(first) || KEYWORDS.has(first)) {
      words = words.slice(1);
      continue;
    }
    const prog = basename(first);
    const withArg = WRAPPER_OPTS_WITH_ARG[prog];
    if (!withArg) break;
    let k = 1;
    while (k < words.length) {
      const w = words[k]!;
      if (w === "--") {
        k++;
        break;
      }
      if (prog === "env" && ASSIGNMENT.test(w)) {
        k++;
        continue;
      }
      if (prog === "timeout" && /^\d/.test(w)) {
        // The duration argument; the command follows.
        k++;
        break;
      }
      if (!w.startsWith("-")) break;
      if (withArg.has(w)) k += 2;
      else k++;
    }
    // A bare wrapper such as `env` or `sudo` with no command is itself the command.
    if (k >= words.length) break;
    if (prog === "sudo" || prog === "doas") elevated = true;
    words = words.slice(k);
  }
  return { argv: words, elevated };
}

/** Expand `~` and `$HOME` and resolve against the working directory. */
export function resolvePath(p: string, env: Env): string {
  let expanded = p;
  if (expanded === "~" || expanded.startsWith("~/")) expanded = env.home + expanded.slice(1);
  expanded = expanded.replace(/^\$\{?HOME\}?(?=\/|$)/, env.home);
  return path.resolve(env.cwd, expanded);
}

/** The script passed to `bash -c`, `sh -lc`, etc., if any. */
function shellScript(program: string, args: string[]): string | null {
  if (!SHELLS.has(program)) return null;
  for (let k = 0; k < args.length; k++) {
    const a = args[k]!;
    if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(a)) return args[k + 1] ?? null;
    if (!a.startsWith("-")) return null;
  }
  return null;
}

/** Commands nested inside `find -exec ... ;`. */
function findExecCommands(args: string[]): string[][] {
  const out: string[][] = [];
  for (let k = 0; k < args.length; k++) {
    if (args[k] === "-exec" || args[k] === "-execdir" || args[k] === "-ok") {
      const cmd: string[] = [];
      k++;
      while (k < args.length && args[k] !== ";" && args[k] !== "+") {
        cmd.push(args[k]!);
        k++;
      }
      if (cmd.length > 0) out.push(cmd);
    }
  }
  return out;
}

const MAX_DEPTH = 6;

/**
 * Flatten a command line into every command that would run, including those
 * inside `bash -c`, `eval`, command substitutions and `find -exec`.
 */
export function analyzeCommand(command: string, env: Env, depth = 0): CommandContext[] {
  return analyzePipelines(parseShell(command), env, depth);
}

function analyzePipelines(pipelines: Pipeline[], env: Env, depth: number): CommandContext[] {
  const out: CommandContext[] = [];
  for (const pl of pipelines) {
    const group: CommandContext[] = [];
    for (const sc of pl.commands) {
      const { argv, elevated } = unwrap(sc.argv);
      const ctx: CommandContext = {
        program: argv.length > 0 ? basename(argv[0]!) : "",
        args: argv.slice(1),
        redirects: sc.redirects,
        heredocs: sc.heredocs,
        text: sc.text,
        elevated,
        pipeline: group,
        index: group.length,
        env,
      };
      group.push(ctx);
      out.push(ctx);

      if (depth >= MAX_DEPTH) continue;
      const script = shellScript(ctx.program, ctx.args);
      if (script !== null) out.push(...inherit(analyzeCommand(script, env, depth + 1), elevated));
      if (ctx.program === "eval" && ctx.args.length > 0) {
        out.push(...inherit(analyzeCommand(ctx.args.join(" "), env, depth + 1), elevated));
      }
      if (ctx.program === "find") {
        for (const inner of findExecCommands(ctx.args)) {
          out.push(...inherit(analyzePipelines([{ commands: [{ argv: inner, redirects: [], heredocs: [], text: inner.join(" ") }] }], env, depth + 1), elevated));
        }
      }
    }
  }
  return out;
}

function inherit(cmds: CommandContext[], elevated: boolean): CommandContext[] {
  if (elevated) for (const c of cmds) c.elevated = true;
  return cmds;
}

/** Short flags like `-rf` expanded to individual letters, plus long flags. */
export function flags(args: string[]): { short: Set<string>; long: Set<string> } {
  const short = new Set<string>();
  const long = new Set<string>();
  for (const a of args) {
    if (a === "--") break;
    if (a.startsWith("--")) long.add(a.split("=")[0]!);
    else if (/^-[a-zA-Z]+$/.test(a)) for (const ch of a.slice(1)) short.add(ch);
  }
  return { short, long };
}

/** Positional (non-flag) arguments. Everything after `--` counts as positional. */
export function positionals(args: string[]): string[] {
  const out: string[] = [];
  let rest = false;
  for (const a of args) {
    if (rest) out.push(a);
    else if (a === "--") rest = true;
    else if (!a.startsWith("-") || a === "-") out.push(a);
  }
  return out;
}
