#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig } from "./config.js";
import { evaluateCommand, evaluateFileWrite, type Verdict } from "./engine.js";
import { runHook } from "./hook.js";
import { install, uninstall } from "./install.js";
import { builtinRules } from "./rules/index.js";

const HELP = `shellwarden - safety hooks for Claude Code

Usage:
  shellwarden install [--user | --local] [--dry-run]   Add the hook to Claude Code settings
  shellwarden uninstall [--user | --local]             Remove the hook
  shellwarden test "<command>"                         Show what shellwarden thinks of a command
  shellwarden test --file <path> [--content <text>]    ...or of a file write
  shellwarden rules [--markdown]                       List the built-in rules
  shellwarden check                                    Run as a hook (reads JSON on stdin)

Install targets:
  (default)  .claude/settings.json in the current project (commit it to protect your team)
  --local    .claude/settings.local.json in the current project (just you)
  --user     ~/.claude/settings.json (every project on this machine)

Docs: https://github.com/mydoxi/medox`;

const color = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = (s: string) => paint("31", s);
const yellow = (s: string) => paint("33", s);
const green = (s: string) => paint("32", s);
const dim = (s: string) => paint("2", s);
const bold = (s: string) => paint("1", s);

function version(): string {
  const pkgPath = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "package.json");
  return (JSON.parse(fs.readFileSync(pkgPath, "utf8")) as { version: string }).version;
}

function readStdin(): string {
  try {
    return fs.readFileSync(0, "utf8");
  } catch {
    return "";
  }
}

function option(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
}

function settingsFile(args: string[]): string {
  if (args.includes("--user")) return path.join(os.homedir(), ".claude", "settings.json");
  const name = args.includes("--local") ? "settings.local.json" : "settings.json";
  return path.join(process.cwd(), ".claude", name);
}

/** The command Claude Code should run. Invocations through npx keep using npx. */
function hookCommand(): string {
  const script = process.argv[1] ?? "";
  return /[\\/]_npx[\\/]/.test(script) ? "npx -y shellwarden check" : "shellwarden check";
}

function printVerdict(v: Verdict): void {
  if (v.decision === "allow") {
    console.log(`${green("ALLOW")}  no rule matched`);
    return;
  }
  for (const f of v.findings) {
    const label = f.decision === "deny" ? red("DENY ") : yellow("ASK  ");
    console.log(`${label}  ${bold(f.ruleId)}  ${f.reason}`);
    if (f.suggestion) console.log(`       ${dim(`safer: ${f.suggestion}`)}`);
  }
}

function main(argv: string[]): number {
  const [cmd, ...args] = argv;

  if (cmd === "check" || (cmd === undefined && !process.stdin.isTTY)) {
    const result = runHook(readStdin());
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    return result.exitCode;
  }

  if (cmd === "install" || cmd === "uninstall") {
    const file = settingsFile(args);
    const dryRun = args.includes("--dry-run");
    const result = cmd === "install" ? install(file, hookCommand(), { dryRun }) : uninstall(file, { dryRun });
    if (dryRun) {
      console.log(JSON.stringify(result.settings, null, 2));
    } else if (!result.changed) {
      console.log(cmd === "install" ? `shellwarden is already installed in ${file}` : `shellwarden was not installed in ${file}`);
    } else {
      console.log(cmd === "install" ? `${green("✓")} Installed shellwarden hook in ${file}` : `${green("✓")} Removed shellwarden hook from ${file}`);
      if (cmd === "install") console.log(dim("  Restart Claude Code (or run /hooks) to pick it up. Try: shellwarden test \"rm -rf ~\""));
    }
    return 0;
  }

  if (cmd === "test") {
    const cwd = option(args, "--cwd") ?? process.cwd();
    const home = os.homedir();
    const { config, warnings } = loadConfig(cwd, home);
    for (const w of warnings) console.error(yellow(`warning: ${w}`));
    const file = option(args, "--file");
    if (file !== undefined) {
      printVerdict(evaluateFileWrite({ tool: "Write", path: file, content: option(args, "--content") ?? "" }, { cwd, home }, config));
      return 0;
    }
    const command = args.filter((a, i) => a !== "--cwd" && args[i - 1] !== "--cwd").join(" ");
    if (!command) {
      console.error('Usage: shellwarden test "<command>"');
      return 2;
    }
    printVerdict(evaluateCommand(command, { cwd, home }, config));
    return 0;
  }

  if (cmd === "rules") {
    if (args.includes("--markdown")) {
      console.log("| Rule | Default | What it catches |\n| --- | --- | --- |");
      for (const r of builtinRules) console.log(`| \`${r.id}\` | ${r.decision} | ${r.description.replace(/\|/g, "\\|")} |`);
      return 0;
    }
    for (const r of builtinRules) {
      const d = r.decision === "deny" ? red("deny") : yellow("ask ");
      console.log(`${d}  ${bold(r.id.padEnd(28))} ${r.description}`);
    }
    return 0;
  }

  if (cmd === "--version" || cmd === "-v" || cmd === "version") {
    console.log(version());
    return 0;
  }

  console.log(HELP);
  return cmd === undefined || cmd === "help" || cmd === "--help" || cmd === "-h" ? 0 : 2;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (err) {
  console.error(`shellwarden: ${(err as Error).message}`);
  process.exitCode = 1;
}
