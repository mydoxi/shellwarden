import path from "node:path";
import { isCredentialPath, isEnvFile } from "./paths.js";
import type { CommandRule, FileRule } from "./types.js";

interface SecretPattern {
  name: string;
  pattern: RegExp;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { name: "AWS access key", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: "GitHub token", pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: "GitHub fine-grained token", pattern: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/ },
  { name: "GitLab token", pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
  { name: "Anthropic API key", pattern: /\bsk-ant-[A-Za-z0-9_-]{40,}/ },
  { name: "OpenAI API key", pattern: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}/ },
  { name: "OpenAI API key", pattern: /\bsk-[A-Za-z0-9]{48}\b/ },
  { name: "Slack token", pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  { name: "Stripe live key", pattern: /\b[sr]k_live_[A-Za-z0-9]{20,}/ },
  { name: "Google API key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: "npm token", pattern: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { name: "Hugging Face token", pattern: /\bhf_[A-Za-z]{34,}\b/ },
  { name: "SendGrid API key", pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
  { name: "private key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/ },
];

/** Obvious placeholders and documentation examples are not real secrets. */
function isPlaceholder(match: string): boolean {
  return /example|dummy|placeholder|your[_-]?|x{8,}|0{10,}|\*{4,}|<|\.\.\./i.test(match);
}

export function findSecret(content: string): { name: string; preview: string } | null {
  for (const { name, pattern } of SECRET_PATTERNS) {
    const global = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
    for (const m of content.matchAll(global)) {
      if (isPlaceholder(m[0])) continue;
      const preview = m[0].length > 12 ? `${m[0].slice(0, 8)}…` : m[0];
      return { name, preview };
    }
  }
  return null;
}

export const secretInFile: FileRule = {
  kind: "file",
  id: "secrets.hardcoded",
  decision: "deny",
  description: "Writing an API key, token or private key into a source file (.env files are allowed)",
  check(file) {
    if (file.content === "" || isEnvFile(file.path)) return null;
    const secret = findSecret(file.content);
    if (!secret) return null;
    return {
      reason: `The content contains what looks like a real ${secret.name} (\`${secret.preview}\`). Hardcoded secrets end up in git history and logs.`,
      suggestion: "Read it from an environment variable (e.g. `process.env.API_KEY`) and put the value in a gitignored .env file.",
    };
  },
  examples: {
    flag: [
      { path: "src/config.ts", content: 'const key = "AKIAQWERTYUIOPASDFGH";' },
      { path: "app.py", content: "client = Anthropic(api_key='sk-ant-api03-" + "a".repeat(20) + "B".repeat(30) + "')" },
      { path: "deploy.sh", content: "export GITHUB_TOKEN=ghp_" + "A1b2C3d4E5".repeat(4) },
      { path: "key.txt", content: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----" },
    ],
    pass: [
      { path: ".env", content: 'ANTHROPIC_API_KEY="sk-ant-api03-' + "a".repeat(20) + "B".repeat(30) + '"' },
      { path: "src/config.ts", content: "const key = process.env.API_KEY;" },
      { path: "README.md", content: "Set AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" },
      { path: ".env.example", content: "OPENAI_API_KEY=sk-proj-your-key-here" },
    ],
  },
};

function underHome(abs: string, home: string, rel: string): boolean {
  const base = `${home.replace(/\/+$/, "")}/${rel}`;
  return abs === base || abs.startsWith(`${base}/`);
}

const SHELL_STARTUP = [".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".config/fish/config.fish", ".gitconfig"];

export const sensitivePath: FileRule = {
  kind: "file",
  id: "files.sensitive-path",
  decision: "ask",
  description: "Writing to credential stores, shell startup files, system directories, or .git internals",
  check(file) {
    const { path: abs, env } = file;
    if (isCredentialPath(abs, env) || underHome(abs, env.home, ".ssh")) {
      return { reason: `\`${abs}\` holds credentials or SSH configuration.` };
    }
    const startup = SHELL_STARTUP.find((f) => underHome(abs, env.home, f));
    if (startup) return { reason: `\`~/${startup}\` is a user-wide startup file, so changes to it affect every shell and project.` };
    if (underHome(abs, env.home, "Library/LaunchAgents") || abs.startsWith("/Library/Launch")) {
      return { reason: `\`${abs}\` registers a program to run automatically at login.` };
    }
    if (/^\/(etc|usr|bin|sbin|boot|System|lib|lib64)(\/|$)/.test(abs)) {
      return { reason: `\`${abs}\` is a system file.` };
    }
    if (abs.split(path.sep).includes(".git") && !abs.endsWith("/.git/COMMIT_EDITMSG")) {
      return { reason: `\`${abs}\` is inside .git; editing it directly can corrupt the repository or install hooks.`, suggestion: "Use git commands instead." };
    }
    return null;
  },
  examples: {
    flag: [{ path: "~/.ssh/authorized_keys" }, { path: "~/.zshrc" }, { path: "/etc/hosts" }, { path: ".git/hooks/pre-commit" }, { path: "~/.aws/credentials" }],
    pass: [{ path: "src/index.ts" }, { path: ".gitignore" }, { path: ".github/workflows/ci.yml" }, { path: "~/project/notes.md" }],
  },
};

/** Files that control Claude Code's permissions and shellwarden itself. */
export function isGuardConfig(abs: string, home: string): boolean {
  const name = path.basename(abs);
  const dir = path.basename(path.dirname(abs));
  if (dir === ".claude" && /^settings(\.local)?\.json$/.test(name)) return true;
  if (name === ".shellwarden.json") return true;
  return underHome(abs, home, ".config/shellwarden");
}

export const guardConfig: FileRule = {
  kind: "file",
  id: "self.config-tamper",
  decision: "ask",
  description: "Changing Claude Code settings or shellwarden's own config (which could disable these checks)",
  check(file) {
    if (!isGuardConfig(file.path, file.env.home)) return null;
    return { reason: `\`${file.path}\` controls Claude's permissions and safety hooks, so the user should approve changes to it.` };
  },
  examples: {
    flag: [{ path: ".claude/settings.json" }, { path: "~/.claude/settings.json" }, { path: ".shellwarden.json" }, { path: ".claude/settings.local.json" }],
    pass: [{ path: ".claude/commands/review.md" }, { path: "settings.json" }],
  },
};

export const uninstallSelf: CommandRule = {
  kind: "command",
  id: "self.uninstall",
  decision: "ask",
  description: "Uninstalling shellwarden from a command",
  check(cmd) {
    const direct = cmd.program === "shellwarden" && cmd.args[0] === "uninstall";
    const viaRunner = ["npx", "pnpx", "bunx"].includes(cmd.program) && cmd.args.some((a) => a.startsWith("shellwarden")) && cmd.args.includes("uninstall");
    const viaNpm = ["npm", "pnpm", "yarn", "bun"].includes(cmd.program) && ["uninstall", "remove", "rm", "un"].includes(cmd.args[0] ?? "") && cmd.args.includes("shellwarden");
    if (direct || viaRunner || viaNpm) return { reason: "This removes the shellwarden safety hook, so the user should approve it." };
    return null;
  },
  examples: {
    flag: ["shellwarden uninstall", "npx -y shellwarden uninstall", "npm uninstall -g shellwarden"],
    pass: ["shellwarden rules", "npm uninstall lodash"],
  },
};

export const fileRules = [secretInFile, sensitivePath, guardConfig];
export const selfRules = [uninstallSelf];
