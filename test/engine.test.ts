import { describe, expect, it } from "vitest";
import { emptyConfig, parseConfig } from "../src/config.js";
import { evaluateCommand, evaluateToolCall } from "../src/engine.js";

const env = { cwd: "/home/dev/project", home: "/home/dev" };

/** Everyday commands a coding agent runs. None of these may be flagged. */
const BENIGN = [
  "npm test",
  "npm run build && npm run lint",
  "pnpm install --frozen-lockfile",
  "git status && git diff --stat",
  "git add -A && git commit -m 'feat: add login'",
  `git commit -m "$(cat <<'EOF'\nRemove the rm -rf / footgun from docs\n\nWe no longer DROP TABLE users in the seed script.\nEOF\n)"`,
  "git push -u origin HEAD",
  "git push origin feature/auth",
  "git checkout -b fix/null-check",
  "git log --oneline -20",
  "git stash && git pull --rebase && git stash pop",
  "rm -rf node_modules package-lock.json && npm install",
  "rm -rf dist build .next coverage",
  "rm -f /tmp/test.sock",
  "mkdir -p src/components && touch src/components/Button.tsx",
  "ls -la ~/project",
  "cat package.json | jq .scripts",
  "grep -rn 'TODO' src/",
  'grep -r "DROP TABLE" migrations/',
  "find . -name '*.test.ts' | xargs wc -l",
  "python -m pytest -x -q",
  "cargo build --release && cargo test",
  "go test ./... -run TestAuth",
  "docker compose up -d db",
  "docker build -t app:dev .",
  "curl -s http://localhost:3000/health | jq .",
  "curl -fsSL https://example.com/install.sh -o /tmp/install.sh",
  "echo 'export PATH=$PATH:./bin' > .envrc",
  "cp .env.example .env",
  "npx prisma migrate dev --name init",
  "kubectl get pods -n staging",
  "terraform plan -out tfplan",
  "chmod +x scripts/*.sh",
  "sed -i 's/foo/bar/g' src/app.ts",
  "tee -a notes.md <<< 'done'",
  "psql -c 'SELECT count(*) FROM users'",
  "aws s3 ls s3://my-bucket/",
  "echo done > /dev/null 2>&1",
];

describe("benign commands", () => {
  for (const cmd of BENIGN) {
    it(`allows: ${cmd.split("\n")[0]}`, () => {
      const v = evaluateCommand(cmd, env);
      expect(v.findings).toEqual([]);
      expect(v.decision).toBe("allow");
    });
  }
});

describe("dangerous commands hidden behind wrappers", () => {
  const cases: [string, string][] = [
    ["npm test && rm -rf ~", "fs.rm-root"],
    ['bash -c "rm -rf /"', "fs.rm-root"],
    ["sudo -E env X=1 rm -rf /", "fs.rm-root"],
    ["echo $(git push --force origin main)", "git.force-push"],
    ["find / -maxdepth 0 -exec rm -rf {} ;", "fs.find-delete-root"],
    ["cd .. && git reset --hard", "git.reset-hard"],
    ["echo 'ssh-rsa AAA' >> ~/.ssh/authorized_keys", "files.sensitive-path"],
    ["sed -i 's/deny/allow/' .claude/settings.json", "self.config-tamper"],
  ];
  for (const [cmd, rule] of cases) {
    it(`${rule}: ${cmd}`, () => {
      expect(evaluateCommand(cmd, env).findings.map((f) => f.ruleId)).toContain(rule);
    });
  }
});

describe("decisions", () => {
  it("deny wins over ask", () => {
    const v = evaluateCommand("git reset --hard && rm -rf /", env);
    expect(v.decision).toBe("deny");
    expect(v.findings.map((f) => f.ruleId).sort()).toEqual(["fs.rm-root", "git.reset-hard"]);
  });

  it("force-push to a protected branch is denied, to a feature branch asked", () => {
    expect(evaluateCommand("git push -f origin main", env).decision).toBe("deny");
    expect(evaluateCommand("git push -f origin feature", env).decision).toBe("ask");
  });
});

describe("config", () => {
  const cfg = (raw: unknown) => {
    const warnings: string[] = [];
    const c = parseConfig(raw, "test", warnings);
    expect(warnings).toEqual([]);
    return c;
  };

  it("turns rules off individually or by category", () => {
    expect(evaluateCommand("git reset --hard", env, cfg({ rules: { "git.reset-hard": "off" } })).decision).toBe("allow");
    expect(evaluateCommand("git clean -fd", env, cfg({ rules: { "git.*": "off" } })).decision).toBe("allow");
  });

  it("can escalate ask to deny", () => {
    expect(evaluateCommand("npm publish", env, cfg({ rules: { "release.publish": "deny" } })).decision).toBe("deny");
  });

  it("allow patterns skip only the matching command", () => {
    const c = cfg({ allow: ["^rm -rf \\.$"] });
    expect(evaluateCommand("rm -rf .", env, c).decision).toBe("allow");
    expect(evaluateCommand("rm -rf . && rm -rf ~", env, c).decision).toBe("deny");
  });

  it("supports custom rules", () => {
    const c = cfg({ custom: [{ id: "prod-db", pattern: "prod-db\\.internal", decision: "deny", reason: "Never touch the production database." }] });
    const v = evaluateCommand("psql -h prod-db.internal -c 'select 1'", env, c);
    expect(v.decision).toBe("deny");
    expect(v.findings[0]).toMatchObject({ ruleId: "custom.prod-db", reason: "Never touch the production database." });
  });

  it("reports invalid entries instead of throwing", () => {
    const warnings: string[] = [];
    const c = parseConfig({ rules: { "git.clean": "maybe" }, allow: ["("], custom: [{ id: 1 }] }, "cfg", warnings);
    expect(warnings).toHaveLength(3);
    expect(c).toEqual(emptyConfig());
  });
});

describe("evaluateToolCall", () => {
  it("checks Write content for secrets", () => {
    const v = evaluateToolCall("Write", { file_path: "src/aws.ts", content: 'export const key = "AKIAQWERTYUIOPASDFGH";' }, env);
    expect(v.decision).toBe("deny");
    expect(v.findings[0]!.ruleId).toBe("secrets.hardcoded");
  });

  it("checks only the new text of an Edit", () => {
    const old = evaluateToolCall("Edit", { file_path: "src/aws.ts", old_string: "AKIAQWERTYUIOPASDFGH", new_string: "process.env.AWS_KEY" }, env);
    expect(old.decision).toBe("allow");
  });

  it("checks every file in a MultiEdit", () => {
    const v = evaluateToolCall("MultiEdit", { file_path: "a.ts", edits: [{ old_string: "a", new_string: "b" }, { file_path: ".claude/settings.json", old_string: "x", new_string: "y" }] }, env);
    expect(v.findings.map((f) => f.ruleId)).toContain("self.config-tamper");
  });

  it("allows tools it does not know about", () => {
    expect(evaluateToolCall("Read", { file_path: "~/.ssh/id_rsa" }, env).decision).toBe("allow");
    expect(evaluateToolCall("mcp__github__create_issue", { title: "rm -rf /" }, env).decision).toBe("allow");
  });
});
