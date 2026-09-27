import { flags, type CommandContext } from "../analyze.js";
import type { CommandRule } from "./types.js";

const PROTECTED = new Set(["main", "master", "trunk", "production", "prod"]);

/** Global git options that take a separate value, e.g. `git -C dir push`. */
const GLOBAL_WITH_ARG = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"]);

/** Split `git [global opts] <subcommand> [args]`. */
export function gitSubcommand(cmd: CommandContext): { sub: string; args: string[] } | null {
  if (cmd.program !== "git") return null;
  let k = 0;
  while (k < cmd.args.length) {
    const a = cmd.args[k]!;
    if (GLOBAL_WITH_ARG.has(a)) k += 2;
    else if (a.startsWith("-")) k++;
    else return { sub: a, args: cmd.args.slice(k + 1) };
  }
  return null;
}

/** Push options that take a separate value. */
const PUSH_WITH_ARG = new Set(["-o", "--push-option", "--repo", "--receive-pack", "--exec"]);

function pushTargets(args: string[]): { remote?: string; refspecs: string[] } {
  const pos: string[] = [];
  for (let k = 0; k < args.length; k++) {
    const a = args[k]!;
    if (PUSH_WITH_ARG.has(a)) k++;
    else if (!a.startsWith("-")) pos.push(a);
  }
  return { remote: pos[0], refspecs: pos.slice(1) };
}

/** The destination branch of a refspec such as `+HEAD:refs/heads/main`. */
function destBranch(refspec: string): string {
  const dst = refspec.includes(":") ? refspec.slice(refspec.indexOf(":") + 1) : refspec;
  return dst.replace(/^\+/, "").replace(/^refs\/heads\//, "");
}

export const forcePush: CommandRule = {
  kind: "command",
  id: "git.force-push",
  decision: "ask",
  description: "Force-pushing (denied outright for main/master and other protected branches)",
  check(cmd) {
    const g = gitSubcommand(cmd);
    if (!g || g.sub !== "push") return null;
    const f = flags(g.args);
    const hardForce = f.short.has("f") || f.long.has("--force");
    const lease = f.long.has("--force-with-lease") || f.long.has("--force-if-includes");
    const { refspecs } = pushTargets(g.args);
    const plusRefspec = refspecs.some((r) => r.startsWith("+"));
    if (!hardForce && !lease && !plusRefspec) return null;
    const branches = refspecs.map(destBranch);
    const protectedHit = branches.find((b) => PROTECTED.has(b));
    if (protectedHit) {
      return {
        decision: "deny",
        reason: `Force-pushing to \`${protectedHit}\` rewrites shared history and can destroy other people's commits.`,
        suggestion: "Push a new commit instead, or force-push to a feature branch.",
      };
    }
    if (lease && !hardForce && !plusRefspec && refspecs.length > 0) return null;
    return {
      reason: branches.length > 0 ? `Force-pushing \`${branches.join(", ")}\` overwrites the remote branch.` : "Force-pushing overwrites the remote branch, and no branch was named so it may be a shared one.",
      suggestion: "Prefer `git push --force-with-lease origin <feature-branch>`.",
    };
  },
  examples: {
    flag: ["git push --force origin main", "git push -f", "git push origin +main", "git push -uf origin feature", "git -C repo push --force-with-lease origin master", "git push origin HEAD:main --force"],
    pass: ["git push origin feature", "git push -u origin HEAD", "git push --force-with-lease origin feature/login", "git push --follow-tags"],
  },
};

export const pushDelete: CommandRule = {
  kind: "command",
  id: "git.push-delete",
  decision: "ask",
  description: "Deleting a branch or tag on the remote",
  check(cmd) {
    const g = gitSubcommand(cmd);
    if (!g || g.sub !== "push") return null;
    const f = flags(g.args);
    const { refspecs } = pushTargets(g.args);
    const colon = refspecs.find((r) => r.startsWith(":"));
    if (!f.short.has("d") && !f.long.has("--delete") && !colon) return null;
    const names = colon ? [colon.slice(1)] : refspecs;
    return {
      decision: names.some((n) => PROTECTED.has(n)) ? "deny" : undefined,
      reason: `This deletes \`${names.join(", ") || "a ref"}\` on the remote.`,
    };
  },
  examples: {
    flag: ["git push origin --delete old-branch", "git push origin :feature", "git push -d origin main"],
    pass: ["git push origin feature"],
  },
};

export const resetHard: CommandRule = {
  kind: "command",
  id: "git.reset-hard",
  decision: "ask",
  description: "`git reset --hard`, which throws away uncommitted work",
  check(cmd) {
    const g = gitSubcommand(cmd);
    if (!g || g.sub !== "reset" || !g.args.includes("--hard")) return null;
    return {
      reason: "`git reset --hard` permanently discards uncommitted changes.",
      suggestion: "Run `git stash` first so the changes can be recovered.",
    };
  },
  examples: {
    flag: ["git reset --hard", "git reset --hard HEAD~3", "git reset --hard origin/main"],
    pass: ["git reset HEAD file.txt", "git reset --soft HEAD~1"],
  },
};

export const clean: CommandRule = {
  kind: "command",
  id: "git.clean",
  decision: "ask",
  description: "`git clean -f`, which deletes untracked files",
  check(cmd) {
    const g = gitSubcommand(cmd);
    if (!g || g.sub !== "clean") return null;
    const f = flags(g.args);
    if (f.short.has("n") || f.long.has("--dry-run")) return null;
    if (!f.short.has("f") && !f.long.has("--force")) return null;
    const ignored = f.short.has("x") || f.short.has("X");
    return {
      reason: `\`git clean\` permanently deletes untracked files${ignored ? ", including ignored ones such as .env files" : ""}.`,
      suggestion: "Preview with `git clean -n` first.",
    };
  },
  examples: {
    flag: ["git clean -fd", "git clean -fdx", "git clean --force"],
    pass: ["git clean -n", "git clean -fdn"],
  },
};

const EVERYTHING = new Set([".", "./", ":/", "*", ":/*", "-A"]);

export const discardChanges: CommandRule = {
  kind: "command",
  id: "git.discard-changes",
  decision: "ask",
  description: "Discarding all working-tree changes (`git checkout .`, `git restore .`, `git stash clear`)",
  check(cmd) {
    const g = gitSubcommand(cmd);
    if (!g) return null;
    if ((g.sub === "checkout" || g.sub === "restore") && g.args.some((a) => EVERYTHING.has(a))) {
      if (g.sub === "restore" && g.args.includes("--staged") && !g.args.includes("--worktree") && !g.args.includes("-W")) return null;
      return { reason: `\`git ${g.sub} .\` throws away every uncommitted change in the working tree.`, suggestion: "Use `git stash` so the changes can be recovered." };
    }
    if (g.sub === "stash" && (g.args[0] === "clear" || g.args[0] === "drop")) {
      return { reason: `\`git stash ${g.args[0]}\` permanently deletes stashed work.` };
    }
    return null;
  },
  examples: {
    flag: ["git checkout -- .", "git checkout .", "git restore .", "git stash clear"],
    pass: ["git checkout main", "git checkout -- src/app.ts", "git restore --staged .", "git stash", "git stash pop"],
  },
};

export const branchForceDelete: CommandRule = {
  kind: "command",
  id: "git.branch-force-delete",
  decision: "ask",
  description: "Force-deleting a local branch that may have unmerged commits",
  check(cmd) {
    const g = gitSubcommand(cmd);
    if (!g || g.sub !== "branch") return null;
    const f = flags(g.args);
    const force = f.short.has("D") || ((f.short.has("d") || f.long.has("--delete")) && (f.short.has("f") || f.long.has("--force")));
    if (!force) return null;
    const names = g.args.filter((a) => !a.startsWith("-"));
    return {
      decision: names.some((n) => PROTECTED.has(n)) ? "deny" : undefined,
      reason: `\`git branch -D\` deletes \`${names.join(", ")}\` even if it has commits that exist nowhere else.`,
      suggestion: "Use `git branch -d`, which refuses to delete unmerged work.",
    };
  },
  examples: {
    flag: ["git branch -D feature/x", "git branch -d --force old", "git branch -D main"],
    pass: ["git branch -d merged-feature", "git branch new-feature"],
  },
};

export const historyRewrite: CommandRule = {
  kind: "command",
  id: "git.history-rewrite",
  decision: "ask",
  description: "Rewriting repository history (filter-branch, filter-repo, reflog expire)",
  check(cmd) {
    const g = gitSubcommand(cmd);
    if (!g) return null;
    if (g.sub === "filter-branch" || g.sub === "filter-repo") {
      return { reason: `\`git ${g.sub}\` rewrites every matching commit in history.` };
    }
    if (g.sub === "reflog" && g.args[0] === "expire") {
      return { reason: "`git reflog expire` removes the safety log used to recover lost commits." };
    }
    if (g.sub === "update-ref" && g.args.includes("-d")) {
      return { reason: "`git update-ref -d` deletes a ref directly, bypassing safety checks." };
    }
    return null;
  },
  examples: {
    flag: ["git filter-branch --tree-filter 'rm secrets' HEAD", "git filter-repo --path secret.txt --invert-paths", "git reflog expire --expire=now --all"],
    pass: ["git reflog", "git log --oneline"],
  },
};

export const noVerify: CommandRule = {
  kind: "command",
  id: "git.no-verify",
  decision: "ask",
  description: "Skipping git hooks with `--no-verify`",
  check(cmd) {
    const g = gitSubcommand(cmd);
    if (!g || !["commit", "push", "merge", "rebase", "am"].includes(g.sub)) return null;
    const f = flags(g.args);
    const skip = f.long.has("--no-verify") || (g.sub === "commit" && f.short.has("n"));
    if (!skip) return null;
    return {
      reason: `\`git ${g.sub} --no-verify\` skips the repository's pre-${g.sub === "push" ? "push" : "commit"} checks.`,
      suggestion: "Fix whatever the hook is reporting instead of bypassing it.",
    };
  },
  examples: {
    flag: ["git commit --no-verify -m wip", "git commit -nm wip", "git push --no-verify"],
    pass: ["git commit -m 'fix: handle null'", "git commit -am wip"],
  },
};

export const gitRules = [forcePush, pushDelete, resetHard, clean, discardChanges, branchForceDelete, historyRewrite, noVerify];
