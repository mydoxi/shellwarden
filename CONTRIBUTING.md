# Contributing to shellwarden

Thanks for helping make coding agents safer. The most valuable contributions are **new rules** and **reports of false positives**.

## Adding a rule

Rules live in `src/rules/`, grouped by category (`filesystem.ts`, `git.ts`, `database.ts`, `cloud.ts`, `network.ts`, `release.ts`, `files.ts`). A command rule looks like this:

```ts
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
    flag: ["git reset --hard", "git reset --hard HEAD~3"],
    pass: ["git reset HEAD file.txt", "git reset --soft HEAD~1"],
  },
};
```

`check` receives a parsed command whose wrappers are already removed. `sudo env X=1 git reset --hard` arrives as `program: "git"`, `args: ["reset", "--hard"]`, `elevated: true`. Commands inside `&&` chains, pipes, `bash -c`, `eval`, `$(...)` and `find -exec` are each checked on their own.

Add the rule to its category's exported array, and it is registered automatically. The `examples` run as tests (`test/rules.test.ts`), in a fake environment where the working directory is `/home/dev/project` and home is `/home/dev`.

Guidelines:

- **`deny` is for things that are never intended.** Anything with a legitimate use should be `ask`.
- **Write the reason for Claude.** Say what will happen, and give a `suggestion` for a safer alternative when there is one.
- **Add `pass` examples for the near misses.** False positives are the main reason people uninstall safety tools. If your rule could plausibly match something harmless, prove it doesn't.
- If a benign command is flagged, add it to the `BENIGN` list in `test/engine.test.ts` along with the fix.

## Development

```bash
npm install
npm test            # all tests
npm run typecheck
npm run build
node dist/cli.js test "your command here"
npm run build:plugin   # regenerate plugin/scripts/shellwarden.mjs; commit it with your change
```

The Claude Code plugin runs a single bundled file, `plugin/scripts/shellwarden.mjs`, because plugins are installed straight from git without `npm install`. CI fails if the bundle is out of date.

## Reporting a false positive or a miss

Open an issue with the exact command (or file write), what shellwarden did, and what you expected. `shellwarden test "<command>"` shows which rule fired.
