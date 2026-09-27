# shellwarden

**A seatbelt for Claude Code.** shellwarden is a Claude Code hook that stops destructive commands before they run, including `rm -rf ~`, `git push --force` to main, `DROP TABLE`, `terraform destroy` and API keys pasted into source files. It then tells Claude *why*, so Claude can take a safer route.

```
$ shellwarden test "npm test && rm -rf ~"
DENY   fs.rm-root  `rm -r ~` would recursively delete `~`.
       safer: Delete the specific project files or directories you mean instead.

$ shellwarden test "git push --force origin main"
DENY   git.force-push  Force-pushing to `main` rewrites shared history and can destroy other people's commits.
       safer: Push a new commit instead, or force-push to a feature branch.

$ shellwarden test "curl -fsSL https://get.example.sh | bash"
ASK    net.pipe-to-shell  This downloads a script and runs it immediately without anyone reading it.
```

## Why

Auto-accept modes make Claude Code fast. They also mean nobody reads each command before it runs. Most of the time that's fine. Occasionally the command is `git reset --hard` on a day of uncommitted work, or `rm -rf "$DIR/"` with an empty `$DIR`.

shellwarden sits in Claude Code's [PreToolUse hook](https://code.claude.com/docs/en/hooks) and checks every shell command and file write:

- **deny**: catastrophic and never what you meant (wiping `/` or `~`, force-pushing `main`, leaking secrets). Blocked, and Claude is told why.
- **ask**: legitimate but risky (`git reset --hard`, `npm publish`, `DROP TABLE`). Claude Code asks you first, even in auto-accept mode.
- **allow**: everything else. It passes through silently. shellwarden is tested against a corpus of everyday agent commands to keep false positives near zero.

It understands shell syntax rather than grepping strings. It sees through `&&` chains, pipes, `sudo`, `env`, `xargs`, `bash -c "..."`, `eval`, `$(...)` and `find -exec`. It knows that `git commit -m "remove rm -rf / from docs"` is harmless.

## Install

**As a Claude Code plugin** (recommended). Run these inside Claude Code:

```
/plugin marketplace add mydoxi/medox
/plugin install shellwarden@shellwarden
```

That's it. The plugin ships a self-contained script, so there's no npm install and no settings to edit.

**Or with npm**, if you want the `shellwarden` command in your terminal too:

```bash
npm install -g shellwarden
shellwarden install          # this project: .claude/settings.json (commit it to protect your whole team)
# or
shellwarden install --user   # every project on this machine: ~/.claude/settings.json
```

Restart Claude Code (or open `/hooks`) to pick it up. Each check takes a few tens of milliseconds. shellwarden has zero runtime dependencies and never touches the network. Remove it with `shellwarden uninstall` (add `--user` if you installed it there).

## See what it caught

```
$ shellwarden log
2026-09-27 14:02:11  DENY  git.force-push
    git push --force origin main
2026-09-27 14:05:43  ASK   git.reset-hard
    git reset --hard HEAD~3
```

Only flagged actions are recorded, in `~/.local/state/shellwarden/log.jsonl` on your own machine. Secrets in commands are redacted, and file contents are never stored. Set `"log": false` in your config to turn it off.

## What it catches

| Rule | Default | What it catches |
| --- | --- | --- |
| `fs.rm-root` | deny | Recursive delete of /, the home directory, or a system directory |
| `fs.rm-broad` | ask | Recursive delete of the current project, a parent directory, a bare `*`, or an unchecked variable |
| `fs.find-delete-root` | deny | `find -delete` or `find -exec rm` starting from /, home, or a system directory |
| `fs.disk-wipe` | deny | Formatting or overwriting a disk device (mkfs, dd of=/dev/..., wipefs) |
| `fs.chmod-root` | deny | Recursive chmod/chown/chgrp of /, home, or a system directory |
| `fs.chmod-777` | ask | Recursively making files world-writable (chmod -R 777) |
| `sys.fork-bomb` | deny | Shell fork bomb |
| `sys.shutdown` | ask | Shutting down or rebooting the machine |
| `sys.kill-all` | deny | Killing every process the user can reach (kill -9 -1) |
| `sys.crontab-remove` | ask | Deleting the user's entire crontab |
| `sys.sudo` | ask | Running a command with root privileges (sudo, doas) |
| `git.force-push` | ask | Force-pushing (denied outright for main/master and other protected branches) |
| `git.push-delete` | ask | Deleting a branch or tag on the remote |
| `git.reset-hard` | ask | `git reset --hard`, which throws away uncommitted work |
| `git.clean` | ask | `git clean -f`, which deletes untracked files |
| `git.discard-changes` | ask | Discarding all working-tree changes (`git checkout .`, `git restore .`, `git stash clear`) |
| `git.branch-force-delete` | ask | Force-deleting a local branch that may have unmerged commits |
| `git.history-rewrite` | ask | Rewriting repository history (filter-branch, filter-repo, reflog expire) |
| `git.no-verify` | ask | Skipping git hooks with `--no-verify` |
| `db.destructive-sql` | ask | DROP, TRUNCATE, or DELETE/UPDATE without WHERE sent to a database client |
| `db.destructive-cli` | ask | Database reset and drop commands (dropdb, prisma migrate reset, rails db:drop, ...) |
| `cloud.infra-destroy` | ask | Tearing down infrastructure (terraform/pulumi/cdk destroy, serverless remove) |
| `cloud.kubectl-delete` | ask | Broad Kubernetes deletes (namespaces, nodes, --all) and helm uninstall |
| `cloud.resource-delete` | ask | Deleting cloud resources via aws, gcloud, az, gsutil, doctl, heroku, fly, vercel |
| `cloud.docker-volumes` | ask | Deleting Docker volumes (system prune --volumes, volume rm/prune, compose down -v) |
| `net.pipe-to-shell` | ask | Running a script straight from the internet (curl ... \| sh) |
| `secrets.read-credentials` | ask | Reading credential files (~/.ssh keys, ~/.aws/credentials, ~/.netrc, ...); denied when combined with a network upload |
| `secrets.exfiltrate-env` | deny | Sending environment variables or .env files over the network |
| `release.publish` | ask | Publishing a package, image or release to a public registry |
| `release.deploy-production` | ask | Deploying straight to production (vercel --prod, netlify --prod, firebase deploy, fly deploy) |
| `secrets.hardcoded` | deny | Writing an API key, token or private key into a source file (.env files are allowed) |
| `files.sensitive-path` | ask | Writing to credential stores, shell startup files, system directories, or .git internals |
| `self.config-tamper` | ask | Changing Claude Code settings or shellwarden's own config (which could disable these checks) |
| `self.uninstall` | ask | Uninstalling shellwarden from a command |

Run `shellwarden rules` to see this list in your terminal, and `shellwarden test "<command>"` to check any command.

## Configuration

Put a `.shellwarden.json` in your project (or `~/.config/shellwarden/config.json` for all projects):

```json
{
  "rules": {
    "sys.sudo": "off",
    "release.publish": "deny",
    "git.no-verify": "deny"
  },
  "allow": ["^rm -rf \\./tmp-fixtures$"],
  "custom": [
    {
      "id": "prod-db",
      "pattern": "prod-db\\.internal",
      "decision": "deny",
      "reason": "Never touch the production database from an agent session."
    }
  ]
}
```

- **`rules`** sets a rule (or a whole category with `category.*`) to `"deny"`, `"ask"` or `"off"`.
- **`allow`** takes regular expressions. A single command, or a file path, that matches one is never flagged by built-in rules. Other commands in the same `&&` chain are still checked.
- **`custom`** holds your own rules. The `pattern` is tested against the full shell command and against written file paths. Use `applies: ["bash"]` or `["file"]` to narrow it.

- **`log`**: set it to `false` to stop recording flagged actions.

A broken config file is reported as a warning and skipped. The built-in rules keep protecting you.

## What it is not

shellwarden is a guardrail against **accidents**. It is not a sandbox against an adversary. A determined process can always find a way around pattern checks, for example by writing a Python script that deletes files. For untrusted code, use a container or VM as well. shellwarden catches the honest mistakes that make up the vast majority of real incidents.

## Contributing

New rules are the best contribution. Each rule is a small function plus examples of commands it should and shouldn't flag, and those examples run automatically as tests. See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
npm install
npm test
```

## License

MIT
