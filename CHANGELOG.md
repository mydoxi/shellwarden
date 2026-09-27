# Changelog

## 0.1.0

First release.

- PreToolUse hook for Claude Code covering Bash, Write, Edit, MultiEdit and NotebookEdit.
- 34 built-in rules across filesystem, system, git, database, cloud, network, secrets, release and self-protection.
- Shell parser that sees through `&&`/`||`/`;` chains, pipes, `sudo`, `env`, `xargs`, `bash -c`, `eval`, `$(...)`, heredocs and `find -exec`.
- `shellwarden install` / `uninstall` / `test` / `rules` commands.
- Project and user config: per-rule overrides, allow patterns and custom rules.
