import { describe, expect, it } from "vitest";
import { analyzeCommand, unwrap } from "../src/analyze.js";
import { parseShell } from "../src/shell.js";

const env = { cwd: "/home/dev/project", home: "/home/dev" };
const argvs = (cmd: string) => parseShell(cmd).flatMap((p) => p.commands.map((c) => c.argv));
const programs = (cmd: string) => analyzeCommand(cmd, env).map((c) => [c.program, ...c.args].join(" "));

describe("parseShell", () => {
  it("splits command lists and pipelines", () => {
    const pls = parseShell("a 1 && b 2 || c; d | e |& f & g");
    expect(pls.map((p) => p.commands.map((c) => c.argv[0]))).toEqual([["a"], ["b"], ["c"], ["d", "e", "f"], ["g"]]);
  });

  it("removes quotes and handles escapes", () => {
    expect(argvs(`echo "a b" 'c d' e\\ f "x\\"y" $'t\\tq'`)).toEqual([["echo", "a b", "c d", "e f", 'x"y', "t\tq"]]);
  });

  it("keeps operators inside quotes as text", () => {
    expect(argvs(`echo "a && b; c | d"`)).toEqual([["echo", "a && b; c | d"]]);
  });

  it("records redirections", () => {
    const [cmd] = parseShell("cat a >out.txt 2>&1 >> log 2> err <in").flatMap((p) => p.commands);
    expect(cmd!.argv).toEqual(["cat", "a"]);
    expect(cmd!.redirects).toEqual([
      { op: ">", target: "out.txt" },
      { op: ">>", target: "log" },
      { op: ">", target: "err" },
      { op: "<", target: "in" },
    ]);
  });

  it("captures heredoc bodies without treating them as commands", () => {
    const pls = parseShell("psql <<'SQL'\nDROP TABLE x;\nrm -rf /\nSQL\necho done");
    expect(pls.map((p) => p.commands[0]!.argv[0])).toEqual(["psql", "echo"]);
    expect(pls[0]!.commands[0]!.heredocs).toEqual(["DROP TABLE x;\nrm -rf /"]);
  });

  it("parses command substitutions recursively", () => {
    expect(argvs("echo $(rm -rf /tmp/x) `ls`").map((a) => a[0])).toEqual(["echo", "rm", "ls"]);
  });

  it("handles the heredoc-in-substitution pattern Claude uses for commit messages", () => {
    const cmd = `git commit -m "$(cat <<'EOF'\nfix: don't crash when rm -rf / is mentioned (really)\n\nIt's fine.\nEOF\n)" && git push`;
    expect(programs(cmd)).toEqual([
      "git commit -m $(cat <<'EOF'\nfix: don't crash when rm -rf / is mentioned (really)\n\nIt's fine.\nEOF\n)",
      "git push",
      "cat",
    ]);
  });

  it("ignores comments and line continuations", () => {
    expect(argvs("ls \\\n  -la # rm -rf /")).toEqual([["ls", "-la"]]);
  });
});

describe("unwrap", () => {
  it("strips sudo, env, assignments and other wrappers", () => {
    expect(unwrap(["sudo", "-u", "root", "env", "A=1", "nice", "-n", "5", "rm", "-rf", "x"])).toEqual({ argv: ["rm", "-rf", "x"], elevated: true });
    expect(unwrap(["FOO=bar", "timeout", "10", "xargs", "-0", "rm"])).toEqual({ argv: ["rm"], elevated: false });
  });
});

describe("analyzeCommand", () => {
  it("looks inside bash -c, eval and find -exec", () => {
    expect(programs(`bash -lc "cd /tmp && rm -rf x"`)).toContain("rm -rf x");
    expect(programs(`eval "git push --force"`)).toContain("git push --force");
    expect(programs(`find . -name '*.tmp' -exec rm -f {} ;`)).toContain("rm -f {}");
  });

  it("marks commands under sudo as elevated, including nested ones", () => {
    const cmds = analyzeCommand(`sudo sh -c "rm -rf /var/cache"`, env);
    expect(cmds.every((c) => c.elevated)).toBe(true);
  });

  it("resolves /bin/rm and \\rm to rm", () => {
    expect(analyzeCommand("/bin/rm -rf a; \\rm b", env).map((c) => c.program)).toEqual(["rm", "rm"]);
  });
});
