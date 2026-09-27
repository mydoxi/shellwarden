import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { emptyConfig } from "../src/config.js";
import { runHook } from "../src/hook.js";
import { HOOK_MATCHER, install, uninstall } from "../src/install.js";

const home = "/home/dev";
const hook = (payload: unknown) => runHook(JSON.stringify(payload), { home, config: emptyConfig() });

describe("runHook", () => {
  it("prints nothing for a safe command", () => {
    expect(hook({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, cwd: "/home/dev/project" })).toEqual({ stdout: "", stderr: "", exitCode: 0 });
  });

  it("emits a deny decision with the reason Claude will see", () => {
    const r = hook({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "rm -rf ~" }, cwd: "/home/dev/project" });
    expect(r.exitCode).toBe(0);
    const out = JSON.parse(r.stdout);
    expect(out.hookSpecificOutput.hookEventName).toBe("PreToolUse");
    expect(out.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(out.hookSpecificOutput.permissionDecisionReason).toContain("[fs.rm-root]");
  });

  it("emits an ask decision for risky-but-legitimate commands", () => {
    const r = hook({ tool_name: "Bash", tool_input: { command: "npm publish" }, cwd: "/home/dev/project" });
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("ask");
  });

  it("fails open with a warning on malformed input", () => {
    const r = runHook("not json", { home, config: emptyConfig() });
    expect(r.stdout).toBe("");
    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain("could not parse");
  });
});

describe("install / uninstall", () => {
  const tmp = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), "shellwarden-")), ".claude", "settings.json");

  it("adds the hook once and preserves existing settings", () => {
    const file = tmp();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify({ permissions: { allow: ["Bash(npm test)"] }, hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "other-hook" }] }] } }));

    expect(install(file, "shellwarden check").changed).toBe(true);
    expect(install(file, "shellwarden check").changed).toBe(false);

    const settings = JSON.parse(fs.readFileSync(file, "utf8"));
    expect(settings.permissions).toEqual({ allow: ["Bash(npm test)"] });
    expect(settings.hooks.PreToolUse).toHaveLength(2);
    expect(settings.hooks.PreToolUse[1]).toEqual({ matcher: HOOK_MATCHER, hooks: [{ type: "command", command: "shellwarden check", timeout: 10 }] });
  });

  it("uninstall removes only shellwarden and cleans up empty sections", () => {
    const file = tmp();
    install(file, "npx -y shellwarden check");
    expect(uninstall(file).changed).toBe(true);
    expect(JSON.parse(fs.readFileSync(file, "utf8"))).toEqual({});
    expect(uninstall(file).changed).toBe(false);
  });

  it("refuses to overwrite a settings file it cannot parse", () => {
    const file = tmp();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, "{ broken");
    expect(() => install(file, "shellwarden check")).toThrow();
    expect(fs.readFileSync(file, "utf8")).toBe("{ broken");
  });
});
