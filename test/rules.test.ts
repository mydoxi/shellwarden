import { describe, expect, it } from "vitest";
import { evaluateCommand, evaluateFileWrite } from "../src/engine.js";
import { builtinRules } from "../src/rules/index.js";

const env = { cwd: "/home/dev/project", home: "/home/dev" };

function ruleIdsForCommand(command: string): string[] {
  return evaluateCommand(command, env).findings.map((f) => f.ruleId);
}

function ruleIdsForFile(file: { path: string; content?: string }): string[] {
  return evaluateFileWrite({ tool: "Write", path: file.path, content: file.content ?? "" }, env).findings.map((f) => f.ruleId);
}

describe("built-in rule examples", () => {
  it("has unique rule ids", () => {
    const ids = builtinRules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  for (const rule of builtinRules) {
    describe(rule.id, () => {
      it("has at least one flag and one pass example", () => {
        expect(rule.examples.flag.length).toBeGreaterThan(0);
        expect(rule.examples.pass.length).toBeGreaterThan(0);
      });

      if (rule.kind === "file") {
        for (const ex of rule.examples.flag) {
          it(`flags write to ${ex.path}`, () => expect(ruleIdsForFile(ex)).toContain(rule.id));
        }
        for (const ex of rule.examples.pass) {
          it(`allows write to ${ex.path}`, () => expect(ruleIdsForFile(ex)).not.toContain(rule.id));
        }
      } else {
        for (const ex of rule.examples.flag) {
          it(`flags: ${ex}`, () => expect(ruleIdsForCommand(ex)).toContain(rule.id));
        }
        for (const ex of rule.examples.pass) {
          it(`allows: ${ex}`, () => expect(ruleIdsForCommand(ex)).not.toContain(rule.id));
        }
      }
    });
  }
});
