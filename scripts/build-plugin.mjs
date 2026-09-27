// Bundles the CLI into a single dependency-free file for the Claude Code plugin,
// and keeps the plugin manifest's version in sync with package.json.
import { build } from "esbuild";
import fs from "node:fs";

const pkg = JSON.parse(fs.readFileSync("package.json", "utf8"));

await build({
  entryPoints: ["src/cli.ts"],
  outfile: "plugin/scripts/shellwarden.mjs",
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  define: { SHELLWARDEN_VERSION: JSON.stringify(pkg.version) },
  legalComments: "none",
});

for (const file of ["plugin/.claude-plugin/plugin.json", ".claude-plugin/marketplace.json"]) {
  const json = JSON.parse(fs.readFileSync(file, "utf8"));
  if (json.plugins) for (const p of json.plugins) p.version = pkg.version;
  else json.version = pkg.version;
  fs.writeFileSync(file, `${JSON.stringify(json, null, 2)}\n`);
}
