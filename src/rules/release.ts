import type { CommandRule } from "./types.js";

type Matcher = (program: string, args: string[]) => string | null;

const PUBLISHERS: Matcher[] = [
  (p, a) => (["npm", "pnpm", "bun"].includes(p) && a[0] === "publish" ? `${p} publish` : null),
  (p, a) => (p === "yarn" && (a[0] === "publish" || (a[0] === "npm" && a[1] === "publish")) ? "yarn publish" : null),
  (p, a) => (p === "cargo" && a[0] === "publish" && !a.includes("--dry-run") ? "cargo publish" : null),
  (p, a) => (p === "twine" && a[0] === "upload" ? "twine upload" : null),
  (p, a) => ((p === "python" || p === "python3") && a[0] === "-m" && a[1] === "twine" && a[2] === "upload" ? "twine upload" : null),
  (p, a) => ((p === "poetry" || p === "uv" || p === "flit" || p === "hatch") && a[0] === "publish" ? `${p} publish` : null),
  (p, a) => (p === "gem" && a[0] === "push" ? "gem push" : null),
  (p, a) => (p === "dotnet" && a[0] === "nuget" && a[1] === "push" ? "dotnet nuget push" : null),
  (p, a) => ((p === "vsce" || p === "ovsx") && a[0] === "publish" ? `${p} publish` : null),
  (p, a) => ((p === "docker" || p === "podman") && (a[0] === "push" || (a[0] === "image" && a[1] === "push")) ? `${p} push` : null),
  (p, a) => (p === "gh" && a[0] === "release" && a[1] === "create" ? "gh release create" : null),
  (p, a) => ((p === "dart" || p === "flutter") && a[0] === "pub" && a[1] === "publish" && !a.includes("--dry-run") ? `${p} pub publish` : null),
  (p, a) => (p === "pod" && a[0] === "trunk" && a[1] === "push" ? "pod trunk push" : null),
  (p, a) => (p === "mix" && a[0] === "hex.publish" ? "mix hex.publish" : null),
  (p, a) => (p === "mvn" && a.includes("deploy") ? "mvn deploy" : null),
];

export const publishPackage: CommandRule = {
  kind: "command",
  id: "release.publish",
  decision: "ask",
  description: "Publishing a package, image or release to a public registry",
  check(cmd) {
    if (cmd.args.includes("--dry-run")) return null;
    for (const m of PUBLISHERS) {
      const what = m(cmd.program, cmd.args);
      if (what) return { reason: `\`${what}\` publishes to a registry. Published versions are public and usually cannot be taken back.` };
    }
    return null;
  },
  examples: {
    flag: ["npm publish", "pnpm publish --access public", "cargo publish", "python -m twine upload dist/*", "docker push me/app:latest", "gh release create v1.0.0"],
    pass: ["npm publish --dry-run", "npm pack", "cargo build --release", "docker build -t me/app .", "gh release list"],
  },
};

export const deployProduction: CommandRule = {
  kind: "command",
  id: "release.deploy-production",
  decision: "ask",
  description: "Deploying straight to production (vercel --prod, netlify --prod, firebase deploy, fly deploy)",
  check(cmd) {
    const p = cmd.program;
    const a = cmd.args;
    if (p === "vercel" && (a.includes("--prod") || a.includes("--production"))) return { reason: "`vercel --prod` deploys to production." };
    if (p === "netlify" && a[0] === "deploy" && a.includes("--prod")) return { reason: "`netlify deploy --prod` deploys to production." };
    if (p === "firebase" && a[0] === "deploy") return { reason: "`firebase deploy` deploys to the live project." };
    if ((p === "fly" || p === "flyctl") && a[0] === "deploy") return { reason: "`fly deploy` deploys to the live app." };
    if (p === "gcloud" && a.includes("deploy")) return { reason: "`gcloud ... deploy` deploys to Google Cloud." };
    return null;
  },
  examples: {
    flag: ["vercel --prod", "netlify deploy --prod --dir dist", "firebase deploy --only hosting", "fly deploy"],
    pass: ["vercel", "netlify deploy --dir dist", "firebase emulators:start"],
  },
};

export const releaseRules = [publishPackage, deployProduction];
