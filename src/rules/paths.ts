import path from "node:path";
import { resolvePath, type Env } from "../analyze.js";

/** Top-level directories whose recursive deletion or chmod would wreck the machine. */
const SYSTEM_DIRS = [
  "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/opt", "/proc", "/root",
  "/sbin", "/srv", "/sys", "/usr", "/var", "/home", "/mnt", "/media", "/snap",
  "/Users", "/System", "/Library", "/Applications", "/Volumes", "/private",
];

function stripGlob(p: string): string {
  return p.replace(/\/\*+$/, "").replace(/\/+$/, "") || "/";
}

/**
 * True when `target` is the filesystem root, the home directory, or a
 * top-level system directory, including glob forms like `/*` and `~/*`.
 */
export function isCatastrophicPath(target: string, env: Env): boolean {
  const cleaned = target.replace(/^["']|["']$/g, "");
  if (/^[A-Za-z]:[\\/]?\*?$/.test(cleaned)) return true;
  const abs = stripGlob(resolvePath(cleaned, env));
  if (abs === "/" || abs === stripGlob(env.home)) return true;
  if (SYSTEM_DIRS.includes(abs)) return true;
  return false;
}

/** True when `target` is the working directory itself or one of its ancestors. */
export function isCwdOrAncestor(target: string, env: Env): boolean {
  const abs = stripGlob(resolvePath(target, env));
  const rel = path.relative(abs, env.cwd);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/** Paths that hold credentials. */
export function isCredentialPath(abs: string, env: Env): boolean {
  const home = env.home.replace(/\/+$/, "");
  const inHome = (rel: string) => abs === `${home}/${rel}` || abs.startsWith(`${home}/${rel}/`);
  if (abs.startsWith(`${home}/.ssh/`)) {
    const name = path.basename(abs);
    return !name.endsWith(".pub") && name !== "known_hosts" && name !== "config" && name !== "authorized_keys";
  }
  return (
    inHome(".aws/credentials") ||
    inHome(".aws/sso/cache") ||
    inHome(".config/gcloud/application_default_credentials.json") ||
    inHome(".config/gcloud/credentials.db") ||
    inHome(".azure") ||
    inHome(".netrc") ||
    inHome(".git-credentials") ||
    inHome(".docker/config.json") ||
    inHome(".kube/config") ||
    inHome(".npmrc") ||
    inHome(".pypirc") ||
    inHome(".gnupg") ||
    inHome(".config/gh/hosts.yml") ||
    abs === "/etc/shadow" ||
    abs === "/etc/sudoers"
  );
}

export function isEnvFile(abs: string): boolean {
  const name = path.basename(abs);
  return /^\.env(\..+)?$/.test(name) && !/\.(example|sample|template|dist|defaults)$/i.test(name);
}
