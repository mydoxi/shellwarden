import { flags, positionals } from "../analyze.js";
import { isCatastrophicPath, isCwdOrAncestor } from "./paths.js";
import type { CommandRule, RawRule } from "./types.js";

function isRecursiveRm(program: string, args: string[]): boolean {
  if (program !== "rm") return false;
  const f = flags(args);
  return f.short.has("r") || f.short.has("R") || f.long.has("--recursive");
}

export const rmRoot: CommandRule = {
  kind: "command",
  id: "fs.rm-root",
  decision: "deny",
  description: "Recursive delete of /, the home directory, or a system directory",
  check(cmd) {
    if (cmd.program !== "rm") return null;
    if (cmd.args.includes("--no-preserve-root")) {
      return { reason: "`rm --no-preserve-root` disables the last safety net against wiping the whole filesystem." };
    }
    if (!isRecursiveRm(cmd.program, cmd.args)) return null;
    const target = positionals(cmd.args).find((t) => isCatastrophicPath(t, cmd.env));
    if (!target) return null;
    return {
      reason: `\`rm -r ${target}\` would recursively delete ${target === "/" ? "the entire filesystem" : `\`${target}\``}.`,
      suggestion: "Delete the specific project files or directories you mean instead.",
    };
  },
  examples: {
    flag: ["rm -rf /", "rm -rf ~", "rm -rf ~/", "rm -rf $HOME", "rm -fr /*", "sudo rm -rf /usr", "rm -rf ../..", "rm --no-preserve-root -rf /", "rm -r -f ~/*"],
    pass: ["rm -rf node_modules", "rm -rf ./dist build", "rm -rf /tmp/cache", "rm -f /", "rm -rf ~/project/tmp"],
  },
};

export const rmBroad: CommandRule = {
  kind: "command",
  id: "fs.rm-broad",
  decision: "ask",
  description: "Recursive delete of the current project, a parent directory, a bare `*`, or an unchecked variable",
  check(cmd) {
    if (!isRecursiveRm(cmd.program, cmd.args)) return null;
    for (const t of positionals(cmd.args)) {
      if (isCatastrophicPath(t, cmd.env)) continue; // fs.rm-root covers these.
      if (t === "*" || t === ".*") {
        return { reason: `\`rm -r ${t}\` deletes everything in the current directory.`, suggestion: "Name the files or directories to delete." };
      }
      if (/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\/\*?$/.test(t)) {
        return {
          reason: `\`rm -r ${t}\` becomes \`rm -r /\` if the variable is empty or unset.`,
          suggestion: 'Use `${VAR:?}` so the shell aborts when the variable is empty, e.g. `rm -rf "${VAR:?}/"`.',
        };
      }
      if (isCwdOrAncestor(t, cmd.env)) {
        return {
          reason: `\`rm -r ${t}\` deletes the current working directory (${cmd.env.cwd}) or one of its parents.`,
          suggestion: "Delete specific subdirectories instead.",
        };
      }
    }
    return null;
  },
  examples: {
    flag: ["rm -rf *", "rm -rf .", "rm -rf ./", "rm -rf ../project", 'rm -rf "$BUILD_DIR/"', "rm -rf $TARGET/*", "rm -rf /home/dev/project"],
    pass: ["rm -rf node_modules", "rm -rf ./src/generated", "rm -rf *.log", 'rm -rf "${BUILD_DIR:?}/"', "rm -rf ../other-project/dist"],
  },
};

export const findDelete: CommandRule = {
  kind: "command",
  id: "fs.find-delete-root",
  decision: "deny",
  description: "`find -delete` or `find -exec rm` starting from /, home, or a system directory",
  check(cmd) {
    if (cmd.program !== "find") return null;
    const deletes = cmd.args.includes("-delete") || cmd.args.some((a, i) => (a === "-exec" || a === "-execdir") && cmd.args[i + 1] === "rm");
    if (!deletes) return null;
    const start = cmd.args.find((a) => !a.startsWith("-"));
    if (!start || !isCatastrophicPath(start, cmd.env)) return null;
    return { reason: `\`find ${start} ... -delete\` can delete files across the whole ${start === "/" ? "filesystem" : "directory tree"}.`, suggestion: "Run `find` from the project directory." };
  },
  examples: {
    flag: ["find / -name '*.log' -delete", "find ~ -type f -exec rm {} ;"],
    pass: ["find . -name '*.pyc' -delete", "find / -name foo", "find src -type f -exec rm {} +"],
  },
};

const BLOCK_DEVICE = /^\/dev\/(sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|disk\d|mmcblk\d|md\d|dm-\d|mapper\/)/;

export const diskWipe: CommandRule = {
  kind: "command",
  id: "fs.disk-wipe",
  decision: "deny",
  description: "Formatting or overwriting a disk device (mkfs, dd of=/dev/..., wipefs)",
  check(cmd) {
    if (/^mkfs(\.|$)/.test(cmd.program) || cmd.program === "wipefs" || cmd.program === "mkswap") {
      return { reason: `\`${cmd.program}\` formats or wipes a disk.` };
    }
    if (cmd.program === "dd") {
      const of = cmd.args.find((a) => a.startsWith("of="));
      if (of && BLOCK_DEVICE.test(of.slice(3))) return { reason: `\`dd ${of}\` overwrites a disk device.` };
    }
    if ((cmd.program === "shred" || cmd.program === "fdisk" || cmd.program === "sfdisk" || cmd.program === "parted") && cmd.args.some((a) => BLOCK_DEVICE.test(a))) {
      return { reason: `\`${cmd.program}\` on a disk device can destroy all data on it.` };
    }
    const redirect = cmd.redirects.find((r) => r.op.includes(">") && BLOCK_DEVICE.test(r.target));
    if (redirect) return { reason: `Redirecting output to \`${redirect.target}\` overwrites a disk device.` };
    return null;
  },
  examples: {
    flag: ["mkfs.ext4 /dev/sda1", "dd if=/dev/zero of=/dev/sda bs=1M", "echo x > /dev/nvme0n1", "wipefs -a /dev/sdb", "shred -n 3 /dev/sda"],
    pass: ["dd if=/dev/zero of=./disk.img bs=1M count=10", "echo hi > /dev/null", "cat /dev/urandom | head -c 16"],
  },
};

export const chmodRoot: CommandRule = {
  kind: "command",
  id: "fs.chmod-root",
  decision: "deny",
  description: "Recursive chmod/chown/chgrp of /, home, or a system directory",
  check(cmd) {
    if (!["chmod", "chown", "chgrp"].includes(cmd.program)) return null;
    const f = flags(cmd.args);
    if (!f.short.has("R") && !f.long.has("--recursive")) return null;
    const target = positionals(cmd.args).slice(1).find((t) => isCatastrophicPath(t, cmd.env));
    if (!target) return null;
    return { reason: `\`${cmd.program} -R ... ${target}\` changes ownership or permissions across ${target === "/" ? "the whole system" : `\`${target}\``} and can break the OS or lock you out.` };
  },
  examples: {
    flag: ["chmod -R 777 /", "sudo chown -R me /usr", "chmod -R 700 ~"],
    pass: ["chmod -R 755 ./scripts", "chown -R me ./data", "chmod +x build.sh"],
  },
};

export const chmodWorldWritable: CommandRule = {
  kind: "command",
  id: "fs.chmod-777",
  decision: "ask",
  description: "Recursively making files world-writable (chmod -R 777)",
  check(cmd) {
    if (cmd.program !== "chmod") return null;
    const f = flags(cmd.args);
    if (!f.short.has("R") && !f.long.has("--recursive")) return null;
    const mode = positionals(cmd.args)[0] ?? "";
    if (mode === "777" || mode === "0777" || /^(a|ugo|o)\+rwx$/.test(mode) || mode === "o+w" || mode === "a+w") {
      return { reason: `\`chmod -R ${mode}\` makes every file writable by any user.`, suggestion: "Grant only the permissions needed, e.g. `chmod -R u+rwX`." };
    }
    return null;
  },
  examples: {
    flag: ["chmod -R 777 ./public", "chmod -R a+rwx storage"],
    pass: ["chmod 644 file.txt", "chmod -R 755 ./bin"],
  },
};

export const forkBomb: RawRule = {
  kind: "raw",
  id: "sys.fork-bomb",
  decision: "deny",
  description: "Shell fork bomb",
  check(command) {
    if (/(\S+)\s*\(\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1/.test(command)) {
      return { reason: "This is a fork bomb: it spawns processes until the machine becomes unresponsive." };
    }
    return null;
  },
  examples: {
    flag: [":(){ :|:& };:", "bomb(){ bomb|bomb& };bomb"],
    pass: ["f(){ echo hi; }; f"],
  },
};

export const powerOff: CommandRule = {
  kind: "command",
  id: "sys.shutdown",
  decision: "ask",
  description: "Shutting down or rebooting the machine",
  check(cmd) {
    if (["shutdown", "reboot", "halt", "poweroff"].includes(cmd.program)) {
      return { reason: `\`${cmd.program}\` will shut down or restart the machine.` };
    }
    if (cmd.program === "systemctl" && ["poweroff", "reboot", "halt", "kexec"].some((a) => cmd.args.includes(a))) {
      return { reason: "`systemctl` will shut down or restart the machine." };
    }
    if (cmd.program === "init" && (cmd.args[0] === "0" || cmd.args[0] === "6")) {
      return { reason: `\`init ${cmd.args[0]}\` will shut down or restart the machine.` };
    }
    return null;
  },
  examples: {
    flag: ["sudo shutdown -h now", "reboot", "systemctl reboot"],
    pass: ["systemctl restart nginx", "echo shutdown"],
  },
};

export const killAll: CommandRule = {
  kind: "command",
  id: "sys.kill-all",
  decision: "deny",
  description: "Killing every process the user can reach (kill -9 -1)",
  check(cmd) {
    // A leading `-1` is the signal (SIGHUP); `-1` anywhere after it is the "every process" target.
    if (cmd.program === "kill" && cmd.args.indexOf("-1", 1) !== -1) {
      return { reason: "`kill ... -1` sends the signal to every process you own, which ends your session." };
    }
    if (cmd.program === "killall5") return { reason: "`killall5` signals every process on the system." };
    return null;
  },
  examples: {
    flag: ["kill -9 -1", "kill -KILL -1", "kill -- -1"],
    pass: ["kill -9 1234", "kill -1 1234", "kill %1", "pkill -f 'node server.js'"],
  },
};

export const crontabRemove: CommandRule = {
  kind: "command",
  id: "sys.crontab-remove",
  decision: "ask",
  description: "Deleting the user's entire crontab",
  check(cmd) {
    if (cmd.program === "crontab" && flags(cmd.args).short.has("r")) {
      return { reason: "`crontab -r` deletes all of your scheduled jobs without confirmation.", suggestion: "Use `crontab -e` to remove individual entries." };
    }
    return null;
  },
  examples: { flag: ["crontab -r"], pass: ["crontab -l", "crontab -e"] },
};

export const sudo: CommandRule = {
  kind: "command",
  id: "sys.sudo",
  decision: "ask",
  description: "Running a command with root privileges (sudo, doas)",
  check(cmd) {
    if (!cmd.elevated || cmd.program === "") return null;
    // Report once per elevated command line, on the command sudo wraps directly.
    if (!/^\s*([A-Za-z_][A-Za-z0-9_]*=\S*\s+)*(sudo|doas)\b/.test(cmd.text)) return null;
    return { reason: `\`${cmd.program}\` would run as root.` };
  },
  examples: {
    flag: ["sudo apt-get install -y jq", "doas make install", "DEBIAN_FRONTEND=noninteractive sudo apt-get upgrade"],
    pass: ["apt-get install -y jq", "echo sudo"],
  },
};

export const filesystemRules = [rmRoot, rmBroad, findDelete, diskWipe, chmodRoot, chmodWorldWritable, forkBomb, powerOff, killAll, crontabRemove, sudo];
