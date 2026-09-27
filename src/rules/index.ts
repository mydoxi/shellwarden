import { cloudRules } from "./cloud.js";
import { databaseRules } from "./database.js";
import { fileRules, selfRules } from "./files.js";
import { filesystemRules } from "./filesystem.js";
import { gitRules } from "./git.js";
import { networkRules } from "./network.js";
import { releaseRules } from "./release.js";
import type { Rule } from "./types.js";

export const builtinRules: Rule[] = [
  ...filesystemRules,
  ...gitRules,
  ...databaseRules,
  ...cloudRules,
  ...networkRules,
  ...releaseRules,
  ...fileRules,
  ...selfRules,
];

export type { CommandRule, Decision, FileContext, FileRule, Hit, RawRule, Rule } from "./types.js";
