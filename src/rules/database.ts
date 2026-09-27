import type { CommandContext } from "../analyze.js";
import type { CommandRule } from "./types.js";

const DB_CLIENTS = new Set([
  "psql", "mysql", "mariadb", "sqlite3", "sqlite", "sqlcmd", "mongosh", "mongo", "cockroach",
  "duckdb", "clickhouse-client", "clickhouse", "bq", "snowsql", "cqlsh", "turso", "pgcli", "mycli", "litecli",
]);

/** SQL (or Mongo shell) text reaching a database client in this pipeline. */
function sqlText(cmd: CommandContext): string | null {
  if (!DB_CLIENTS.has(cmd.program)) return null;
  const parts: string[] = [];
  for (const c of cmd.pipeline) {
    parts.push(...c.args, ...c.heredocs);
  }
  return parts.join("\n");
}

function destructiveStatement(sql: string): string | null {
  const statements = sql.split(";");
  for (const raw of statements) {
    const s = raw.replace(/--[^\n]*/g, " ").replace(/\s+/g, " ").trim();
    if (/\bdrop\s+(database|schema|table|collection|keyspace)\b/i.test(s)) return s;
    if (/\btruncate\s+(table\s+)?[\w."`\[]/i.test(s)) return s;
    if (/\bdelete\s+from\s+\S+/i.test(s) && !/\bwhere\b/i.test(s)) return s;
    if (/\bupdate\s+\S+\s+set\b/i.test(s) && !/\bwhere\b/i.test(s)) return s;
    if (/\balter\s+table\s+\S+\s+drop\b/i.test(s)) return s;
    if (/\.(dropDatabase|drop)\s*\(\s*\)/.test(s) || /\.deleteMany\s*\(\s*\{\s*\}\s*\)/.test(s)) return s;
    if (/^\s*(flushall|flushdb)\b/i.test(s)) return s;
  }
  return null;
}

export const destructiveSql: CommandRule = {
  kind: "command",
  id: "db.destructive-sql",
  decision: "ask",
  description: "DROP, TRUNCATE, or DELETE/UPDATE without WHERE sent to a database client",
  check(cmd) {
    const sql = sqlText(cmd);
    if (sql === null) return null;
    const stmt = destructiveStatement(sql);
    if (!stmt) return null;
    const shown = stmt.length > 80 ? `${stmt.slice(0, 77)}...` : stmt;
    return {
      reason: `\`${cmd.program}\` would run a destructive statement: \`${shown}\`.`,
      suggestion: "Confirm this is not a production database and that a backup exists.",
    };
  },
  examples: {
    flag: [
      'psql -c "DROP TABLE users"',
      'mysql -e "DELETE FROM orders"',
      "sqlite3 app.db 'truncate table logs'",
      'echo "DROP DATABASE prod;" | psql',
      "psql <<SQL\nUPDATE users SET admin = true;\nSQL",
      "mongosh --eval 'db.dropDatabase()'",
    ],
    pass: [
      'psql -c "SELECT * FROM users"',
      'mysql -e "DELETE FROM sessions WHERE expires_at < now()"',
      'grep -r "DROP TABLE" migrations/',
      'git commit -m "drop table users"',
    ],
  },
};

type CliMatch = (cmd: CommandContext) => string | null;

const hasAll = (args: string[], ...want: string[]) => want.every((w) => args.includes(w));

const DESTRUCTIVE_CLIS: CliMatch[] = [
  (c) => (c.program === "dropdb" ? "dropdb deletes a PostgreSQL database" : null),
  (c) => (c.program === "mysqladmin" && c.args.includes("drop") ? "mysqladmin drop deletes a database" : null),
  (c) => (c.program === "redis-cli" && c.args.some((a) => /^flush(all|db)$/i.test(a)) ? "FLUSHALL/FLUSHDB erases Redis data" : null),
  (c) => {
    const args = c.program === "npx" || c.program === "bunx" || c.program === "pnpx" ? c.args : c.program === "prisma" ? ["prisma", ...c.args] : null;
    if (!args) return null;
    if (hasAll(args, "prisma", "migrate", "reset")) return "prisma migrate reset drops the database";
    if (hasAll(args, "prisma", "db", "push") && (args.includes("--force-reset") || args.includes("--accept-data-loss"))) return "prisma db push with --force-reset/--accept-data-loss can delete data";
    return null;
  },
  (c) => {
    if (!["rails", "rake", "bin/rails", "bundle"].includes(c.program) && !c.program.endsWith("rails")) return null;
    const task = c.args.find((a) => /^db:(drop|reset|purge|schema:load)(:|$)/.test(a));
    return task ? `${task} deletes database data` : null;
  },
  (c) => (["python", "python3"].includes(c.program) && c.args[0]?.endsWith("manage.py") && (c.args.includes("flush") || c.args.includes("reset_db")) ? "manage.py flush deletes all data" : null),
  (c) => (c.program.endsWith("manage.py") && c.args.includes("flush") ? "manage.py flush deletes all data" : null),
  (c) => (c.program === "php" && c.args[0] === "artisan" && c.args.some((a) => /^(migrate:(fresh|reset|refresh)|db:wipe)$/.test(a)) ? "this artisan command drops tables" : null),
  (c) => (c.program === "supabase" && hasAll(c.args, "db", "reset") ? "supabase db reset recreates the database" : null),
];

export const destructiveDbCli: CommandRule = {
  kind: "command",
  id: "db.destructive-cli",
  decision: "ask",
  description: "Database reset and drop commands (dropdb, prisma migrate reset, rails db:drop, ...)",
  check(cmd) {
    for (const m of DESTRUCTIVE_CLIS) {
      const reason = m(cmd);
      if (reason) {
        const linked = cmd.args.includes("--linked") || cmd.args.some((a) => /prod/i.test(a));
        return {
          reason: `${reason[0]!.toUpperCase()}${reason.slice(1)}${linked ? " (and it looks like it targets a remote or production database)" : ""}.`,
          suggestion: "Confirm this is a disposable local database.",
        };
      }
    }
    return null;
  },
  examples: {
    flag: ["dropdb myapp", "npx prisma migrate reset --force", "bin/rails db:drop", "redis-cli FLUSHALL", "python manage.py flush --noinput", "php artisan migrate:fresh", "supabase db reset --linked"],
    pass: ["npx prisma migrate dev", "bin/rails db:migrate", "redis-cli GET key", "python manage.py migrate"],
  },
};

export const databaseRules = [destructiveSql, destructiveDbCli];
