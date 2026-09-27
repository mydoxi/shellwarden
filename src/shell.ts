/**
 * A small, forgiving shell parser.
 *
 * It does not try to be a full POSIX implementation. Its job is to split a
 * command line into the simple commands that will actually run (so that
 * `ls && rm -rf /` is seen as two commands), strip quoting, record
 * redirections and heredoc bodies, and surface the contents of command
 * substitutions so they can be inspected too.
 */

export interface Redirect {
  op: string;
  target: string;
}

export interface SimpleCommand {
  /** Words after quote removal. */
  argv: string[];
  redirects: Redirect[];
  /** Heredoc and here-string bodies fed to this command's stdin. */
  heredocs: string[];
  /** The raw source text of this command. */
  text: string;
}

export interface Pipeline {
  commands: SimpleCommand[];
}

const MAX_DEPTH = 8;

interface PendingHeredoc {
  delim: string;
  stripTabs: boolean;
  into: string[];
}

/**
 * Parse a command line into pipelines. Pipelines found inside command and
 * process substitutions (`$(...)`, backticks, `<(...)`) are appended after the
 * top-level ones.
 */
export function parseShell(input: string, depth = 0): Pipeline[] {
  return new Parser(input, depth).run();
}

/**
 * Read heredoc bodies starting at `pos` (the first character after the
 * newline that ends the command). Returns the bodies and the position just
 * past the last delimiter line.
 */
function readHeredocBodies(
  src: string,
  pos: number,
  pending: { delim: string; stripTabs: boolean }[],
): { bodies: string[]; end: number } {
  const bodies: string[] = [];
  let p = pos;
  for (const h of pending) {
    const lines: string[] = [];
    while (p < src.length) {
      const nl = src.indexOf("\n", p);
      const lineEnd = nl === -1 ? src.length : nl;
      let line = src.slice(p, lineEnd);
      p = nl === -1 ? src.length : nl + 1;
      if (h.stripTabs) line = line.replace(/^\t+/, "");
      if (line === h.delim) break;
      lines.push(line);
    }
    bodies.push(lines.join("\n"));
  }
  return { bodies, end: p };
}

/** Skip a double-quoted string starting at `start` (the opening quote). */
function skipDouble(src: string, start: number): number {
  let j = start + 1;
  while (j < src.length) {
    const ch = src[j];
    if (ch === "\\") {
      j += 2;
      continue;
    }
    if (ch === '"') return j + 1;
    j++;
  }
  return src.length;
}

/** Read a heredoc delimiter word starting at `k`; quotes are removed. */
function readDelimiter(src: string, k: number): { delim: string; end: number } {
  let j = k;
  while (src[j] === " " || src[j] === "\t") j++;
  let delim = "";
  while (j < src.length) {
    const ch = src[j]!;
    if (ch === "'" || ch === '"') {
      const close = src.indexOf(ch, j + 1);
      const e = close === -1 ? src.length : close;
      delim += src.slice(j + 1, e);
      j = e + 1;
      continue;
    }
    if (ch === "\\") {
      delim += src[j + 1] ?? "";
      j += 2;
      continue;
    }
    if (/[\s;|&<>()]/.test(ch)) break;
    delim += ch;
    j++;
  }
  return { delim, end: j };
}

/**
 * Given the index just after an opening `(`, return the index of the matching
 * `)`. Quotes and heredoc bodies are skipped so that apostrophes in, say, a
 * commit message do not confuse the matcher.
 */
function findClosingParen(src: string, start: number): number {
  let depth = 1;
  let j = start;
  const pending: { delim: string; stripTabs: boolean }[] = [];
  while (j < src.length) {
    const ch = src[j];
    if (ch === "\\") {
      j += 2;
      continue;
    }
    if (ch === "'") {
      const e = src.indexOf("'", j + 1);
      j = e === -1 ? src.length : e + 1;
      continue;
    }
    if (ch === '"') {
      j = skipDouble(src, j);
      continue;
    }
    if (ch === "<" && src[j + 1] === "<" && src[j + 2] !== "<") {
      let k = j + 2;
      const stripTabs = src[k] === "-";
      if (stripTabs) k++;
      const { delim, end } = readDelimiter(src, k);
      if (delim) pending.push({ delim, stripTabs });
      j = end;
      continue;
    }
    if (ch === "\n" && pending.length > 0) {
      j = readHeredocBodies(src, j + 1, pending).end;
      pending.length = 0;
      continue;
    }
    if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) return j;
    }
    j++;
  }
  return src.length;
}

function findClosingBacktick(src: string, start: number): number {
  let j = start;
  while (j < src.length) {
    if (src[j] === "\\") {
      j += 2;
      continue;
    }
    if (src[j] === "`") return j;
    j++;
  }
  return src.length;
}

function findClosingBrace(src: string, start: number): number {
  let depth = 1;
  let j = start;
  while (j < src.length) {
    const ch = src[j];
    if (ch === "\\") {
      j += 2;
      continue;
    }
    if (ch === "'") {
      const e = src.indexOf("'", j + 1);
      j = e === -1 ? src.length : e + 1;
      continue;
    }
    if (ch === '"') {
      j = skipDouble(src, j);
      continue;
    }
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return j;
    }
    j++;
  }
  return src.length;
}

function newCommand(): SimpleCommand {
  return { argv: [], redirects: [], heredocs: [], text: "" };
}

class Parser {
  private i = 0;
  private readonly pipelines: Pipeline[] = [];
  private current: SimpleCommand[] = [];
  private cmd = newCommand();
  private cmdStart = 0;
  private word = "";
  private wordStarted = false;
  private pendingRedirect: string | null = null;
  private pendingHeredocs: PendingHeredoc[] = [];
  private readonly nested: string[] = [];

  constructor(
    private readonly src: string,
    private readonly depth: number,
  ) {}

  run(): Pipeline[] {
    const s = this.src;
    while (this.i < s.length) {
      const c = s[this.i]!;
      const next = s[this.i + 1];

      if (c === " " || c === "\t" || c === "\r") {
        this.endWord();
        this.i++;
        continue;
      }
      if (c === "\\") {
        if (next === "\n") {
          this.i += 2;
          continue;
        }
        if (next !== undefined) this.append(next);
        this.i += 2;
        continue;
      }
      if (c === "'") {
        const end = s.indexOf("'", this.i + 1);
        const e = end === -1 ? s.length : end;
        this.append(s.slice(this.i + 1, e));
        this.i = e + 1;
        continue;
      }
      if (c === '"') {
        this.readDoubleQuoted();
        continue;
      }
      if (c === "$" && next === "'") {
        this.readAnsiC();
        continue;
      }
      if (c === "$" && next === "(") {
        this.readSubstitution(this.i, this.i + 2);
        continue;
      }
      if (c === "$" && next === "{") {
        const end = findClosingBrace(s, this.i + 2);
        this.append(s.slice(this.i, end + 1));
        this.i = end + 1;
        continue;
      }
      if (c === "`") {
        const end = findClosingBacktick(s, this.i + 1);
        this.nested.push(s.slice(this.i + 1, end));
        this.append(s.slice(this.i, end + 1));
        this.i = end + 1;
        continue;
      }
      if ((c === "<" || c === ">") && next === "(" && !this.wordStarted) {
        this.readSubstitution(this.i, this.i + 2);
        continue;
      }
      if (c === "#" && !this.wordStarted) {
        const nl = s.indexOf("\n", this.i);
        this.i = nl === -1 ? s.length : nl;
        continue;
      }
      if (c === "<" || c === ">") {
        this.readRedirect();
        continue;
      }
      if (c === "&" && next === ">") {
        this.endWord();
        const op = s[this.i + 2] === ">" ? "&>>" : "&>";
        this.i += op.length;
        this.pendingRedirect = op;
        continue;
      }
      if (c === "\n") {
        this.endPipeline();
        this.i++;
        if (this.pendingHeredocs.length > 0) {
          const { bodies, end } = readHeredocBodies(s, this.i, this.pendingHeredocs);
          this.pendingHeredocs.forEach((h, idx) => h.into.push(bodies[idx] ?? ""));
          this.pendingHeredocs = [];
          this.i = end;
        }
        this.cmdStart = this.i;
        continue;
      }
      if (c === ";") {
        this.endPipeline();
        this.i += next === ";" ? 2 : 1;
        this.cmdStart = this.i;
        continue;
      }
      if (c === "&") {
        this.endPipeline();
        this.i += next === "&" ? 2 : 1;
        this.cmdStart = this.i;
        continue;
      }
      if (c === "|") {
        if (next === "|") {
          this.endPipeline();
          this.i += 2;
        } else {
          this.endCommand();
          this.i += next === "&" ? 2 : 1;
        }
        this.cmdStart = this.i;
        continue;
      }
      if (c === "(" || c === ")") {
        this.endPipeline();
        this.i++;
        this.cmdStart = this.i;
        continue;
      }
      this.append(c);
      this.i++;
    }
    this.endPipeline();
    // Unterminated heredocs at end of input: nothing more to read.
    for (const h of this.pendingHeredocs) h.into.push("");

    if (this.depth < MAX_DEPTH) {
      for (const inner of this.nested) {
        this.pipelines.push(...parseShell(inner, this.depth + 1));
      }
    }
    return this.pipelines;
  }

  private append(text: string): void {
    this.word += text;
    this.wordStarted = true;
  }

  private readDoubleQuoted(): void {
    const s = this.src;
    let j = this.i + 1;
    let out = "";
    while (j < s.length) {
      const ch = s[j]!;
      if (ch === '"') break;
      if (ch === "\\") {
        const n = s[j + 1];
        if (n !== undefined && '"\\$`\n'.includes(n)) {
          if (n !== "\n") out += n;
          j += 2;
          continue;
        }
        out += ch;
        j++;
        continue;
      }
      if (ch === "$" && s[j + 1] === "(") {
        const end = findClosingParen(s, j + 2);
        this.nested.push(s.slice(j + 2, end));
        out += s.slice(j, end + 1);
        j = end + 1;
        continue;
      }
      if (ch === "`") {
        const end = findClosingBacktick(s, j + 1);
        this.nested.push(s.slice(j + 1, end));
        out += s.slice(j, end + 1);
        j = end + 1;
        continue;
      }
      out += ch;
      j++;
    }
    this.append(out);
    this.i = j + 1;
  }

  private readAnsiC(): void {
    const s = this.src;
    let j = this.i + 2;
    let out = "";
    const escapes: Record<string, string> = { n: "\n", t: "\t", r: "\r", "'": "'", "\\": "\\", '"': '"' };
    while (j < s.length && s[j] !== "'") {
      if (s[j] === "\\" && j + 1 < s.length) {
        const n = s[j + 1]!;
        out += escapes[n] ?? n;
        j += 2;
        continue;
      }
      out += s[j];
      j++;
    }
    this.append(out);
    this.i = j + 1;
  }

  /** `$(...)`, `<(...)` or `>(...)`: record the inner text for recursive parsing. */
  private readSubstitution(start: number, innerStart: number): void {
    const end = findClosingParen(this.src, innerStart);
    this.nested.push(this.src.slice(innerStart, end));
    this.append(this.src.slice(start, end + 1));
    this.i = end + 1;
  }

  private readRedirect(): void {
    const s = this.src;
    if (this.wordStarted && /^\d+$/.test(this.word)) {
      // File descriptor prefix such as `2>`.
      this.word = "";
      this.wordStarted = false;
    } else {
      this.endWord();
    }
    let op: string;
    const rest = s.slice(this.i, this.i + 3);
    if (rest.startsWith("<<<")) op = "<<<";
    else if (rest.startsWith("<<-")) op = "<<-";
    else if (rest.startsWith("<<")) op = "<<";
    else if (rest.startsWith("<>")) op = "<>";
    else if (rest.startsWith("<&")) op = "<&";
    else if (rest.startsWith(">>")) op = ">>";
    else if (rest.startsWith(">|")) op = ">|";
    else if (rest.startsWith(">&")) op = ">&";
    else op = s[this.i]!;
    this.i += op.length;

    if (op.endsWith("&")) {
      // `2>&1` or `>&-` duplicate a descriptor and take no file target.
      let j = this.i;
      while (s[j] === " ") j++;
      const m = /^(\d+|-)(?![\w.\/])/.exec(s.slice(j));
      if (m) {
        this.i = j + m[0].length;
        return;
      }
    }
    this.pendingRedirect = op;
  }

  private endWord(): void {
    if (!this.wordStarted) return;
    const word = this.word;
    this.word = "";
    this.wordStarted = false;
    const op = this.pendingRedirect;
    if (op === null) {
      this.cmd.argv.push(word);
      return;
    }
    this.pendingRedirect = null;
    if (op === "<<" || op === "<<-") {
      this.pendingHeredocs.push({ delim: word, stripTabs: op === "<<-", into: this.cmd.heredocs });
    } else if (op === "<<<") {
      this.cmd.heredocs.push(word);
    } else {
      this.cmd.redirects.push({ op, target: word });
    }
  }

  private endCommand(): void {
    this.endWord();
    this.pendingRedirect = null;
    const c = this.cmd;
    if (c.argv.length > 0 || c.redirects.length > 0 || c.heredocs.length > 0) {
      c.text = this.src.slice(this.cmdStart, this.i).trim();
      this.current.push(c);
    }
    this.cmd = newCommand();
    this.cmdStart = this.i;
  }

  private endPipeline(): void {
    this.endCommand();
    if (this.current.length > 0) this.pipelines.push({ commands: this.current });
    this.current = [];
  }
}
