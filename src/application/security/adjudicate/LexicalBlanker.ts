/**
 * LexicalBlanker
 * Language-aware comment, string literal, regex, and heredoc blanking pipeline.
 * Ensures guards cited by LLMs or scanners are executable code rather than comments or documentation.
 */

export interface BlankedSource {
  readonly blanked_code: string;
  readonly language: string;
}

/**
 * Normalizes an expression by stripping superfluous whitespace and standardizing comparison operators.
 */
export function normalizeGuardExpression(expr: string): string {
  return expr
    .trim()
    .replace(/\s+/g, " ")
    .replace(/\s*([<>!=]=?|[()+*/%-])\s*/g, "$1");
}

/**
 * Generates operator-reversed mirror variants (e.g., `x < y` mirror is `y > x`).
 */
export function getOperatorMirrors(expr: string): readonly string[] {
  const norm = normalizeGuardExpression(expr);
  const mirrors: string[] = [norm];

  // Match simple binary comparison: operand1 OP operand2
  const match = norm.match(/^([^<>!=]+)(<=|>=|<|>|==|!=)([^<>!=]+)$/);
  if (match) {
    const left = match[1]?.trim();
    const op = match[2];
    const right = match[3]?.trim();
    if (left && op && right) {
      let mirroredOp = op;
      if (op === "<") mirroredOp = ">";
      else if (op === ">") mirroredOp = "<";
      else if (op === "<=") mirroredOp = ">=";
      else if (op === ">=") mirroredOp = "<=";

      mirrors.push(`${right}${mirroredOp}${left}`);
    }
  }

  return mirrors;
}

/**
 * Blanks comments and string literals from source code to reveal executable tokens.
 */
export function blankSourceCode(source: string, language: string = "c"): string {
  const lang = language.toLowerCase();

  // Multi-pass blanking:
  // 1. Strings: "...", '...', `...`
  // 2. Comments: //..., /*...*/, #..., --...
  // 3. Regex: /.../ (for JS/TS)

  let result = source;

  // Block comments (C, C++, Java, JS, TS, Rust, Go)
  if (["c", "cpp", "c++", "java", "javascript", "js", "typescript", "ts", "rust", "go"].includes(lang)) {
    result = result.replace(/\/\*[\s\S]*?\*\//g, (match) => " ".repeat(match.length));
  }

  // Triple quotes (Python)
  if (["python", "py"].includes(lang)) {
    result = result.replace(/"""[\s\S]*?"""/g, (match) => " ".repeat(match.length));
    result = result.replace(/'''[\s\S]*?'''/g, (match) => " ".repeat(match.length));
  }

  // Double and single quoted strings
  // Handle escaped quotes inside strings
  result = result.replace(/"(?:\\.|[^"\\])*"/g, (match) => `"${" ".repeat(Math.max(0, match.length - 2))}"`);
  result = result.replace(/'(?:\\.|[^'\\])*'/g, (match) => `'${" ".repeat(Math.max(0, match.length - 2))}'`);

  // Template literals (JS, TS)
  if (["javascript", "js", "typescript", "ts"].includes(lang)) {
    result = result.replace(/`(?:\\.|[^`\\])*`/g, (match) => `\`${" ".repeat(Math.max(0, match.length - 2))}\``);
  }

  // Line comments
  if (["c", "cpp", "c++", "java", "javascript", "js", "typescript", "ts", "rust", "go"].includes(lang)) {
    result = result.replace(/\/\/.*$/gm, (match) => " ".repeat(match.length));
  }

  if (["python", "py", "shell", "sh", "bash", "ruby", "perl"].includes(lang)) {
    result = result.replace(/#.*$/gm, (match) => " ".repeat(match.length));
  }

  if (["sql", "lua"].includes(lang)) {
    result = result.replace(/--.*$/gm, (match) => " ".repeat(match.length));
  }

  return result;
}

/**
 * Verifies whether a claimed guard expression physically exists in the executable portion of source code.
 */
export function guardExistsInExecutableSource(
  source: string,
  guardExpression: string,
  language: string = "c",
): { exists: boolean; matched_line?: number; matched_variant?: string } {
  if (!guardExpression || !source) {
    return { exists: false };
  }

  const blanked = blankSourceCode(source, language);
  const variants = getOperatorMirrors(guardExpression);
  const lines = blanked.split("\n");

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const rawLine = lines[lineIdx];
    if (!rawLine) continue;
    const normLine = normalizeGuardExpression(rawLine);

    for (const variant of variants) {
      if (normLine.includes(variant)) {
        return {
          exists: true,
          matched_line: lineIdx + 1,
          matched_variant: variant,
        };
      }
    }
  }

  return { exists: false };
}

