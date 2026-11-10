/**
 * A unified diff of two texts, line by line (for the operator to review what changed in a plugin's
 * code before approving a new version). Small on purpose: longest common subsequence over lines,
 * with a ceiling; past it, the file is shown as replaced.
 */

const MAX_CELLS = 4_000_000;

export function unifiedDiff(path: string, before: string | undefined, after: string | undefined, context = 3): string {
  const a = before === undefined ? [] : before.replace(/\r\n/g, "\n").split("\n");
  const b = after === undefined ? [] : after.replace(/\r\n/g, "\n").split("\n");
  const head = `--- ${before === undefined ? "/dev/null" : `a/${path}`}\n+++ ${after === undefined ? "/dev/null" : `b/${path}`}\n`;
  if (before === after) return "";
  const ops = a.length * b.length > MAX_CELLS ? [...a.map((l) => ["-", l] as const), ...b.map((l) => ["+", l] as const)] : lcsOps(a, b);
  // Hunks: changed lines with `context` lines around them.
  const out: string[] = [];
  let i = 0;
  let aLine = 1;
  let bLine = 1;
  const positions = ops.map((op) => {
    const p = { op, a: aLine, b: bLine };
    if (op[0] !== "+") aLine++;
    if (op[0] !== "-") bLine++;
    return p;
  });
  while (i < positions.length) {
    if (positions[i]!.op[0] === " ") {
      i++;
      continue;
    }
    const start = Math.max(0, i - context);
    let end = i;
    // Extend while the next change is within 2×context lines.
    for (let j = i; j < positions.length; j++) {
      if (positions[j]!.op[0] !== " ") end = j;
      else if (j - end > context * 2) break;
    }
    const stop = Math.min(positions.length, end + context + 1);
    const slice = positions.slice(start, stop);
    const aCount = slice.filter((p) => p.op[0] !== "+").length;
    const bCount = slice.filter((p) => p.op[0] !== "-").length;
    out.push(`@@ -${slice[0]!.a},${aCount} +${slice[0]!.b},${bCount} @@`);
    for (const p of slice) out.push(`${p.op[0]}${p.op[1]}`);
    i = stop;
  }
  return head + out.join("\n") + "\n";
}

function lcsOps(a: string[], b: string[]): Array<readonly [" " | "-" | "+", string]> {
  const n = a.length;
  const m = b.length;
  // Lengths of the common subsequence of a[i..] and b[j..].
  const len = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) len[i]![j] = a[i] === b[j] ? len[i + 1]![j + 1]! + 1 : Math.max(len[i + 1]![j]!, len[i]![j + 1]!);
  const ops: Array<readonly [" " | "-" | "+", string]> = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      ops.push([" ", a[i]!]);
      i++;
      j++;
    } else if (len[i + 1]![j]! >= len[i]![j + 1]!) ops.push(["-", a[i++]!]);
    else ops.push(["+", b[j++]!]);
  }
  while (i < n) ops.push(["-", a[i++]!]);
  while (j < m) ops.push(["+", b[j++]!]);
  return ops;
}
