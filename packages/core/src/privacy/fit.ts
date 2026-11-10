/**
 * Fitting a result to what a model can read. A blind cut at N
 * characters drops whatever came after it: the second half of a list, the closing fields of a
 * record. Instead the result is shrunk by its structure - long lists keep their first items plus
 * how many there were and which fields they have, long texts keep their beginning and end - until
 * it fits. The agent sees the whole shape and knows exactly what was left out and where to read it.
 */

export interface FitInfo {
  /** Whether anything had to be shortened. */
  shrunk: boolean;
  /** Items left out of lists, characters left out of texts. */
  omittedItems: number;
  omittedChars: number;
}

/** A list's summary: how many items, and which fields they carry (with how many have each). */
function fieldsOf(items: unknown[]): Record<string, number> | undefined {
  const counts: Record<string, number> = {};
  let objects = 0;
  for (const it of items) {
    if (!it || typeof it !== "object" || Array.isArray(it)) continue;
    objects++;
    for (const k of Object.keys(it)) counts[k] = (counts[k] ?? 0) + 1;
  }
  return objects ? counts : undefined;
}

function shrink(v: unknown, maxItems: number, maxChars: number, info: FitInfo): unknown {
  if (typeof v === "string") {
    if (v.length <= maxChars) return v;
    const head = Math.ceil(maxChars * 0.75);
    const tail = maxChars - head;
    info.shrunk = true;
    info.omittedChars += v.length - maxChars;
    return `${v.slice(0, head)}\n… [${v.length - maxChars} of ${v.length} characters omitted here] …\n${v.slice(v.length - tail)}`;
  }
  if (Array.isArray(v)) {
    const kept = v.slice(0, maxItems).map((x) => shrink(x, maxItems, maxChars, info));
    if (v.length <= maxItems) return kept;
    info.shrunk = true;
    info.omittedItems += v.length - maxItems;
    const fields = fieldsOf(v);
    return [...kept, { "…": `${v.length - maxItems} more of ${v.length} items not shown`, ...(fields ? { fieldsAcrossAllItems: fields } : {}) }];
  }
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, shrink(x, maxItems, maxChars, info)]));
  return v;
}

const STEPS: Array<[number, number]> = [
  [50, 6000],
  [25, 3000],
  [12, 1500],
  [6, 800],
  [3, 400],
  [2, 200],
];

/**
 * The value as JSON text within `budget` characters, shrunk by structure if it has to be. The
 * note says what was left out and where the full data is.
 */
export function fitForModel(value: unknown, budget: number, where?: string): { text: string; info: FitInfo } {
  const full = JSON.stringify(value, null, 1);
  if (full.length <= budget) return { text: full, info: { shrunk: false, omittedItems: 0, omittedChars: 0 } };
  for (const [items, chars] of STEPS) {
    const info: FitInfo = { shrunk: false, omittedItems: 0, omittedChars: 0 };
    const text = JSON.stringify(shrink(value, items, chars, info), null, 1);
    if (text.length <= budget - 400) {
      const note = `[Penteos: this result was ${full.length} characters; it was shortened by structure to fit (${info.omittedItems ? `${info.omittedItems} list items` : ""}${info.omittedItems && info.omittedChars ? " and " : ""}${info.omittedChars ? `${info.omittedChars} characters of long texts` : ""} left out, marked where). Every list keeps its total and the fields of all its items.${where ? ` The complete data: ${where}.` : ""}]`;
      return { text: `${text}\n${note}`, info };
    }
  }
  // Nothing structural left to shrink (one huge flat value): cut, saying so.
  const info: FitInfo = { shrunk: true, omittedItems: 0, omittedChars: full.length - budget };
  return { text: `${full.slice(0, budget - 300)}\n… [Penteos: cut at ${budget} of ${full.length} characters.${where ? ` The complete data: ${where}.` : ""}]`, info };
}
