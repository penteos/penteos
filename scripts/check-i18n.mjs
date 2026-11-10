#!/usr/bin/env node
/**
 * Keeps the interface bilingual and the Spanish neutral. Fails when:
 *   1. a key exists in one language and not in the other, or their {placeholders} differ;
 *   2. a screen shows text that is not in a catalog (JSX text, title/placeholder/aria-label, toasts);
 *   3. the Spanish catalogs use voseo ("tenés", "podés", "elegí"…).
 *
 *   node scripts/check-i18n.mjs            → everything
 *   node scripts/check-i18n.mjs src/panels/Board.tsx …   → only the hardcoded-text check for those files
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const root = new URL("../apps/desktop/src/", import.meta.url).pathname;
const only = process.argv.slice(2);
let problems = 0;
const fail = (msg) => {
  problems++;
  console.error(msg);
};

// --- 1. catalogs ----------------------------------------------------------------------------
function entries(file) {
  const out = new Map();
  for (const line of readFileSync(file, "utf8").split("\n")) {
    const m = /^\s*(?:"([^"]+)"|([A-Za-z_][\w]*))\s*:\s*("(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`)\s*,?\s*$/.exec(line);
    if (m) out.set(m[1] ?? m[2], m[3].slice(1, -1));
  }
  return out;
}
const placeholders = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(",");
const catalogs = { es: {}, en: {} };
for (const lang of ["es", "en"]) {
  for (const f of readdirSync(join(root, "i18n", lang))) catalogs[lang][f.replace(/\.ts$/, "")] = entries(join(root, "i18n", lang, f));
}
if (!only.length) {
  for (const ns of new Set([...Object.keys(catalogs.es), ...Object.keys(catalogs.en)])) {
    const es = catalogs.es[ns] ?? new Map();
    const en = catalogs.en[ns] ?? new Map();
    for (const [k, v] of es) {
      if (!en.has(k)) fail(`[keys] ${ns}.${k}: missing in English`);
      else if (placeholders(v) !== placeholders(en.get(k))) fail(`[keys] ${ns}.${k}: placeholders differ (es {${placeholders(v)}} / en {${placeholders(en.get(k))}})`);
    }
    for (const k of en.keys()) if (!es.has(k)) fail(`[keys] ${ns}.${k}: missing in Spanish`);
  }
  // --- 3. neutral Spanish --------------------------------------------------------------------
  const voseo = /\b(tenés|podés|querés|sabés|hacés|decís|elegí|escribí|mirá|fijate|pedile|decile|escribile|andá|vení|poné|tocá|probá|usá|cargá|revisá|confirmá|abrí|cerrá|agregá|creá|guardá|seguí|esperá|dejá|pasá|mandá|hacé|tené|volvé|corré|mové|leé|decí|salí|subí|pedí|vos)\b/i;
  // Beyond the list, the shapes of voseo: a sentence that starts with an imperative stressed on its
  // last vowel ("Armá", "Revisá…", "Elegí"), with or without a pronoun ("Pasale"); and the present
  // in -ás/-és/-ís ("necesitás", "podés", "decís"). Ordinary words with those endings are excepted.
  const NOT_VOSEO = new Set(["está", "están", "más", "además", "jamás", "atrás", "detrás", "demás", "allá", "acá", "ahí", "aquí", "allí", "así", "sí", "también", "después", "través", "interés", "inglés", "francés", "país", "maíz", "quizá", "quizás", "será", "habrá", "podrá", "tendrá", "hará", "dirá", "verá", "irá", "dará", "estará", "quedará", "faltará", "llegará", "aparecerá", "volverá", "pedirá", "seguirá", "correrá", "agregará", "hay", "mamá", "papá", "sofá", "café", "bebé", "menú", "algún", "según", "ningún", "aún", "jamás", "revés", "estrés", "mes", "res", "cortés", "portugués", "japonés", "holandés", "danés", "irlandés", "qué", "cachés", "escocés", "galés", "marqués", "ciprés", "anís", "parís", "lis", "gris", "tris", "bis"]);
  // Only -á: in -é/-í the voseo imperative and the first person past look the same ("revisé" is
  // fine, "hacé" is not); those come from the list above.
  const imperative = /(?:^|[.!?¿¡:\n]\s*|^\s*)([A-ZÁÉÍÓÚ][a-záéíóúñ]+á(?:le|les|lo|la|los|las|me|te|nos)?)(?=[\s,.!?:]|$)/g;
  const present = /\b([a-záéíóúñ]{3,}(?:ás|és|ís))\b/gi;
  for (const [ns, es] of Object.entries(catalogs.es)) {
    for (const [k, v] of es) {
      if (voseo.test(v)) {
        fail(`[voseo] es/${ns}.${k}: "${v}"`);
        continue;
      }
      const hits = [...v.matchAll(imperative), ...v.matchAll(present)].map((m) => m[1]).filter((w) => !NOT_VOSEO.has(w.toLowerCase()) && !/(ción|sión)$/i.test(w));
      if (hits.length) fail(`[voseo] es/${ns}.${k}: "${hits.join(", ")}" in "${v}"`);
    }
  }
}

// --- 2. hardcoded text in screens ----------------------------------------------------------
function walk(dir) {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? (f === "i18n" ? [] : walk(p)) : /\.tsx$/.test(f) && !/icons\.tsx$/.test(f) ? [p] : [];
  });
}
// Text that may stay literal: product names, keyboard shortcuts, units, protocol words.
const allowed = /^(Penteos|Maestro|Ctrl\s?[A-Z`]|Ctrl\+.*|Shift\+.*|Enter|Esc|OK|CVSS.*|OWASP.*|WSTG|HTTP\/?\d?.*|WS|URL|IP|API|JSON|HAR|DOCX|PDF|HTML|Markdown|nmap|Burp|Caido|ZAP|ATT&CK|MITRE.*|[A-Z]{2,6}|[\d\s.,:/%·×→←↑↓\-+()#@*]+)$/;
const files = only.length ? only.map((f) => join(process.cwd(), f)) : walk(root);
for (const file of files) {
  const src = readFileSync(file, "utf8");
  const rel = relative(root, file);
  const hits = [];
  const lines = src.split("\n");
  lines.forEach((line, i) => {
    if (/^\s*(\/\/|\*|\/\*)/.test(line) || /i18n-ignore/.test(line)) return;
    for (const m of line.matchAll(/>([^<>{}]*[A-Za-zÁÉÍÓÚáéíóúñÑ]{2,}[^<>{}]*)</g)) {
      const text = m[1].trim();
      if (text && !allowed.test(text) && !/^[=&|!?:;)]/.test(text) && !/=>|&&|\|\||===/.test(m[0])) hits.push([i + 1, text]);
    }
    for (const m of line.matchAll(/\b(title|placeholder|aria-label|alt|label)=\"([^"]*[A-Za-zÁÉÍÓÚáéíóúñ]{3,}[^"]*)\"/g)) {
      if (!allowed.test(m[2])) hits.push([i + 1, `${m[1]}="${m[2]}"`]);
    }
    for (const m of line.matchAll(/\btoast\(\s*"(?:ok|bad|info|warn)"\s*,\s*("[^"]*[A-Za-zá-ú]{3,}[^"]*"|`[^`]*[A-Za-zá-ú]{3,}[^`]*`)/g)) hits.push([i + 1, `toast(${m[1]})`]);
  });
  for (const [n, text] of hits) fail(`[text] ${rel}:${n}: ${text}`);
}

if (problems) {
  console.error(`\n${problems} problem(s).`);
  process.exit(1);
}
console.log("i18n: catalogs match, no hardcoded text, no voseo.");
