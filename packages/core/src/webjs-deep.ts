/**
 * The whole of a web application's JavaScript, not only what its first page loads: modern bundlers
 * (Next.js, Vite, webpack) split the code into chunks requested later, so most of it - admin
 * screens, server actions, configuration - is never in the HTML. These are the pure parts: which
 * other scripts a script names, its source map, and what the code reveals beyond endpoints. The
 * runner fetches (in scope, through the proxy, politely) and keeps every file in the project.
 */

/** Other scripts a script (or the page) names: chunks, dynamic imports, Next.js manifests. */
export function jsReferences(code: string, baseUrl: string): string[] {
  const out = new Set<string>();
  const add = (raw: string, base = baseUrl) => {
    try {
      const u = new URL(raw, base);
      if (/^https?:$/.test(u.protocol) && /\.m?js$/i.test(u.pathname)) out.add(u.href);
    } catch {
      /* not a URL */
    }
  };
  const origin = (() => {
    try {
      return new URL(baseUrl).origin;
    } catch {
      return "";
    }
  })();
  // Next.js: chunks named from anywhere (manifests, the RSC payload in the HTML, the runtime).
  for (const m of code.matchAll(/(?:\/_next\/)?(static\/(?:chunks|[A-Za-z0-9_-]{6,})\/[A-Za-z0-9_\-./@\[\]%()~]+?\.js)\b/g)) add(`/_next/${m[1]}`, origin);
  // Quoted script paths: import("./x.js"), "assets/index-abc.js", "/static/js/main.js".
  for (const m of code.matchAll(/["'`]((?:\.{1,2}\/|\/)?[A-Za-z0-9_\-./@~]+\.m?js)(?:\?[^"'`]*)?["'`]/g)) {
    const p = m[1]!;
    if (p.includes("node_modules") || /^[a-z]+\.m?js$/i.test(p)) continue; // package entry names, not files of this site
    if (/^(?:\/?_next\/)?static\//.test(p)) continue; // Next.js chunk names: the rule above places them
    add(p);
  }
  // A Next.js build manifest names every page's chunks: ask for it once the build id is known.
  const buildId = /"buildId"\s*:\s*"([A-Za-z0-9_-]{6,})"/.exec(code)?.[1] ?? /\/_next\/static\/([A-Za-z0-9_-]{6,})\/_(?:buildManifest|ssgManifest)\.js/.exec(code)?.[1];
  if (buildId && origin) {
    add(`/_next/static/${buildId}/_buildManifest.js`, origin);
    add(`/_next/static/${buildId}/_ssgManifest.js`, origin);
  }
  return [...out];
}

/** Where a script's source map is: its comment, its response header, or undefined. */
export function sourceMapUrl(code: string, headers: Array<[string, string]>, scriptUrl: string): string | undefined {
  const fromHeader = headers.find(([k]) => /^(x-)?sourcemap$/i.test(k))?.[1];
  const fromComment = [...code.matchAll(/\/\/[#@]\s*sourceMappingURL=([^\s"'`]+)/g)].pop()?.[1];
  const ref = fromHeader ?? fromComment;
  if (!ref || ref.startsWith("data:")) return undefined;
  try {
    return new URL(ref, scriptUrl).href;
  } catch {
    return undefined;
  }
}

export interface RecoveredSource {
  /** The original file's path, made safe to write under the project (no "..", no scheme). */
  path: string;
  content: string;
}

/** A source map's original files (only those whose content it carries). */
export function recoverSources(mapText: string): RecoveredSource[] | undefined {
  let map: { sources?: unknown; sourcesContent?: unknown; sections?: unknown };
  try {
    map = JSON.parse(mapText);
  } catch {
    return undefined;
  }
  const out: RecoveredSource[] = [];
  const take = (m: { sources?: unknown; sourcesContent?: unknown }) => {
    if (!Array.isArray(m.sources) || !Array.isArray(m.sourcesContent)) return;
    m.sources.forEach((src, i) => {
      const content = (m.sourcesContent as unknown[])[i];
      if (typeof src !== "string" || typeof content !== "string" || !content) return;
      out.push({ path: safeSourcePath(src), content });
    });
  };
  take(map);
  // Index maps (sections), as some bundlers write them.
  if (Array.isArray(map.sections)) for (const s of map.sections as Array<{ map?: { sources?: unknown; sourcesContent?: unknown } }>) if (s.map) take(s.map);
  return out.length || Array.isArray(map.sources) ? out : undefined;
}

/** "webpack://app/./src/../lib/x.ts" → "app/src/lib/x.ts": inside the project folder, always. */
export function safeSourcePath(src: string): string {
  const parts = src
    .replace(/^[a-z][a-z0-9+.-]*:\/\/+/i, "")
    .replace(/[?#].*$/, "")
    .split(/[\\/]+/)
    .filter((p) => p && p !== "." && p !== "..")
    .map((p) => p.replace(/[^A-Za-z0-9._@()[\]+-]/g, "_").slice(0, 120));
  return parts.join("/").slice(0, 400) || "unnamed";
}

export interface DeepSignals {
  /** Configuration the client ships: an error tracker's DSN, a backend's public URL, a bucket. */
  config: Array<{ kind: string; value: string }>;
  /** Environment variable names the build inlined (NEXT_PUBLIC_*, VITE_*, process.env.*). */
  configNames: string[];
  /** Addresses of internal networks named in the code. */
  internalAddresses: string[];
  /** window "message" listeners, and whether the code checks the sender's origin near them. */
  messageListeners: Array<{ file: string; checksOrigin: boolean }>;
  /** Places HTML or code is built from data (XSS sinks). */
  sinks: Array<{ kind: string; file: string }>;
  /** Parameters that carry where to go next (open redirect candidates). */
  redirectParams: string[];
  /** Fields the browser computes and sends that a server might trust (IP, time zone, device…). */
  clientFields: string[];
  /** Next.js server actions: their ids (and names, when the build keeps them). */
  serverActions: Array<{ id: string; name?: string; file: string }>;
}

export const emptySignals = (): DeepSignals => ({ config: [], configNames: [], internalAddresses: [], messageListeners: [], sinks: [], redirectParams: [], clientFields: [], serverActions: [] });

const CONFIG_RULES: Array<{ kind: string; re: RegExp }> = [
  { kind: "Sentry DSN", re: /https:\/\/[0-9a-f]{32}@[a-z0-9.-]*sentry\.io\/\d+/gi },
  { kind: "Supabase project", re: /https:\/\/[a-z0-9]{20}\.supabase\.co\b/gi },
  { kind: "Firebase project", re: /\b[a-z0-9-]+\.firebaseio\.com\b|\b[a-z0-9-]+\.firebaseapp\.com\b/gi },
  { kind: "S3 bucket", re: /\b[a-z0-9][a-z0-9.-]{2,62}\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com\b|\bs3[.-](?:[a-z0-9-]+\.)?amazonaws\.com\/[a-z0-9][a-z0-9.-]{2,62}\b/gi },
  { kind: "Google Cloud Storage bucket", re: /\bstorage\.googleapis\.com\/[a-z0-9][a-z0-9._-]{2,62}\b/gi },
  { kind: "Azure storage", re: /\b[a-z0-9]{3,24}\.blob\.core\.windows\.net\b/gi },
  { kind: "Mapbox token", re: /\bpk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b/g },
  { kind: "Algolia app", re: /\b(?:appId|applicationId)\s*[:=]\s*["'][A-Z0-9]{10}["']/g },
];
const INTERNAL = /\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b(?::\d{2,5})?/g;
/** Names that only mean "where to go next" (anywhere they appear: a key, a property, a parameter). */
const REDIRECT_NAMES = /\b(redirect(?:_?ur[il]|_?to|_?path)?|return(?:_?ur[il]|_?to|_?path)|callback_?ur[il]|next_?ur[il]|goto|redirect_uri)\b/gi;
/** Common words that mean it only as a URL parameter: ?next=, &url=, ?dest=. */
const REDIRECT_PARAMS = /[?&](next|continue|dest(?:ination)?|target|back|url|to|r|u)=/gi;
const CLIENT_FIELDS = /["'`]?\b(ip(?:_?address)?|client_?ip|public_?ip|time_?zone|timezone|tz|fingerprint|device_?id|device_?fingerprint|geo(?:location)?|latitude|longitude|user_?agent|risk_?score|is_?bot)\b["'`]?\s*:/gi;

/** What the code reveals beyond endpoints. `file` names it in the project's copy. */
export function deepSignals(code: string, file: string): DeepSignals {
  const s = emptySignals();
  const vendored = /(^|\/)node_modules\//.test(file);
  for (const { kind, re } of CONFIG_RULES) for (const m of code.matchAll(re)) if (s.config.length < 100) s.config.push({ kind, value: m[0] });
  for (const m of code.matchAll(/\b((?:NEXT_PUBLIC|VITE|REACT_APP|NUXT_PUBLIC|PUBLIC)_[A-Z0-9_]{2,60})\b/g)) if (!s.configNames.includes(m[1]!)) s.configNames.push(m[1]!);
  for (const m of code.matchAll(/\bprocess\.env\.([A-Z][A-Z0-9_]{2,60})\b/g)) if (!s.configNames.includes(m[1]!)) s.configNames.push(m[1]!);
  for (const m of code.matchAll(INTERNAL)) if (!s.internalAddresses.includes(m[0]) && s.internalAddresses.length < 50) s.internalAddresses.push(m[0]);
  // Server actions (Next.js): createServerReference("<id>", callServer, …, "<name>").
  for (const m of code.matchAll(/createServerReference\)?\(\s*["']([0-9a-f]{40,42})["'](?:[^)]{0,200}?,\s*["']([A-Za-z_$][\w$]{0,80})["']\s*\))?/g)) {
    if (!s.serverActions.some((a) => a.id === m[1])) s.serverActions.push({ id: m[1]!, ...(m[2] ? { name: m[2] } : {}), file });
  }
  // Vendored code is the libraries': its listeners, sinks and field names are not the application's.
  if (vendored) return s;
  for (const m of code.matchAll(/addEventListener\(\s*["'`]message["'`]/g)) {
    const around = code.slice(m.index!, m.index! + 600);
    s.messageListeners.push({ file, checksOrigin: /\.origin\b/.test(around) });
  }
  for (const [kind, re] of [
    ["innerHTML", /\.(?:inner|outer)HTML\s*=(?!=)/g],
    ["dangerouslySetInnerHTML", /dangerouslySetInnerHTML/g],
    ["document.write", /document\.write(?:ln)?\(/g],
    ["eval", /(?<![\w$.])eval\(/g],
    ["new Function", /new Function\(/g],
    ["insertAdjacentHTML", /insertAdjacentHTML\(/g],
  ] as const) {
    if (re.test(code)) s.sinks.push({ kind, file });
  }
  for (const re of [REDIRECT_NAMES, REDIRECT_PARAMS]) {
    for (const m of code.matchAll(re)) {
      const n = m[1]!.toLowerCase();
      if (!s.redirectParams.includes(n)) s.redirectParams.push(n);
    }
  }
  for (const m of code.matchAll(CLIENT_FIELDS)) {
    const n = m[1]!.toLowerCase();
    if (!s.clientFields.includes(n)) s.clientFields.push(n);
  }
  return s;
}

export function mergeSignals(parts: DeepSignals[]): DeepSignals {
  const out = emptySignals();
  const uniq = <T>(arr: T[], key: (x: T) => string, limit: number) => {
    const seen = new Set<string>();
    return arr.filter((x) => (seen.has(key(x)) ? false : (seen.add(key(x)), true))).slice(0, limit);
  };
  for (const p of parts) {
    out.config.push(...p.config);
    out.configNames.push(...p.configNames);
    out.internalAddresses.push(...p.internalAddresses);
    out.messageListeners.push(...p.messageListeners);
    out.sinks.push(...p.sinks);
    out.redirectParams.push(...p.redirectParams);
    out.clientFields.push(...p.clientFields);
    out.serverActions.push(...p.serverActions);
  }
  return {
    config: uniq(out.config, (x) => `${x.kind}:${x.value}`, 100),
    configNames: uniq(out.configNames, (x) => x, 200),
    internalAddresses: uniq(out.internalAddresses, (x) => x, 50),
    messageListeners: uniq(out.messageListeners, (x) => `${x.file}:${x.checksOrigin}`, 50),
    sinks: uniq(out.sinks, (x) => `${x.kind}:${x.file}`, 100),
    redirectParams: uniq(out.redirectParams, (x) => x, 30),
    clientFields: uniq(out.clientFields, (x) => x, 30),
    serverActions: uniq(out.serverActions, (x) => x.id, 500),
  };
}
