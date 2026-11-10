/**
 * Pulls what a web application leaks in its own JavaScript: the endpoints it
 * calls, the hosts of other environments it names, the routes of its admin panel, and credentials
 * left in the code. A single-page app ships its whole API surface in its bundles, so this is often
 * where a web pentest really starts. Everything here is pure text analysis of already-fetched
 * scripts; fetching them goes through scope and the proxy like any other request.
 */

/** A path the app calls, e.g. "/api/tenants/public/{slug}". */
export interface JsEndpoint {
  path: string;
  /** The absolute origin it is called on, when the code names one (another host, an env URL). */
  origin?: string;
}

/** A credential-looking string found in the code, with why it matched. */
export interface JsSecret {
  kind: string;
  value: string;
}

export interface JsHarvest {
  endpoints: JsEndpoint[];
  /** Absolute hosts named in the code (other environments, internal APIs, third parties). */
  hosts: string[];
  /** SPA route templates, e.g. "/admin/users/:id". */
  routes: string[];
  secrets: JsSecret[];
  /** Source map URLs referenced, which would expose the original source. */
  sourceMaps: string[];
  /**
   * Where the app's API lives, as the code names it: absolute ("https://api.example.com/api", from a
   * URL or a baseURL setting) or relative to the page ("/api/v1"). Relative calls in the code go there.
   */
  apiBases: string[];
}

const MAX = 4000; // per category, so a huge bundle cannot flood the graph

// High-signal credential patterns only: each is specific enough that a match is worth a human
// look. Generic "token"/"key" words are deliberately left out to avoid drowning real ones in noise.
const SECRET_RULES: Array<{ kind: string; re: RegExp }> = [
  { kind: "AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { kind: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { kind: "Stripe live key", re: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/g },
  { kind: "GitHub token", re: /\bgh[pousr]_[0-9A-Za-z]{30,}\b/g },
  { kind: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { kind: "Private key block", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
  { kind: "JWT", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  // An assignment of a secret-looking name to a long literal, e.g. apiKey: "abcd…".
  { kind: "hardcoded secret", re: /\b(?:api[_-]?key|secret|passwd|password|auth[_-]?token|access[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*["'`]([0-9A-Za-z_\-./+]{16,})["'`]/gi },
];

/** Hosts that are never worth reporting (CDNs, analytics, fonts, the standards). */
const BORING_HOST = /(^|\.)(w3\.org|schema\.org|googleapis\.com|gstatic\.com|google-analytics\.com|googletagmanager\.com|cloudflare\.com|jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|fontawesome\.com|sentry\.io|gravatar\.com|github\.com|npmjs\.com|mozilla\.org|example\.com)$/i;

/** A path that is an API's root rather than a route: /api, /api/v2, /rest, /graphql, /v1… */
const API_ROOT = /^\/(?:(?:api|rest|graphql|gql|backend|services?|svc|gateway)(?:\/v\d+(?:\.\d+)?)?|v\d+(?:\.\d+)?)\/?$/i;
/** A host that is an API by its name: api.x, backend.x, gateway.x, backend3.x… */
const API_HOST = /^(?:api|backend|gateway|services?|svc)[\w-]*\./i;

const add = (set: Set<string>, v: string) => {
  if (v && set.size < MAX) set.add(v);
};

/** A path looks like an API or app route, not a file sitting next to the bundle. */
function looksLikePath(p: string): boolean {
  if (!p.startsWith("/") || p.startsWith("//")) return false;
  if (p.length < 2 || p.length > 200) return false;
  if (/\s/.test(p)) return false;
  // Plain static assets are noise: .js, .css, images, fonts, maps.
  if (/\.(js|css|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|mp4|webm|json)(\?|$)/i.test(p)) return false;
  return true;
}

/** Extracts endpoints, hosts, routes, secrets and source maps from one script's text. */
export function harvestScript(code: string): JsHarvest {
  const endpoints = new Map<string, JsEndpoint>();
  const hosts = new Set<string>();
  const routes = new Set<string>();
  const secrets = new Map<string, JsSecret>();
  const sourceMaps = new Set<string>();
  const apiBases = new Set<string>();

  // Explicit API settings: baseURL: "https://…/api", apiUrl = "/api/v1", API_BASE: "…".
  for (const m of code.matchAll(/\b(?:baseURL|baseUrl|base_url|apiUrl|apiURL|API_URL|API_BASE|apiBase|apiRoot|API_ROOT|endpoint)\s*[:=]\s*["'`]((?:https?:\/\/[A-Za-z0-9.-]+(?::\d+)?)?\/?[A-Za-z0-9_\-./]*)["'`]/g)) {
    const v = m[1]!.replace(/\/+$/, "");
    if (v && (v.startsWith("http") || v.startsWith("/"))) add(apiBases, v);
  }
  for (const m of code.matchAll(/\bhttps?:\/\/[A-Za-z0-9.-]+(?::\d+)?(\/[^\s"'`)<>]*)?/g)) {
    try {
      const u = new URL(m[0]);
      if (BORING_HOST.test(u.hostname)) continue; // CDNs, fonts, analytics: not the app's surface
      add(hosts, u.host);
      // An API root named in the code: relative calls are made against it.
      if (API_ROOT.test(u.pathname) || (API_HOST.test(u.hostname) && (u.pathname === "/" || u.pathname === ""))) add(apiBases, `${u.origin}${u.pathname.replace(/\/+$/, "")}`);
      if (u.pathname && looksLikePath(u.pathname) && endpoints.size < MAX) {
        endpoints.set(`${u.origin}${u.pathname}`, { path: u.pathname, origin: u.origin });
      }
    } catch {
      /* not a URL */
    }
  }

  // Relative paths in quotes: fetch("/api/..."), "/admin/users", `/v1/${x}`.
  for (const m of code.matchAll(/["'`](\/[A-Za-z0-9_\-./:${}*]{1,180})["'`]/g)) {
    const p = m[1]!.replace(/\$\{[^}]*\}/g, ":id"); // `/users/${id}` → /users/:id
    if (API_ROOT.test(p)) add(apiBases, p.replace(/\/+$/, ""));
    if (looksLikePath(p) && endpoints.size < MAX) endpoints.set(p, { path: p });
  }

  // SPA route definitions: path: "/admin/:id", { path: "users/new" } in a routes array.
  for (const m of code.matchAll(/\bpath\s*:\s*["'`](\/?[A-Za-z0-9_\-./:*]{1,180})["'`]/g)) {
    const r = m[1]!.startsWith("/") ? m[1]! : `/${m[1]}`;
    if (r.length > 1 && !/\.(js|css|map)$/i.test(r)) add(routes, r);
  }

  for (const { kind, re } of SECRET_RULES) {
    for (const m of code.matchAll(re)) {
      const value = (m[1] ?? m[0]).trim();
      // Skip obvious false positives: all-same char, or a known placeholder.
      if (/^(.)\1+$/.test(value) || /^(your|example|changeme|xxx+|placeholder|undefined|null)/i.test(value)) continue;
      if (secrets.size < 200) secrets.set(`${kind}:${value}`, { kind, value });
    }
  }

  for (const m of code.matchAll(/\/\/[#@]\s*sourceMappingURL=([^\s"'`]+)/g)) add(sourceMaps, m[1]!);

  return {
    endpoints: [...endpoints.values()],
    hosts: [...hosts],
    routes: [...routes],
    secrets: [...secrets.values()],
    sourceMaps: [...sourceMaps],
    apiBases: [...apiBases],
  };
}

/** The `<script src>` URLs in an HTML page, resolved against the page URL. */
export function scriptUrls(html: string, pageUrl: string): string[] {
  const out = new Set<string>();
  for (const m of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) {
    try {
      out.add(new URL(m[1]!, pageUrl).href);
    } catch {
      /* bad url */
    }
  }
  // Vite/webpack also preload chunks via <link rel="modulepreload"> and import() - pick those too.
  for (const m of html.matchAll(/<link\b[^>]*\brel\s*=\s*["'](?:module)?preload["'][^>]*\bhref\s*=\s*["']([^"']+\.m?js)["']/gi)) {
    try {
      out.add(new URL(m[1]!, pageUrl).href);
    } catch {
      /* bad url */
    }
  }
  return [...out];
}

/** Merges several scripts' harvests into one, de-duplicated. */
export function mergeHarvests(parts: JsHarvest[]): JsHarvest {
  const endpoints = new Map<string, JsEndpoint>();
  const hosts = new Set<string>();
  const routes = new Set<string>();
  const secrets = new Map<string, JsSecret>();
  const sourceMaps = new Set<string>();
  const apiBases = new Set<string>();
  for (const h of parts) {
    for (const b of h.apiBases) apiBases.add(b);
    for (const e of h.endpoints) endpoints.set(e.origin ? `${e.origin}${e.path}` : e.path, e);
    for (const x of h.hosts) hosts.add(x);
    for (const r of h.routes) routes.add(r);
    for (const s of h.secrets) secrets.set(`${s.kind}:${s.value}`, s);
    for (const m of h.sourceMaps) sourceMaps.add(m);
  }
  return { endpoints: [...endpoints.values()], hosts: [...hosts], routes: [...routes], secrets: [...secrets.values()], sourceMaps: [...sourceMaps], apiBases: [...apiBases] };
}
