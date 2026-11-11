/**
 * Three web checks that need no account and that a careful tester always runs, with the pure part
 * (what to send, how to read the answer) here and the requests in the runner:
 *   - open redirect: a parameter that says where to go next, sent an outside address;
 *   - path traversal in a path parameter (/api/x/{id}): ../ in its encodings, compared with a
 *     normal value - a route the parameter should never reach answering is the sign;
 *   - session guard by presence: a panel that redirects to the login without a cookie but serves
 *     itself with an invented one only checks that the cookie exists.
 */

export const REDIRECT_CANARY = "penteos-redirect.invalid";

/** Ways of writing "go to the canary" that filters often miss. */
export const REDIRECT_PAYLOADS = [`https://${REDIRECT_CANARY}/`, `//${REDIRECT_CANARY}/`, `/\\${REDIRECT_CANARY}/`, `https:${REDIRECT_CANARY}`, `%2F%2F${REDIRECT_CANARY}%2F`, `https://${REDIRECT_CANARY}%2F@trusted/`];

/** Legitimate redirect values the app itself uses (?to=https://github.com/org/repo), per parameter. */
export function redirectExamples(text: string): Array<{ param: string; value: string }> {
  const out = new Map<string, { param: string; value: string }>();
  for (const m of text.matchAll(/[?&]([A-Za-z_][\w-]{0,30})=(https?(?::|%3A)(?:\/\/|%2F%2F)[^"'`&\s<>)]{3,200})/gi)) {
    let value = m[2]!;
    try {
      value = decodeURIComponent(value);
    } catch {
      /* as written */
    }
    if (out.size < 50) out.set(`${m[1]}=${value}`, { param: m[1]!, value });
  }
  return [...out.values()];
}

/**
 * Payloads that keep a legitimate value in the URL while going elsewhere: what beats allowlists
 * that only check the value appears in it, starts with it, or ends with its host.
 */
export function allowlistBypasses(legit: string): string[] {
  let host = "";
  try {
    host = new URL(legit).host;
  } catch {
    return [];
  }
  return [`https://${REDIRECT_CANARY}/?${legit}`, `https://${REDIRECT_CANARY}/#${legit}`, `https://${host}.${REDIRECT_CANARY}/`, `https://${host}@${REDIRECT_CANARY}/`, `${legit}@${REDIRECT_CANARY}/`];
}

/** Whether an answer sends the browser to the canary: a Location, a meta refresh or a script. */
export function redirectsToCanary(status: number, headers: Array<[string, string]>, body: string, from: string): boolean {
  const loc = headers.find(([k]) => k.toLowerCase() === "location")?.[1];
  if (loc && status >= 300 && status < 400) {
    try {
      if (new URL(loc.replace(/^\/\\/, "//"), from).hostname === REDIRECT_CANARY) return true;
    } catch {
      /* not a URL */
    }
  }
  const head = body.slice(0, 20_000);
  return new RegExp(`(http-equiv=["']?refresh[^>]*url=|location(\\.href)?\\s*=\\s*["'\`]|location\\.(assign|replace)\\(\\s*["'\`])\\s*(https?:)?//${REDIRECT_CANARY.replace(/\./g, "\\.")}`, "i").test(head);
}

/** Path segments that, put in a parameter's place, walk up the path, in the encodings servers decode. */
export const TRAVERSAL_PAYLOADS = ["..%2f", "..%2f..%2f", "%2e%2e%2f", "%2e%2e%2f%2e%2e%2f", "..;/", "..%252f", "..%5c", "%2e%2e/"];

/** A template's placeholder ({id}, :id) replaced; the others with a plain value. */
export function fillTemplate(template: string, value: string, other = "1"): string | undefined {
  const holes = [...template.matchAll(/\{[^}/]+\}|:[A-Za-z_][\w]*/g)];
  if (!holes.length) return undefined;
  let i = 0;
  return template.replace(/\{[^}/]+\}|:[A-Za-z_][\w]*/g, () => (i++ === holes.length - 1 ? value : other));
}

export interface Answer {
  status: number;
  size: number;
  type: string;
}

/**
 * Whether a traversal variant reached something a normal value does not: success where the normal
 * value fails, or a different kind of answer (another content type, far larger) with a new status.
 */
export function traversalReached(baseline: Answer, variant: Answer): boolean {
  const ok = (s: number) => s >= 200 && s < 300;
  if (ok(variant.status) && !ok(baseline.status)) return true;
  if (variant.status !== baseline.status && variant.status !== 404 && variant.status !== 400 && baseline.type && variant.type && variant.type.split(";")[0] !== baseline.type.split(";")[0] && variant.size > 50) return true;
  return ok(variant.status) && ok(baseline.status) && variant.size > Math.max(500, baseline.size * 3);
}

/** Screens that should need a session, among an app's routes. */
export function guardedRoutes(routes: string[]): string[] {
  return [...new Set(routes.filter((r) => /(^|\/)(dashboard|admin|panel|account|cuenta|settings|ajustes|configuracion|portal|backoffice|perfil|profile|movimientos|transactions|users|usuarios)(\/|$)/i.test(r) && !/[:{*]/.test(r)))].slice(0, 20);
}

/** Cookie names a session commonly travels in, plus the ones the app was seen setting. */
export const SESSION_COOKIES = ["session", "session-token", "sessionid", "token", "auth", "auth-token", "access_token", "jwt", "sid", "connect.sid", "next-auth.session-token", "__Secure-next-auth.session-token", "JSESSIONID", "PHPSESSID", "laravel_session", "_session"];

/** Sent to the login (a redirect there, or 401/403) versus served. */
export function looksSentAway(status: number, headers: Array<[string, string]>): boolean {
  if (status === 401 || status === 403) return true;
  const loc = headers.find(([k]) => k.toLowerCase() === "location")?.[1] ?? "";
  return status >= 300 && status < 400 && /log-?in|sign-?in|auth|ingresar|iniciar/i.test(loc);
}
