/**
 * Penteos passive scanner: reviews responses as they go through the proxy (a viewing hook: it never
 * slows them) and drafts a finding once per problem. Only what a response shows by itself - no
 * request of its own is ever sent.
 */

const TEXT = {
  es: {
    headers: (host) => `Faltan cabeceras de seguridad en ${host}`,
    headersDesc: (url, missing) => `Las respuestas HTML de ${url} no incluyen: ${missing.join(", ")}.`,
    headersImpact: "Sin estas cabeceras el navegador no aplica defensas que mitigan XSS, clickjacking, el rastreo del tipo de contenido y la degradación a HTTP.",
    headersFix: "Agregar las cabeceras faltantes en el servidor web o en la aplicación (por ejemplo, Content-Security-Policy restrictiva, Strict-Transport-Security con max-age largo, X-Content-Type-Options: nosniff y frame-ancestors o X-Frame-Options).",
    secret: (kind, host) => `${kind} expuesta en ${host}`,
    secretDesc: (url, kind, sample) => `La respuesta de ${url} contiene lo que parece ser ${kind}: \`${sample}\`.`,
    secretImpact: "Quien acceda al recurso puede usar la credencial para actuar en nombre de la organización en el servicio correspondiente.",
    secretFix: "Revocar la credencial, sacarla del código o la respuesta y moverla a un almacén de secretos del lado del servidor.",
    error: (kind, host) => `${kind} con detalle técnico en ${host}`,
    errorDesc: (url, sample) => `La respuesta de ${url} muestra un error con detalle interno:\n\n\`\`\`\n${sample}\n\`\`\``,
    errorImpact: "Revela tecnologías, rutas internas o consultas que facilitan otros ataques; un error de base de datos puede indicar una inyección.",
    errorFix: "Desactivar el modo de depuración en producción y mostrar mensajes de error genéricos; registrar el detalle solo del lado del servidor.",
    listing: (host) => `Listado de directorio habilitado en ${host}`,
    listingDesc: (url) => `${url} muestra el contenido del directorio.`,
    listingImpact: "Expone archivos que no deberían ser públicos (respaldos, configuraciones, código).",
    listingFix: "Desactivar el listado de directorios en el servidor web.",
    cookie: (name, host) => `Cookie de sesión ${name} sin protección en ${host}`,
    cookieDesc: (url, name, missing) => `${url} entrega la cookie ${name} sin ${missing.join(" ni ")}.`,
    cookieImpact: "Sin Secure puede viajar sin cifrar; sin HttpOnly, un XSS puede leerla y robar la sesión.",
    cookieFix: "Emitir las cookies de sesión con Secure, HttpOnly y SameSite.",
    kinds: { headers: "Cabeceras", secret: "Secreto", error: "Error", listing: "Listado", cookie: "Cookie" },
    forgotten: (n) => `Olvidé ${n} problemas: volverá a avisar lo que vea.`,
  },
  en: {
    headers: (host) => `Missing security headers on ${host}`,
    headersDesc: (url, missing) => `HTML responses from ${url} do not include: ${missing.join(", ")}.`,
    headersImpact: "Without these headers the browser does not apply defenses that mitigate XSS, clickjacking, content-type sniffing and downgrades to HTTP.",
    headersFix: "Add the missing headers in the web server or the application (for example a restrictive Content-Security-Policy, Strict-Transport-Security with a long max-age, X-Content-Type-Options: nosniff and frame-ancestors or X-Frame-Options).",
    secret: (kind, host) => `${kind} exposed on ${host}`,
    secretDesc: (url, kind, sample) => `The response from ${url} contains what looks like ${kind}: \`${sample}\`.`,
    secretImpact: "Anyone who reaches the resource can use the credential to act on behalf of the organization in that service.",
    secretFix: "Revoke the credential, remove it from the code or the response, and move it to a server-side secret store.",
    error: (kind, host) => `${kind} with technical detail on ${host}`,
    errorDesc: (url, sample) => `The response from ${url} shows an error with internal detail:\n\n\`\`\`\n${sample}\n\`\`\``,
    errorImpact: "It reveals technologies, internal paths or queries that make other attacks easier; a database error may point to an injection.",
    errorFix: "Turn debug mode off in production and show generic error messages; log the detail on the server side only.",
    listing: (host) => `Directory listing enabled on ${host}`,
    listingDesc: (url) => `${url} shows the directory's contents.`,
    listingImpact: "It exposes files that should not be public (backups, configuration, code).",
    listingFix: "Turn directory listing off in the web server.",
    cookie: (name, host) => `Session cookie ${name} unprotected on ${host}`,
    cookieDesc: (url, name, missing) => `${url} sets the cookie ${name} without ${missing.join(" or ")}.`,
    cookieImpact: "Without Secure it may travel unencrypted; without HttpOnly, an XSS can read it and steal the session.",
    cookieFix: "Set session cookies with Secure, HttpOnly and SameSite.",
    kinds: { headers: "Headers", secret: "Secret", error: "Error", listing: "Listing", cookie: "Cookie" },
    forgotten: (n) => `Forgot ${n} problems: it will warn again about what it sees.`,
  },
};

const SECRETS = [
  { kind: "AWS access key", re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { kind: "Private key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/ },
  { kind: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { kind: "GitHub token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { kind: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { kind: "Stripe secret key", re: /\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b/ },
  { kind: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/ },
];

const ERRORS = [
  { kind: "SQL error", re: /(You have an error in your SQL syntax|SQLSTATE\[|ORA-\d{5}|Microsoft OLE DB Provider for SQL Server|PG::SyntaxError|SQLite3?::|Unclosed quotation mark after the character string)/i, severity: "medium" },
  { kind: "Stack trace", re: /(Traceback \(most recent call last\)|at [a-zA-Z_$][\w$]*(\.[\w$<>]+)+\([\w$]+\.java:\d+\)|System\.[A-Za-z.]+Exception:|Fatal error: .{0,200} on line \d+|Whoops! There was an error|Werkzeug Debugger|DEBUG = True)/, severity: "low" },
];

const SESSION_COOKIE = /^(sess|session|sid|phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|laravel_session|_session|auth|token|jwt)/i;

let settingsCache = { at: 0, value: null };
async function settingsOf(penteos) {
  if (Date.now() - settingsCache.at < 30_000 && settingsCache.value) return settingsCache.value;
  const value = await penteos.settings();
  settingsCache = { at: Date.now(), value };
  return value;
}

const header = (headers, name) => headers.find(([k]) => k.toLowerCase() === name)?.[1];
const allHeaders = (headers, name) => headers.filter(([k]) => k.toLowerCase() === name).map(([, v]) => v);
const mask = (s) => (s.length <= 10 ? `${s.slice(0, 2)}…` : `${s.slice(0, 6)}…${s.slice(-4)}`);

/** Drafts one finding per key, ever (the project remembers what it already flagged). */
async function once(penteos, key, url, finding) {
  const seen = await penteos.store.query("seen", { where: { key }, limit: 1 });
  if (seen.length) return false;
  await penteos.store.insert("seen", { key, url });
  const draft = await penteos.findingDraft(finding);
  await penteos.store.update("seen", { key }, { finding: draft.id });
  return true;
}

export async function activate(plugin) {
  plugin.operation("inspect", async (res, penteos) => {
    const on = await settingsOf(penteos);
    const T = TEXT[penteos.engagement.language === "en" ? "en" : "es"];
    const url = new URL(res.request.url);
    const host = url.host;
    const where = `${url.origin}${url.pathname}`;
    const type = (header(res.headers, "content-type") ?? "").toLowerCase();
    const body = res.bodyEncoding === "text" && typeof res.body === "string" ? res.body.slice(0, 512 * 1024) : "";
    const html = type.startsWith("text/html");

    if (on.headers !== false && html && res.status >= 200 && res.status < 300) {
      const missing = [];
      const csp = header(res.headers, "content-security-policy");
      if (!csp) missing.push("Content-Security-Policy");
      if (url.protocol === "https:" && !header(res.headers, "strict-transport-security")) missing.push("Strict-Transport-Security");
      if (!header(res.headers, "x-frame-options") && !/frame-ancestors/i.test(csp ?? "")) missing.push("X-Frame-Options / frame-ancestors");
      if ((header(res.headers, "x-content-type-options") ?? "").toLowerCase() !== "nosniff") missing.push("X-Content-Type-Options");
      if (missing.length >= 2) await once(penteos, `headers:${host}`, where, { title: T.headers(host), severity: "low", description: T.headersDesc(where, missing), impact: T.headersImpact, remediation: T.headersFix });
    }

    if (on.secrets !== false && body) {
      for (const s of SECRETS) {
        const m = s.re.exec(body);
        if (m) await once(penteos, `secret:${s.kind}:${host}${url.pathname}`, where, { title: T.secret(s.kind, host), severity: "high", description: T.secretDesc(where, s.kind, mask(m[0])), impact: T.secretImpact, remediation: T.secretFix });
      }
    }

    if (on.errors !== false && body && (html || type.includes("json") || type.startsWith("text/"))) {
      for (const e of ERRORS) {
        const m = e.re.exec(body);
        if (!m) continue;
        const at = Math.max(0, m.index - 120);
        const sample = body.slice(at, m.index + 280).replace(/<[^>]+>/g, " ").replace(/\s+\n/g, "\n").trim();
        await once(penteos, `error:${e.kind}:${host}${url.pathname}`, where, { title: T.error(e.kind, host), severity: e.severity, description: T.errorDesc(where, sample), impact: T.errorImpact, remediation: T.errorFix });
      }
    }

    if (on.listing !== false && html && /<title>\s*Index of \//i.test(body)) {
      await once(penteos, `listing:${host}${url.pathname}`, where, { title: T.listing(host), severity: "low", description: T.listingDesc(where), impact: T.listingImpact, remediation: T.listingFix });
    }

    if (on.cookies !== false) {
      for (const c of allHeaders(res.headers, "set-cookie")) {
        const name = c.split("=")[0].trim();
        if (!SESSION_COOKIE.test(name)) continue;
        const missing = [];
        if (url.protocol === "https:" && !/;\s*secure/i.test(c)) missing.push("Secure");
        if (!/;\s*httponly/i.test(c)) missing.push("HttpOnly");
        if (missing.length) await once(penteos, `cookie:${host}:${name}`, where, { title: T.cookie(name, host), severity: "low", description: T.cookieDesc(where, name, missing), impact: T.cookieImpact, remediation: T.cookieFix });
      }
    }
  });

  plugin.operation("summary", async (_input, penteos) => {
    const T = TEXT[penteos.engagement.language === "en" ? "en" : "es"];
    const rows = await penteos.store.query("seen", { orderBy: { column: "created_at", dir: "desc" }, limit: 200 });
    return { items: rows.map((r) => ({ kind: T.kinds[String(r.key).split(":")[0]] ?? r.key, where: r.url })) };
  });

  plugin.operation("forget", async (_input, penteos) => {
    const T = TEXT[penteos.engagement.language === "en" ? "en" : "es"];
    const r = await penteos.store.delete("seen", { key: { op: "like", value: "%" } });
    return { forgotten: T.forgotten(r.deleted) };
  });
}
