import { resolve4, resolve6, resolveCname } from "node:dns/promises";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP, Socket } from "node:net";
import { lookup } from "node:dns/promises";

/**
 * Penteos's own fallbacks for the capabilities: what the agent gets
 * when no tool for the job is installed. Each one writes the SAME output the tool it stands in for
 * would (dnsx and subfinder JSON lines, httpx JSON lines, katana JSON lines, nmap XML), so it goes
 * through that tool's own mapping and the graph looks exactly as if the tool had run.
 *
 * They are deliberately modest (a short port list, a short path list, a shallow crawl): enough to
 * keep the work moving, and honest about it (the capability reports "degraded" and opens a gap).
 */

export type Say = (line: string) => void;

interface Limits {
  signal?: AbortSignal;
}

// ---------------------------------------------------------------------------------------------
// DNS (stands in for dnsx: same JSON lines)

export async function builtinDns(names: string[], say: Say, { signal }: Limits = {}): Promise<string> {
  const out: string[] = [];
  for (const raw of names) {
    if (signal?.aborted) break;
    const host = raw.replace(/^\*\./, "").replace(/\.$/, "").toLowerCase();
    const [a, aaaa, cname] = await Promise.all([resolve4(host).catch(() => []), resolve6(host).catch(() => []), resolveCname(host).catch(() => [])]);
    const exists = a.length + aaaa.length + cname.length > 0;
    out.push(JSON.stringify({ host, status_code: exists ? "NOERROR" : "NXDOMAIN", a: [...a, ...aaaa], cname }));
    say(`${host}: ${exists ? [...a, ...aaaa, ...cname.map((c) => `CNAME ${c}`)].join(", ") : "does not exist"}`);
  }
  return out.join("\n");
}

// ---------------------------------------------------------------------------------------------
// Passive subdomains from certificate transparency (stands in for subfinder: same JSON lines)

export async function builtinSubdomains(domains: string[], say: Say, { signal }: Limits = {}): Promise<string> {
  const found = new Set<string>();
  for (const raw of domains) {
    const domain = raw.replace(/^\*\./, "").toLowerCase();
    const names = new Set<string>();
    const add = (n: string) => {
      const name = n.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
      if (name === domain || name.endsWith(`.${domain}`)) if (/^[a-z0-9.-]+$/.test(name)) names.add(name);
    };
    // crt.sh first; certspotter when it is down (it often is).
    try {
      const r = await fetch(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`, { signal: signal ?? AbortSignal.timeout(45_000), headers: { "user-agent": "Penteos" } });
      if (!r.ok) throw new Error(`crt.sh ${r.status}`);
      for (const row of (await r.json()) as Array<{ name_value?: string }>) for (const n of String(row.name_value ?? "").split("\n")) add(n);
      say(`crt.sh: ${names.size} names for ${domain}`);
    } catch (e) {
      say(`crt.sh did not answer (${(e as Error).message}); trying certspotter`);
      try {
        const r = await fetch(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`, { signal: signal ?? AbortSignal.timeout(45_000), headers: { "user-agent": "Penteos" } });
        if (!r.ok) throw new Error(`certspotter ${r.status}`);
        for (const row of (await r.json()) as Array<{ dns_names?: string[] }>) for (const n of row.dns_names ?? []) add(n);
        say(`certspotter: ${names.size} names for ${domain}`);
      } catch (e2) {
        say(`certspotter did not answer either (${(e2 as Error).message})`);
      }
    }
    for (const n of names) found.add(n);
  }
  return [...found].sort().map((host) => JSON.stringify({ host, source: "crtsh" })).join("\n");
}

// ---------------------------------------------------------------------------------------------
// HTTP (stands in for httpx: same JSON lines)

interface Fetched {
  url: string;
  status: number;
  headers: IncomingMessage["headers"];
  body: string;
  ip?: string;
}

/** One GET, no redirects followed (a redirect could leave the scope), any certificate accepted. */
export function httpGet(url: string, { timeoutMs = 10_000, maxBytes = 256 * 1024, signal }: { timeoutMs?: number; maxBytes?: number; signal?: AbortSignal } = {}): Promise<Fetched> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = (u.protocol === "https:" ? httpsRequest : httpRequest)(
      u,
      { method: "GET", headers: { "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36", accept: "*/*" }, rejectUnauthorized: false, timeout: timeoutMs, ...(signal ? { signal } : {}) },
      (res) => {
        // Read now: once the response ends the socket may already be gone.
        const ip = res.socket?.remoteAddress?.replace(/^::ffff:/, "");
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (c: Buffer) => {
          if (size < maxBytes) chunks.push(c);
          size += c.length;
          if (size >= maxBytes) res.destroy();
        });
        const done = () => resolve({ url, status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8"), ...(ip ? { ip } : {}) });
        res.on("end", done);
        res.on("close", done);
      },
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end();
  });
}

/** Technologies a response gives away in its headers and markup (a small subset of httpx's). */
export function technologiesOf(f: Fetched): string[] {
  const tech = new Set<string>();
  const h = (n: string) => String(f.headers[n] ?? "");
  if (h("x-powered-by")) tech.add(h("x-powered-by"));
  if (h("x-aspnet-version")) tech.add(`ASP.NET ${h("x-aspnet-version")}`);
  const cookies = ([] as string[]).concat(f.headers["set-cookie"] ?? []).join(";");
  if (/PHPSESSID/i.test(cookies)) tech.add("PHP");
  if (/JSESSIONID/i.test(cookies)) tech.add("Java");
  if (/ASP\.NET_SessionId/i.test(cookies)) tech.add("ASP.NET");
  if (/laravel_session/i.test(cookies)) tech.add("Laravel");
  if (/csrftoken|sessionid=/i.test(cookies) && /django/i.test(f.body)) tech.add("Django");
  const generator = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(f.body)?.[1];
  if (generator) tech.add(generator);
  if (/wp-content\/|wp-includes\//i.test(f.body)) tech.add("WordPress");
  if (/__NEXT_DATA__|\/_next\/static\//.test(f.body)) tech.add("Next.js");
  if (/ng-version=|ng-app/i.test(f.body)) tech.add("Angular");
  if (/data-reactroot|react-dom/i.test(f.body)) tech.add("React");
  if (/\/_nuxt\//.test(f.body)) tech.add("Nuxt.js");
  if (/drupal-settings-json|Drupal\.settings/i.test(f.body)) tech.add("Drupal");
  if (/cdn\.shopify\.com/i.test(f.body)) tech.add("Shopify");
  if (h("cf-ray")) tech.add("Cloudflare");
  return [...tech];
}

export async function builtinHttpProbe(targets: string[], say: Say, { signal }: Limits = {}): Promise<string> {
  const out: string[] = [];
  for (const t of targets) {
    if (signal?.aborted) break;
    // A bare host is tried over HTTPS, then HTTP (like httpx).
    const urls = /^https?:\/\//i.test(t) ? [t] : [`https://${t}`, `http://${t}`];
    for (const url of urls) {
      try {
        const f = await httpGet(url, { signal });
        const title = /<title[^>]*>([^<]{0,200})<\/title>/i.exec(f.body)?.[1]?.trim().replace(/\s+/g, " ");
        const line = {
          url: new URL(url).origin + new URL(url).pathname.replace(/\/$/, ""),
          status_code: f.status,
          ...(title ? { title } : {}),
          ...(f.ip ? { host: f.ip } : {}),
          ...(f.headers.server ? { webserver: String(f.headers.server) } : {}),
          tech: technologiesOf(f),
          ...(f.headers.location ? { location: String(f.headers.location) } : {}),
        };
        out.push(JSON.stringify(line));
        say(`${url} → ${f.status}${title ? ` «${title}»` : ""}${line.tech.length ? ` [${line.tech.join(", ")}]` : ""}`);
        break;
      } catch (e) {
        say(`${url}: ${(e as Error).message}`);
      }
    }
  }
  return out.join("\n");
}

// ---------------------------------------------------------------------------------------------
// Crawling and common paths (stand in for katana: same JSON lines, one per URL found)

const katanaLine = (url: string, status: number, method = "GET") => JSON.stringify({ request: { endpoint: url, method }, response: { status_code: status } });

/** Same-origin links of a page: href, src and action, without fragments. */
export function linksOf(html: string, base: string): string[] {
  const out = new Set<string>();
  const origin = new URL(base).origin;
  for (const m of html.matchAll(/(?:href|src|action)\s*=\s*["']([^"']+)["']/gi)) {
    try {
      const u = new URL(m[1]!.split("#")[0]!, base);
      if (u.origin === origin && /^https?:$/.test(u.protocol)) out.add(u.origin + u.pathname + u.search);
    } catch {
      /* not a URL */
    }
  }
  return [...out];
}

export async function builtinCrawl(origins: string[], say: Say, { signal, maxPages = 60, depth = 2 }: Limits & { maxPages?: number; depth?: number } = {}): Promise<string> {
  const out: string[] = [];
  for (const start of origins) {
    const seen = new Set<string>();
    let frontier = [new URL(start).href];
    for (let level = 0; level <= depth && frontier.length && seen.size < maxPages; level++) {
      const next: string[] = [];
      for (const url of frontier) {
        if (signal?.aborted || seen.size >= maxPages) break;
        if (seen.has(url)) continue;
        seen.add(url);
        try {
          const f = await httpGet(url, { signal });
          out.push(katanaLine(url, f.status));
          if (/html/i.test(String(f.headers["content-type"] ?? ""))) for (const l of linksOf(f.body, url)) if (!seen.has(l)) next.push(l);
        } catch {
          /* unreachable link: skipped */
        }
      }
      frontier = next;
    }
    say(`${start}: ${seen.size} URLs crawled (depth ${depth}, cap ${maxPages})`);
  }
  return out.join("\n");
}

/** Paths worth asking for on almost any web application (a short, careful list). */
export const COMMON_PATHS = [
  "robots.txt", "sitemap.xml", ".well-known/security.txt", ".well-known/openid-configuration", "crossdomain.xml",
  "admin", "administrator", "admin/login", "login", "signin", "logout", "register", "signup", "dashboard", "panel", "console",
  "api", "api/v1", "api/v2", "api/docs", "api/swagger.json", "swagger", "swagger-ui", "swagger-ui.html", "swagger.json", "openapi.json", "v2/api-docs", "v3/api-docs", "graphql", "graphiql", "playground",
  ".git/HEAD", ".git/config", ".svn/entries", ".hg/requires", ".env", ".env.local", ".env.production", ".DS_Store", "config.json", "config.yml", "config.php", "web.config", ".htaccess", ".htpasswd",
  "backup", "backup.zip", "backup.sql", "db.sql", "dump.sql", "database.sql", "site.zip", "www.zip",
  "phpinfo.php", "info.php", "test.php", "server-status", "server-info", "status", "health", "healthz", "metrics", "actuator", "actuator/health", "actuator/env", "actuator/mappings", "debug", "trace",
  "wp-admin/", "wp-login.php", "wp-json/", "xmlrpc.php", "user/login", "administrator/index.php", "phpmyadmin/", "pma/", "adminer.php",
  "uploads", "upload", "files", "static", "assets", "media", "images", "js", "css", "public", "private", "tmp", "temp", "logs", "log",
  "cgi-bin/", "jenkins", "jmx-console", "manager/html", "solr", "kibana", "grafana", "prometheus",
  "package.json", "composer.json", "Gemfile", "requirements.txt", "yarn.lock", "Dockerfile", "docker-compose.yml",
];

export async function builtinCommonPaths(origins: string[], say: Say, { signal, paths = COMMON_PATHS }: Limits & { paths?: string[] } = {}): Promise<string> {
  const out: string[] = [];
  for (const raw of origins) {
    const origin = new URL(raw).origin;
    // What a path that does not exist looks like here (many sites answer 200 to everything).
    let baseline: { status: number; length: number } | undefined;
    try {
      const f = await httpGet(`${origin}/penteos-${Math.random().toString(36).slice(2, 10)}`, { signal });
      baseline = { status: f.status, length: f.body.length };
    } catch {
      say(`${origin}: no answer`);
      continue;
    }
    let hits = 0;
    const queue = [...paths];
    const worker = async () => {
      while (queue.length && !signal?.aborted) {
        const path = queue.shift()!;
        const url = `${origin}/${path}`;
        try {
          const f = await httpGet(url, { signal, timeoutMs: 8000 });
          const like404 = f.status === 404 || (f.status === baseline!.status && Math.abs(f.body.length - baseline!.length) <= Math.max(32, baseline!.length * 0.05));
          if (!like404 && f.status < 500) {
            hits++;
            out.push(katanaLine(url, f.status));
          }
        } catch {
          /* skipped */
        }
      }
    };
    // Four at a time: polite on a production site, still quick.
    await Promise.all([worker(), worker(), worker(), worker()]);
    say(`${origin}: ${hits} of ${paths.length} paths answer differently from a nonexistent one (${baseline.status})`);
  }
  return out.join("\n");
}

// ---------------------------------------------------------------------------------------------
// Ports (stands in for nmap: writes nmap XML, read by nmap's own parser)

/** nmap's 100 most common TCP ports. */
export const TOP_PORTS = [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157];

const SERVICE_BY_PORT: Record<number, string> = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 81: "http", 88: "kerberos-sec", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
  143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission", 631: "ipp", 873: "rsync", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
  2049: "nfs", 3000: "http", 3128: "http-proxy", 3306: "mysql", 3389: "ms-wbt-server", 5000: "http", 5432: "postgresql", 5900: "vnc", 6000: "X11", 8000: "http", 8008: "http",
  8080: "http", 8081: "http", 8443: "https", 8888: "http", 9100: "jetdirect", 10000: "http",
};
const HTTP_PORTS = new Set([80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 10000]);
const TLS_PORTS = new Set([443, 465, 636, 993, 995, 8443]);

interface Open {
  port: number;
  banner?: string;
}

function probePort(ip: string, port: number, timeoutMs: number): Promise<Open | undefined> {
  return new Promise((resolve) => {
    const s = new Socket();
    let banner = "";
    let open = false;
    const finish = () => {
      s.destroy();
      resolve(open ? { port, ...(banner.trim() ? { banner: banner.trim().slice(0, 300) } : {}) } : undefined);
    };
    s.setTimeout(timeoutMs);
    s.once("connect", () => {
      open = true;
      // Services that speak first (SSH, FTP, SMTP…) show their banner; HTTP is asked for a HEAD.
      if (HTTP_PORTS.has(port) && !TLS_PORTS.has(port)) s.write(`HEAD / HTTP/1.0\r\nHost: ${ip}\r\n\r\n`);
      setTimeout(finish, 1200);
    });
    s.on("data", (d) => {
      banner += d.toString("latin1");
      if (banner.length > 300) finish();
    });
    s.once("timeout", finish);
    s.once("error", finish);
    s.connect(port, ip);
  });
}

/** Product and version from a banner, the way nmap reports them (a few common ones). */
export function productOf(banner: string | undefined): { product?: string; version?: string } {
  if (!banner) return {};
  let m = /^SSH-[\d.]+-([A-Za-z]+)[_-]([\w.]+)/.exec(banner);
  if (m) return { product: m[1] === "OpenSSH" ? "OpenSSH" : m[1], version: m[2] };
  m = /^Server:\s*([^\s/]+)(?:\/([\w.]+))?/im.exec(banner);
  if (m) return { product: m[1], ...(m[2] ? { version: m[2] } : {}) };
  m = /^220[ -].*?\b(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server|Postfix|Exim|Microsoft ESMTP)[ /]?([\d.]+)?/i.exec(banner);
  if (m) return { product: m[1], ...(m[2] ? { version: m[2] } : {}) };
  m = /^.\0\0\0\n([\d.]+)-?([\w.-]*)/s.exec(banner);
  if (m) return { product: "MySQL", version: m[1] };
  return {};
}

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export async function builtinPortScan(targets: string[], say: Say, { signal, ports = TOP_PORTS, timeoutMs = 1500, concurrency = 64 }: Limits & { ports?: number[]; timeoutMs?: number; concurrency?: number } = {}): Promise<string> {
  const hosts: string[] = [];
  for (const t of targets) {
    if (signal?.aborted) break;
    const name = t.replace(/^\w+:\/\//, "").replace(/[/:].*$/, "");
    let ip = name;
    if (!isIP(name)) {
      try {
        ip = (await lookup(name)).address;
      } catch {
        say(`${name}: does not resolve`);
        continue;
      }
    }
    const queue = [...ports];
    const open: Open[] = [];
    const worker = async () => {
      while (queue.length && !signal?.aborted) {
        const r = await probePort(ip, queue.shift()!, timeoutMs);
        if (r) open.push(r);
      }
    };
    await Promise.all(Array.from({ length: Math.min(concurrency, ports.length) }, worker));
    open.sort((a, b) => a.port - b.port);
    say(`${name} (${ip}): ${open.length ? open.map((o) => o.port).join(", ") : "no open port"} of ${ports.length} tried`);
    const portXml = open
      .map((o) => {
        const p = productOf(o.banner);
        const svc = SERVICE_BY_PORT[o.port] ?? "unknown";
        return `<port protocol="tcp" portid="${o.port}"><state state="open" reason="syn-ack"/><service name="${svc}"${p.product ? ` product="${esc(p.product)}"` : ""}${p.version ? ` version="${esc(p.version)}"` : ""}${TLS_PORTS.has(o.port) ? ' tunnel="ssl"' : ""} method="probed" conf="3"/></port>`;
      })
      .join("");
    hosts.push(`<host><status state="up"/><address addr="${ip}" addrtype="${isIP(ip) === 6 ? "ipv6" : "ipv4"}"/>${name !== ip ? `<hostnames><hostname name="${esc(name)}" type="user"/></hostnames>` : ""}<ports>${portXml}</ports></host>`);
  }
  return `<?xml version="1.0"?><nmaprun scanner="penteos-tcp-connect" start="${Math.floor(Date.now() / 1000)}" version="penteos">${hosts.join("")}</nmaprun>`;
}
