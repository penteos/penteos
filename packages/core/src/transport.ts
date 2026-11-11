import { randomBytes } from "node:crypto";
import { connect as netConnect } from "node:net";
import { connect as tlsConnect, type PeerCertificate } from "node:tls";

/**
 * How a site protects the connection itself: which TLS versions and weak ciphers it still accepts,
 * whether plain HTTP is turned away, HSTS, cookie flags, the certificate, and the browser-side
 * defences in its headers (CSP, framing, CORS). Node's own TLS cannot even offer what matters most
 * here (OpenSSL 3 dropped 3DES and RC4), so versions and ciphers are tested the way sslscan does:
 * a hand-built ClientHello offering only the thing under test, and the server's answer read back.
 * Nothing past the server's first reply is sent.
 */

export type TlsVersion = "SSLv3" | "TLSv1.0" | "TLSv1.1" | "TLSv1.2";
const VERSION_CODE: Record<TlsVersion, number> = { SSLv3: 0x0300, "TLSv1.0": 0x0301, "TLSv1.1": 0x0302, "TLSv1.2": 0x0303 };

/** Cipher suites by family. The broad set is what old versions are tested with. */
export const CIPHERS = {
  broad: [0xc02f, 0xc030, 0xc02b, 0xc02c, 0xc013, 0xc014, 0xc009, 0xc00a, 0x009c, 0x009d, 0x002f, 0x0035, 0x0033, 0x0039, 0x000a, 0xc012, 0x0016],
  "3DES": [0x000a, 0xc012, 0xc008, 0x0016, 0x0013],
  RC4: [0x0005, 0x0004, 0xc011, 0xc007, 0x0018],
  "NULL or EXPORT": [0x0001, 0x0002, 0x003b, 0x0003, 0x0006, 0x0008, 0x0014, 0x0011, 0x0017, 0x0019],
} as const;

const u16 = (n: number) => [(n >> 8) & 0xff, n & 0xff];

/** A ClientHello offering one version and these ciphers, with SNI and the extensions servers expect. */
export function clientHello(host: string, version: TlsVersion, ciphers: readonly number[]): Buffer {
  const name = Buffer.from(host, "ascii");
  const ext: number[] = [];
  const addExt = (type: number, data: number[]) => ext.push(...u16(type), ...u16(data.length), ...data);
  if (version !== "SSLv3" && !/^[\d.]+$/.test(host)) addExt(0x0000, [...u16(name.length + 3), 0x00, ...u16(name.length), ...name]);
  addExt(0x000a, [...u16(6), ...u16(0x0017), ...u16(0x0018), ...u16(0x001d)]); // secp256r1, secp384r1, x25519
  addExt(0x000b, [0x01, 0x00]); // uncompressed points
  if (version === "TLSv1.2") addExt(0x000d, [...u16(12), 0x04, 0x01, 0x05, 0x01, 0x02, 0x01, 0x04, 0x03, 0x05, 0x03, 0x02, 0x03]);
  addExt(0xff01, [0x00]); // renegotiation info
  const body = [
    ...u16(VERSION_CODE[version]),
    ...randomBytes(32),
    0x00, // no session id
    ...u16(ciphers.length * 2),
    ...ciphers.flatMap(u16),
    0x01, 0x00, // compression: null
    ...(ext.length ? [...u16(ext.length), ...ext] : []),
  ];
  const handshake = [0x01, (body.length >> 16) & 0xff, ...u16(body.length & 0xffff), ...body];
  return Buffer.from([0x16, ...u16(version === "SSLv3" ? 0x0300 : 0x0301), ...u16(handshake.length), ...handshake]);
}

/** The server's first answer: a ServerHello (version and cipher it chose), an alert, or nothing usable. */
export function parseServerHello(buf: Buffer): { kind: "hello"; version: number; cipher: number } | { kind: "alert" } | { kind: "other" } {
  if (buf.length < 5) return { kind: "other" };
  if (buf[0] === 0x15) return { kind: "alert" };
  if (buf[0] !== 0x16 || buf.length < 5 + 4 + 2 + 32 + 1) return { kind: "other" };
  const hs = 5;
  if (buf[hs] !== 0x02) return { kind: "other" };
  const body = hs + 4;
  const version = buf.readUInt16BE(body);
  const sidLen = buf[body + 2 + 32]!;
  const at = body + 2 + 32 + 1 + sidLen;
  if (buf.length < at + 2) return { kind: "other" };
  return { kind: "hello", version, cipher: buf.readUInt16BE(at) };
}

/** Offers one version (and these ciphers) and says whether the server accepted exactly that. */
export function tryHandshake(host: string, port: number, version: TlsVersion, ciphers: readonly number[], timeoutMs = 6000): Promise<{ accepted: boolean; cipher?: number; error?: string }> {
  return new Promise((resolve) => {
    const sock = netConnect({ host, port });
    let buf = Buffer.alloc(0);
    let done = false;
    const finish = (r: { accepted: boolean; cipher?: number; error?: string }) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(r);
    };
    sock.setTimeout(timeoutMs, () => finish({ accepted: false, error: "timeout" }));
    sock.on("error", (e) => finish({ accepted: false, error: e.message }));
    sock.on("connect", () => sock.write(clientHello(host, version, ciphers)));
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, Buffer.isBuffer(d) ? d : Buffer.from(d)]);
      if (buf.length < 5) return;
      const len = buf.readUInt16BE(3);
      if (buf.length < 5 + Math.min(len, 200) && buf[0] === 0x16) return; // wait for the hello's head
      const r = parseServerHello(buf);
      if (r.kind === "hello") finish({ accepted: r.version === VERSION_CODE[version] && ciphers.includes(r.cipher as never), cipher: r.cipher });
      else finish({ accepted: false });
    });
    sock.on("end", () => finish({ accepted: false }));
  });
}

/** The certificate the site presents (with a normal, modern handshake). */
export function peerCertificate(host: string, port: number, timeoutMs = 8000): Promise<{ cert?: PeerCertificate; authorized: boolean; error?: string }> {
  return new Promise((resolve) => {
    const s = tlsConnect({ host, port, servername: /^[\d.]+$/.test(host) ? undefined : host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      const cert = s.getPeerCertificate();
      resolve({ cert, authorized: s.authorized, ...(s.authorizationError ? { error: String(s.authorizationError) } : {}) });
      s.end();
    });
    s.on("error", (e) => resolve({ authorized: false, error: e.message }));
    s.on("timeout", () => {
      s.destroy();
      resolve({ authorized: false, error: "timeout" });
    });
  });
}

export interface TransportIssue {
  title: string;
  severity: "info" | "low" | "medium" | "high";
  detail: string;
  /** What it is about, for the report and for not repeating it: "tls:TLSv1.0", "hsts", "csp:unsafe-inline". */
  key: string;
}

const header = (headers: Array<[string, string]>, name: string) => headers.filter(([k]) => k.toLowerCase() === name).map(([, v]) => v);

/** HSTS, CSP, framing and content-type defences of an HTTPS response. */
export function headerIssues(headers: Array<[string, string]>, isHtml: boolean): TransportIssue[] {
  const out: TransportIssue[] = [];
  const hsts = header(headers, "strict-transport-security")[0];
  if (!hsts) out.push({ key: "hsts", severity: "low", title: "No HSTS (Strict-Transport-Security)", detail: "Browsers are not told to use HTTPS only: a first visit over HTTP can be intercepted and downgraded." });
  else {
    const age = Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts)?.[1] ?? 0);
    if (age < 15552000) out.push({ key: "hsts:short", severity: "info", title: `HSTS max-age is short (${age}s)`, detail: `Strict-Transport-Security: ${hsts}. Six months (15552000) or more is the usual minimum.` });
  }
  if (!isHtml) return out;
  const csp = header(headers, "content-security-policy").join("; ");
  if (!csp) out.push({ key: "csp", severity: "info", title: "No Content-Security-Policy", detail: "Without a CSP, an XSS anywhere runs with no browser-side containment." });
  else {
    const directive = (name: string) => new RegExp(`(?:^|;)\\s*${name}\\s+([^;]*)`, "i").exec(csp)?.[1];
    const script = directive("script-src") ?? directive("default-src") ?? "";
    for (const bad of ["'unsafe-inline'", "'unsafe-eval'"]) {
      // 'unsafe-inline' is ignored by browsers when a nonce or hash is present.
      if (script.includes(bad) && !(bad === "'unsafe-inline'" && /'(nonce|sha(256|384|512))-/.test(script))) out.push({ key: `csp:${bad.replaceAll("'", "")}`, severity: "low", title: `CSP allows ${bad} for scripts`, detail: `script-src: ${script}. This removes most of the CSP's protection against XSS.` });
    }
    if (/(^|\s)(\*|https?:|data:)(\s|$)/.test(script)) out.push({ key: "csp:wide", severity: "low", title: "CSP lets scripts load from anywhere (*, https: or data:)", detail: `script-src: ${script}` });
  }
  const xfo = header(headers, "x-frame-options")[0];
  if (!xfo && !/frame-ancestors/i.test(csp)) out.push({ key: "framing", severity: "low", title: "Page can be framed by any site (no X-Frame-Options or frame-ancestors)", detail: "Clickjacking: another site can load this page invisibly and lead the user into clicking its buttons." });
  if (!header(headers, "x-content-type-options").some((v) => /nosniff/i.test(v))) out.push({ key: "nosniff", severity: "info", title: "No X-Content-Type-Options: nosniff", detail: "Browsers may guess content types, which can turn an upload or a JSON answer into script." });
  return out;
}

/** Cookie flags, as set over HTTPS (or over plain HTTP, which is worse). */
export function cookieIssues(setCookies: string[], overHttps: boolean): TransportIssue[] {
  const out: TransportIssue[] = [];
  for (const c of setCookies) {
    const name = c.split("=")[0]!.trim();
    const attrs = c.toLowerCase();
    const session = /sess|token|auth|sid|jwt|login|user/i.test(name);
    if (!/;\s*secure\b/.test(attrs)) out.push({ key: `cookie:${name}:secure`, severity: session ? "medium" : "low", title: `Cookie ${name} without Secure${overHttps ? "" : " (set over plain HTTP)"}`, detail: `Set-Cookie: ${c.replace(/=([^;]{0,6})[^;]*/, "=$1…")}. It can travel over unencrypted HTTP.` });
    if (session && !/;\s*httponly\b/.test(attrs)) out.push({ key: `cookie:${name}:httponly`, severity: "low", title: `Session cookie ${name} without HttpOnly`, detail: "Script on the page (an XSS) can read it." });
    if (session && !/;\s*samesite=/.test(attrs)) out.push({ key: `cookie:${name}:samesite`, severity: "info", title: `Session cookie ${name} without SameSite`, detail: "Browsers default to Lax today, but older ones send it on cross-site requests (CSRF)." });
  }
  return out;
}

/** CORS: an arbitrary origin (or null) reflected, with or without credentials. */
export function corsIssue(requestOrigin: string, headers: Array<[string, string]>): TransportIssue | undefined {
  const allow = header(headers, "access-control-allow-origin")[0];
  const creds = header(headers, "access-control-allow-credentials").some((v) => /true/i.test(v));
  if (!allow || allow === "*" && !creds) return undefined;
  if (allow === requestOrigin || (requestOrigin === "null" && allow === "null")) {
    return creds
      ? { key: `cors:${requestOrigin === "null" ? "null" : "reflect"}:creds`, severity: "high", title: `CORS trusts ${requestOrigin === "null" ? "the null origin" : "any origin"} with credentials`, detail: `Origin: ${requestOrigin} is answered with Access-Control-Allow-Origin: ${allow} and Allow-Credentials: true. Any site can read this user's authenticated responses.` }
      : { key: `cors:${requestOrigin === "null" ? "null" : "reflect"}`, severity: "low", title: `CORS reflects ${requestOrigin === "null" ? "the null origin" : "any origin"} (without credentials)`, detail: `Origin: ${requestOrigin} → Access-Control-Allow-Origin: ${allow}. Unauthenticated responses are readable by any site.` };
  }
  return undefined;
}

/** The certificate's own problems: expired or close to it, wrong name, not trusted. */
export function certificateIssues(host: string, info: { cert?: PeerCertificate; authorized: boolean; error?: string }, now = new Date()): TransportIssue[] {
  const out: TransportIssue[] = [];
  const c = info.cert;
  if (!c || !c.valid_to) return out;
  const days = Math.floor((new Date(c.valid_to).getTime() - now.getTime()) / 86_400_000);
  if (days < 0) out.push({ key: "cert:expired", severity: "medium", title: `Certificate expired ${-days} day(s) ago`, detail: `Valid to ${c.valid_to}.` });
  else if (days < 21) out.push({ key: "cert:expiring", severity: "low", title: `Certificate expires in ${days} day(s)`, detail: `Valid to ${c.valid_to}.` });
  if (info.error && /HOSTNAME|ALTNAME|IP: .* is not in the cert/i.test(info.error)) out.push({ key: "cert:name", severity: "medium", title: `Certificate is not valid for ${host}`, detail: info.error });
  else if (!info.authorized && info.error && days >= 0) out.push({ key: "cert:untrusted", severity: "medium", title: "Certificate is not trusted", detail: info.error });
  return out;
}

export const TLS_VERSION_SEVERITY: Record<Exclude<TlsVersion, "TLSv1.2">, TransportIssue["severity"]> = { SSLv3: "high", "TLSv1.0": "medium", "TLSv1.1": "medium" };
export const WEAK_CIPHER_SEVERITY: Record<Exclude<keyof typeof CIPHERS, "broad">, TransportIssue["severity"]> = { "3DES": "medium", RC4: "medium", "NULL or EXPORT": "high" };
