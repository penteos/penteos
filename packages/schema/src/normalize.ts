import ipaddr from "ipaddr.js";
import { getDomain } from "tldts";

/**
 * Natural-key normalization. Two sources talking about the same
 * real-world thing must produce the same key, so every function here is deterministic and
 * throws on input it cannot interpret instead of guessing.
 */

export class NormalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NormalizationError";
  }
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** IPv4 without leading zeros; IPv6 compressed and lowercase (RFC 5952). */
export function normalizeIp(input: string): string {
  let value = input.trim();
  if (value.startsWith("[") && value.endsWith("]")) value = value.slice(1, -1);

  const v4 = IPV4.exec(value);
  if (v4) {
    const octets = v4.slice(1).map((o) => Number.parseInt(o, 10));
    if (octets.some((o) => o > 255)) throw new NormalizationError(`invalid IPv4 address: ${input}`);
    return octets.join(".");
  }

  if (value.includes(":") && !value.includes("%") && ipaddr.IPv6.isValid(value)) {
    return ipaddr.IPv6.parse(value).toRFC5952String();
  }

  throw new NormalizationError(`invalid IP address: ${input}`);
}

export function isIp(input: string): boolean {
  try {
    normalizeIp(input);
    return true;
  } catch {
    return false;
  }
}

const DNS_LABEL = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

/** Lowercase, no trailing dot, IDN converted to punycode. */
export function normalizeFqdn(input: string): string {
  const value = input.trim().replace(/\.$/, "");
  if (value === "" || isIp(value) || /[:/\s@?#]/.test(value)) {
    throw new NormalizationError(`not a domain name: ${input}`);
  }

  let ascii: string;
  try {
    // The WHATWG URL parser applies IDNA (punycode) and lowercasing.
    ascii = new URL(`http://${value}`).hostname;
  } catch {
    throw new NormalizationError(`invalid domain name: ${input}`);
  }

  if (ascii.length > 253 || !ascii.split(".").every((label) => DNS_LABEL.test(label))) {
    throw new NormalizationError(`invalid domain name: ${input}`);
  }
  return ascii;
}

/** Registrable domain using the public suffix list: a.b.example.co.uk → example.co.uk. */
export function apexOf(fqdn: string): string {
  return getDomain(fqdn, { allowPrivateDomains: false }) ?? fqdn;
}

const DEFAULT_PORTS: Record<string, number> = { "http:": 80, "https:": 443 };

/** `scheme://host:port` with the port always explicit. */
export function normalizeOrigin(input: string): string {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new NormalizationError(`invalid URL: ${input}`);
  }
  const defaultPort = DEFAULT_PORTS[url.protocol];
  if (defaultPort === undefined) throw new NormalizationError(`unsupported scheme for a web origin: ${url.protocol}`);

  const port = url.port === "" ? defaultPort : Number(url.port);
  const rawHost = url.hostname;
  const host = isIp(rawHost) ? normalizeIp(rawHost) : normalizeFqdn(rawHost);
  const hostPart = host.includes(":") ? `[${host}]` : host;
  return `${url.protocol}//${hostPart}:${port}`;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DIGITS = /^\d+$/;
const LONG_HEX = /^[0-9a-f]{24,}$/i;
const JWT = /^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;
const LONG_TOKEN = /^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_-]{32,}$/;

function templateSegment(segment: string): string {
  if (segment === "") return segment;
  if (DIGITS.test(segment)) return "{id}";
  if (UUID.test(segment)) return "{uuid}";
  if (LONG_HEX.test(segment)) return "{hex}";
  if (JWT.test(segment) || LONG_TOKEN.test(segment)) return "{token}";
  return segment;
}

/**
 * Turns a concrete path into a template so `/api/users/1001` and `/api/users/1002` resolve to
 * the same endpoint. Query string and fragment are dropped; a trailing slash is ignored.
 */
export function pathTemplate(input: string): string {
  let path = input.trim();
  const cut = path.search(/[?#]/);
  if (cut !== -1) path = path.slice(0, cut);
  if (!path.startsWith("/")) path = `/${path}`;
  if (path.length > 1) path = path.replace(/\/+$/, "");
  return path.split("/").map(templateSegment).join("/");
}

export const DEFAULT_NETWORK_CONTEXT = "default";
