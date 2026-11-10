import { isIp, NormalizationError, normalizeFqdn, normalizeIp, normalizeOrigin } from "@penteos/schema";
import ipaddr from "ipaddr.js";

/** An address range as integers, so IPv4 and IPv6 ranges can be compared uniformly. */
export interface AddressRange {
  family: 4 | 6;
  start: bigint;
  end: bigint;
}

/**
 * What an action is aimed at. How a target is specified matters: attacking a domain by name
 * is not the same as attacking the IP it resolves to.
 */
export type Target =
  | { type: "address"; raw: string; range: AddressRange; port?: number }
  | { type: "domain"; raw: string; fqdn: string; port?: number }
  | { type: "url"; raw: string; origin: string; host: string; hostIsIp: boolean; port: number; path: string };

function toBigInt(bytes: number[]): bigint {
  return bytes.reduce((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
}

function addressToBigInt(ip: string): { family: 4 | 6; value: bigint } {
  const addr = ipaddr.parse(normalizeIp(ip));
  return { family: addr.kind() === "ipv4" ? 4 : 6, value: toBigInt(addr.toByteArray()) };
}

export function rangeOfIp(ip: string): AddressRange {
  const { family, value } = addressToBigInt(ip);
  return { family, start: value, end: value };
}

export function rangeOfCidr(cidr: string): AddressRange {
  const [ip, prefixText] = cidr.trim().split("/");
  if (ip === undefined || prefixText === undefined || !/^\d+$/.test(prefixText)) {
    throw new NormalizationError(`invalid CIDR: ${cidr}`);
  }
  const { family, value } = addressToBigInt(ip);
  const bits = family === 4 ? 32 : 128;
  const prefix = Number(prefixText);
  if (prefix > bits) throw new NormalizationError(`invalid CIDR prefix: ${cidr}`);
  const hostBits = BigInt(bits - prefix);
  const mask = ((1n << BigInt(bits)) - 1n) ^ ((1n << hostBits) - 1n);
  const start = value & mask;
  return { family, start, end: start | ((1n << hostBits) - 1n) };
}

export function rangeBetween(from: string, to: string): AddressRange {
  const a = addressToBigInt(from);
  const b = addressToBigInt(to);
  if (a.family !== b.family || a.value > b.value) throw new NormalizationError(`invalid range: ${from} - ${to}`);
  return { family: a.family, start: a.value, end: b.value };
}

export function rangeContains(outer: AddressRange, inner: AddressRange): boolean {
  return outer.family === inner.family && outer.start <= inner.start && inner.end <= outer.end;
}

export function rangesOverlap(a: AddressRange, b: AddressRange): boolean {
  return a.family === b.family && a.start <= b.end && b.start <= a.end;
}

/**
 * Parses what a human or an agent typed as a target: an IP, a CIDR, `host:port`, a domain or
 * a URL. Throws NormalizationError when the input cannot be interpreted.
 */
export function parseTarget(input: string): Target {
  const raw = input.trim();

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    const url = new URL(raw);
    const origin = normalizeOrigin(raw);
    const port = Number(origin.slice(origin.lastIndexOf(":") + 1));
    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    const hostIsIp = isIp(hostname);
    return {
      type: "url",
      raw,
      origin,
      host: hostIsIp ? normalizeIp(hostname) : normalizeFqdn(hostname),
      hostIsIp,
      port,
      path: url.pathname || "/",
    };
  }

  if (raw.includes("/")) return { type: "address", raw, range: rangeOfCidr(raw) };
  if (isIp(raw)) return { type: "address", raw, range: rangeOfIp(raw) };

  // host:port (IPv4 or domain; bare IPv6 is handled above by isIp)
  const hostPort = /^(.+):(\d{1,5})$/.exec(raw);
  if (hostPort) {
    const [, host = "", portText = ""] = hostPort;
    const port = Number(portText);
    if (port > 65535) throw new NormalizationError(`invalid port: ${raw}`);
    return isIp(host)
      ? { type: "address", raw, range: rangeOfIp(host), port }
      : { type: "domain", raw, fqdn: normalizeFqdn(host), port };
  }

  return { type: "domain", raw, fqdn: normalizeFqdn(raw) };
}
