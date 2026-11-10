import { existsSync } from "node:fs";
import { isIp } from "@penteos/schema";
import { parse as parseDomain } from "tldts";
import { type AddressRange, parseTarget, rangeContains, rangeOfIp, type Target } from "../scope/target.js";

/**
 * Finds everything in a command line that looks like a target: IPs, CIDRs, host:port, URLs
 * and domain names. Used to verify that the targets declared
 * for an arbitrary command are really the ones it will hit.
 */

const FILE_EXTENSIONS = new Set([
  "txt", "xml", "json", "jsonl", "csv", "yaml", "yml", "html", "htm", "log", "conf", "cfg", "ini",
  "py", "sh", "rb", "pl", "go", "js", "ts", "md", "php", "jsp", "asp", "aspx", "zip", "gz", "tar",
  "pcap", "pcapng", "nse", "lst", "out", "db", "sqlite", "exe", "dll", "ps1", "bat", "so", "bin",
]);

/**
 * Suffixes that are not on the public list but name hosts all the same: internal networks
 * (dc01.corp.local, intranet.acme.internal) and the reserved test names. Without them a bare
 * internal hostname in a command would not count as a target and would skip the scope check.
 */
const PRIVATE_SUFFIXES = new Set([
  "local", "localdomain", "internal", "intranet", "corp", "lan", "home", "private", "domain",
  "test", "example", "invalid", "localhost", "arpa",
]);

function looksLikeDomain(token: string): boolean {
  if (!token.includes(".") || token.startsWith(".") || token.endsWith(".")) return false;
  if (!/^[a-z0-9._-]+$/i.test(token)) return false;
  const extension = token.slice(token.lastIndexOf(".") + 1).toLowerCase();
  if (FILE_EXTENSIONS.has(extension)) return false;
  if (existsSync(token)) return false; // a local file or directory, not a host
  if (PRIVATE_SUFFIXES.has(extension)) return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(token);
  const parsed = parseDomain(token);
  return parsed.isIcann === true && parsed.domain !== null;
}

function candidates(token: string): string[] {
  // --url=https://x, -u=x, key=value lists
  const parts = token.includes("=") && !/^[a-z][a-z0-9+.-]*:\/\//i.test(token) ? token.split("=").slice(1) : [token];
  return parts.flatMap((p) => (/^[a-z][a-z0-9+.-]*:\/\//i.test(p) ? [p] : p.split(","))).filter(Boolean);
}

export function findTargetTokens(argv: string[]): string[] {
  const found = new Set<string>();
  for (const token of argv) {
    for (const piece of candidates(token)) {
      if (/^[a-z][a-z0-9+.-]*:\/\//i.test(piece)) {
        if (/^(https?|wss?|ftp|smb|ldaps?|rdp|ssh|mysql|postgres(ql)?|mssql|redis|mongodb):/i.test(piece)) found.add(piece);
        continue;
      }
      if (isIp(piece) || /^[0-9a-f:.]+\/\d{1,3}$/i.test(piece)) {
        found.add(piece);
        continue;
      }
      const hostPort = /^([^:/\s]+):(\d{1,5})$/.exec(piece);
      if (hostPort && (isIp(hostPort[1]!) || looksLikeDomain(hostPort[1]!))) {
        found.add(piece);
        continue;
      }
      if (looksLikeDomain(piece)) found.add(piece.toLowerCase());
    }
  }
  return [...found];
}

function hostOf(t: Target): string | undefined {
  if (t.type === "domain") return t.fqdn;
  if (t.type === "url" && !t.hostIsIp) return t.host;
  return undefined;
}

function rangeOf(t: Target): AddressRange | undefined {
  if (t.type === "address") return t.range;
  if (t.type === "url" && t.hostIsIp) return rangeOfIp(t.host);
  return undefined;
}

function covers(declared: Target, found: Target): boolean {
  const d = rangeOf(declared);
  const f = rangeOf(found);
  if (d && f) return rangeContains(d, f);
  const host = hostOf(declared);
  return host !== undefined && host === hostOf(found);
}

/**
 * Returns the found targets not covered by any declared one. A found target is covered when it
 * is declared or falls inside something declared (an IP inside a declared CIDR, a URL or
 * host:port on a declared host).
 */
export function undeclaredTargets(found: string[], declared: string[]): string[] {
  const parsed = declared.map((d) => parseTarget(d));
  return found.filter((token) => {
    let target: Target;
    try {
      target = parseTarget(token);
    } catch {
      return true;
    }
    return !parsed.some((d) => covers(d, target));
  });
}
