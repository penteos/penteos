import type { EntityKind } from "./entities.js";
import {
  DEFAULT_NETWORK_CONTEXT,
  NormalizationError,
  normalizeFqdn,
  normalizeIp,
  normalizeOrigin,
  pathTemplate,
} from "./normalize.js";

/** Natural-key fields as sent by parsers in an ingest item. */
export type KeyFields = Record<string, string | number>;

/** Entity kinds that parsers can address by natural key in v0. */
export const KEYED_KINDS = ["host", "domain", "service", "webapp", "endpoint", "technology", "principal"] as const;
export type KeyedKind = (typeof KEYED_KINDS)[number];

export function isKeyedKind(kind: EntityKind): kind is KeyedKind {
  return (KEYED_KINDS as readonly string[]).includes(kind);
}

function field(key: KeyFields, name: string, kind: string): string {
  const value = key[name];
  if (value === undefined || value === "") {
    throw new NormalizationError(`${kind} key is missing "${name}"`);
  }
  return String(value);
}

function hostKey(key: KeyFields, defaultContext: string): string {
  const context = key.networkContext === undefined ? defaultContext : String(key.networkContext);
  return `${context}|${normalizeIp(field(key, "ip", "host"))}`;
}

/** Windows/AD-style realms are case-insensitive; web, host-local and cloud realms are kept as-is. */
function isDirectoryRealm(realm: string): boolean {
  return !/^[a-z][a-z0-9+.-]*:/i.test(realm);
}

/**
 * Canonical natural key for an entity addressed by its real-world identity.
 * Throws NormalizationError on invalid input.
 */
export function naturalKeyFor(kind: EntityKind, key: KeyFields, defaultContext = DEFAULT_NETWORK_CONTEXT): string {
  switch (kind) {
    case "host":
      return hostKey(key, defaultContext);
    case "domain":
      return normalizeFqdn(field(key, "fqdn", kind));
    case "service": {
      const transport = field(key, "transport", kind).toLowerCase();
      if (transport !== "tcp" && transport !== "udp") throw new NormalizationError(`invalid transport: ${transport}`);
      const port = Number(field(key, "port", kind));
      if (!Number.isInteger(port) || port < 0 || port > 65535) throw new NormalizationError(`invalid port: ${key.port}`);
      return `${hostKey(key, defaultContext)}|${transport}|${port}`;
    }
    case "webapp":
      return normalizeOrigin(field(key, "origin", kind));
    case "endpoint": {
      const origin = normalizeOrigin(field(key, "origin", kind));
      const operation = key.operation === undefined ? "" : String(key.operation);
      return `${origin}|${pathTemplate(field(key, "path", kind))}|${operation}`;
    }
    case "technology": {
      // product + version, scoped to where it runs: the same product+version on the same origin
      // is one technology, wherever it was spotted.
      const where = field(key, "where", kind).trim().toLowerCase();
      const product = field(key, "product", kind).trim().toLowerCase();
      const version = key.version === undefined ? "" : String(key.version).trim();
      return `${where}|${product}|${version}`;
    }
    case "principal": {
      const realm = field(key, "realm", kind);
      const name = field(key, "name", kind);
      return isDirectoryRealm(realm) ? `${realm.toUpperCase()}|${name.toLowerCase()}` : `${realm}|${name}`;
    }
    default:
      throw new NormalizationError(`entities of kind "${kind}" cannot be addressed by natural key`);
  }
}
