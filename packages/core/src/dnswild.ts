import { Resolver } from "node:dns/promises";
import { randomBytes } from "node:crypto";

/**
 * Wildcard DNS: with *.zone defined, every name resolves, so brute-forcing
 * subdomains "finds" everything in the wordlist. Before a DNS brute force, Penteos resolves two
 * random names in the zone; if both answer, whatever answers exactly like them is the wildcard, not
 * a host, and never reaches the graph.
 */

export type WildcardAnswers = Map<string, Set<string>>;

async function answers(resolver: Resolver, name: string): Promise<string[]> {
  const out: string[] = [];
  for (const query of [() => resolver.resolve4(name), () => resolver.resolve6(name), () => resolver.resolveCname(name)]) {
    try {
      out.push(...(await query()).map((v) => v.toLowerCase().replace(/\.$/, "")));
    } catch {
      /* no such record */
    }
  }
  return out;
}

/** For each zone with a wildcard, what the wildcard answers. Zones without one are left out. */
export async function detectWildcards(zones: string[], timeoutMs = 4000): Promise<WildcardAnswers> {
  const found: WildcardAnswers = new Map();
  const resolver = new Resolver({ timeout: timeoutMs, tries: 1 });
  for (const zone of [...new Set(zones.map((z) => z.toLowerCase().replace(/^\*\./, "").replace(/\.$/, "")))]) {
    if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(zone)) continue;
    const probe = () => `penteos-${randomBytes(6).toString("hex")}.${zone}`;
    const [a, b] = await Promise.all([answers(resolver, probe()), answers(resolver, probe())]);
    if (a.length && b.length) found.set(zone, new Set([...a, ...b]));
  }
  return found;
}

type Item = Record<string, unknown> & { op: string };
const fqdnOf = (ref: unknown) => String((ref as { key?: { fqdn?: string } } | undefined)?.key?.fqdn ?? "").toLowerCase();

/**
 * Drops the names that answer exactly like their zone's wildcard (and their records), and leaves
 * one observation per zone saying how many were dropped and why.
 */
export function dropWildcardNames<T extends { items: unknown[] }>(batch: T, wild: WildcardAnswers): { batch: T; dropped: number } {
  if (!wild.size) return { batch, dropped: 0 };
  const items = batch.items as Item[];
  const zoneOf = (name: string) => [...wild.keys()].find((z) => name.endsWith(`.${z}`));
  // What each name answered, from its records in this batch.
  const seen = new Map<string, string[]>();
  for (const it of items) {
    if (it.op !== "relate" || (it.type !== "resolves_to" && it.type !== "alias_of")) continue;
    const name = fqdnOf(it.from);
    const to = it.to as { key?: { ip?: string; fqdn?: string } };
    const value = String(to.key?.ip ?? to.key?.fqdn ?? "").toLowerCase();
    if (name && value) seen.set(name, [...(seen.get(name) ?? []), value]);
  }
  const fake = new Set<string>();
  for (const [name, values] of seen) {
    const zone = zoneOf(name);
    if (zone && values.every((v) => wild.get(zone)!.has(v))) fake.add(name);
  }
  if (!fake.size) return { batch, dropped: 0 };
  const kept = items.filter((it) => {
    if (it.op === "upsert" && it.kind === "domain") return !fake.has(fqdnOf(it));
    if (it.op === "relate") return !fake.has(fqdnOf(it.from));
    return true;
  });
  for (const zone of wild.keys()) {
    const n = [...fake].filter((name) => name.endsWith(`.${zone}`)).length;
    if (!n) continue;
    kept.push({
      op: "observe",
      title: `Wildcard DNS on *.${zone}: ${n} brute-forced names dropped`,
      sourceRule: "dns:wildcard",
      affects: [{ kind: "domain", key: { fqdn: zone } }],
      severityHint: "info",
      detail: `Random names under ${zone} resolve (to ${[...wild.get(zone)!].slice(0, 6).join(", ")}), so a wordlist "finds" every name. ${n} names that answered exactly like the wildcard were not recorded as hosts; one of them could still exist, but DNS alone cannot tell it apart. Names with their own records were kept.`,
    });
  }
  return { batch: { ...batch, items: kept }, dropped: fake.size };
}
