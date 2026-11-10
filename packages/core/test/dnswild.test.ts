import { expect, it } from "vitest";
import { dropWildcardNames } from "../src/dnswild.js";

/** A DNS brute force over a wildcard zone: only the names with their own records survive. */

const upsert = (fqdn: string) => ({ op: "upsert", kind: "domain", key: { fqdn } });
const a = (fqdn: string, ip: string) => ({ op: "relate", type: "resolves_to", from: { kind: "domain", key: { fqdn } }, to: { kind: "host", key: { ip } } });

it("drops names that answer exactly like the wildcard and says so once", () => {
  const wild = new Map([["shop.test", new Set(["104.21.1.1", "172.67.1.1"])]]);
  const batch = {
    items: [
      upsert("admin.shop.test"), a("admin.shop.test", "104.21.1.1"), a("admin.shop.test", "172.67.1.1"),
      upsert("ftp.shop.test"), a("ftp.shop.test", "104.21.1.1"),
      upsert("portal-da41.shop.test"), a("portal-da41.shop.test", "203.0.113.7"),
      upsert("other.lab"), a("other.lab", "104.21.1.1"),
    ],
  };
  const { batch: out, dropped } = dropWildcardNames(batch, wild);
  expect(dropped).toBe(2);
  const names = out.items.filter((i) => (i as { op: string }).op === "upsert").map((i) => (i as { key: { fqdn: string } }).key.fqdn);
  expect(names).toEqual(["portal-da41.shop.test", "other.lab"]);
  const obs = out.items.filter((i) => (i as { op: string }).op === "observe");
  expect(obs).toHaveLength(1);
  expect(obs[0]).toMatchObject({ sourceRule: "dns:wildcard", title: expect.stringContaining("2 brute-forced names") });
});

it("leaves everything alone without a wildcard", () => {
  const batch = { items: [upsert("a.lab"), a("a.lab", "10.0.0.1")] };
  expect(dropWildcardNames(batch, new Map()).dropped).toBe(0);
});
