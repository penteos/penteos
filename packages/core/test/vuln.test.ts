import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { vuln } from "../src/index.js";
import { Feeds, type Net } from "../src/vuln/net.js";
import { compareVersions, epssEnricher, euvdEnricher, exploitDbEnricher, kevEnricher, metasploitEnricher, nvdFinder, osvFinder, toCpe23, wordfenceFinder, wpVulnerabilityFinder } from "../src/vuln/providers.js";
import type { Enricher, Finder } from "../src/vuln/types.js";

/** The vulnerability engine ranks by real-world signal and parses each source; network is faked. */

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-vuln-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

/** A Net that answers from a table of url-substring → value. */
function fakeNet(routes: Array<[RegExp, unknown]>): Net {
  const pick = (url: string) => {
    const hit = routes.find(([re]) => re.test(url));
    if (!hit) throw new Error(`no fixture for ${url}`);
    return hit[1];
  };
  return {
    async json<T>(url: string) {
      return pick(url) as T;
    },
    async text(url: string) {
      const v = pick(url);
      return typeof v === "string" ? v : JSON.stringify(v);
    },
  };
}

// --- ranking ---------------------------------------------------------------------------------

it("ranks exploited-in-the-wild above a higher CVSS with no exploitation signal", async () => {
  const finder: Finder = {
    name: "f",
    available: () => true,
    find: async () => [
      { id: "CVE-2024-0001", cvss: { version: "3.1", score: 9.8 }, source: "f" },
      { id: "CVE-2024-0002", cvss: { version: "3.1", score: 7.5 }, source: "f" },
    ],
  };
  const kev: Enricher = { name: "kev", enrich: async (ids) => new Map(ids.includes("CVE-2024-0002") ? [["CVE-2024-0002", { kev: true }]] : []) };
  const epss: Enricher = { name: "epss", enrich: async () => new Map([["CVE-2024-0001", { epss: 0.02 }]]) };
  const r = await vuln.lookup({ product: "x", version: "1" }, [finder], [kev, epss]);
  expect(r.matches[0]!.id).toBe("CVE-2024-0002");
  expect(r.matches[0]!.kev).toBe(true);
  expect(r.matches[0]!.why).toMatch(/exploited in the wild/);
  expect(r.used).toEqual(expect.arrayContaining(["f", "kev", "epss"]));
});

it("tiers matches fire/smoke/ice by exploitation signal, and a suspected backport caps fire at smoke", () => {
  expect(vuln.tierOf({ id: "a", source: "nvd", sources: [], rank: 0, why: "", kev: true, cvss: { version: "3.1", score: 5 } })).toBe("fire"); // KEV
  expect(vuln.tierOf({ id: "b", source: "nvd", sources: [], rank: 0, why: "", hasExploit: true, cvss: { version: "3.1", score: 4 } })).toBe("fire"); // public exploit
  expect(vuln.tierOf({ id: "c", source: "nvd", sources: [], rank: 0, why: "", cvss: { version: "3.1", score: 9.1 } })).toBe("fire"); // CVSS>=9
  expect(vuln.tierOf({ id: "d", source: "nvd", sources: [], rank: 0, why: "", cvss: { version: "3.1", score: 7.2 }, epss: 0.2 })).toBe("fire"); // EPSS+high
  expect(vuln.tierOf({ id: "e", source: "nvd", sources: [], rank: 0, why: "", cvss: { version: "3.1", score: 7.5 } })).toBe("smoke"); // high alone
  expect(vuln.tierOf({ id: "f", source: "nvd", sources: [], rank: 0, why: "", cvss: { version: "3.1", score: 5 } })).toBe("ice"); // cold
  expect(vuln.tierOf({ id: "g", source: "nvd", sources: [], rank: 0, why: "", kev: true, backportSuspect: true })).toBe("smoke"); // suspected backport caps fire
});

it("softens an upstream NVD range match to unknown/smoke when the host runs a known distro", async () => {
  const finder: Finder = {
    name: "NVD",
    available: () => true,
    find: async () => [{ id: "CVE-2024-9999", cvss: { version: "3.1", score: 9.8, vector: "AV:N" }, affected: "affected < 1.20", source: "NVD" }],
  };
  const withDistro = await vuln.lookup({ product: "nginx", version: "1.18.0", distro: "ubuntu" }, [finder], []);
  expect(withDistro.matches[0]!.backportSuspect).toBe(true);
  expect(withDistro.matches[0]!.tier).toBe("smoke"); // would be fire (CVSS 9.8) without the distro
  expect(withDistro.matches[0]!.applies).toBe("unknown");
  const noDistro = await vuln.lookup({ product: "nginx", version: "1.18.0" }, [finder], []);
  expect(noDistro.matches[0]!.backportSuspect).toBeUndefined();
  expect(noDistro.matches[0]!.tier).toBe("fire");
});

it("merges the same CVE reported by two finders and keeps both sources", async () => {
  const a: Finder = { name: "a", available: () => true, find: async () => [{ id: "CVE-2024-0003", cvss: { version: "3.1", score: 8 }, source: "a" }] };
  const b: Finder = { name: "b", available: () => true, find: async () => [{ id: "CVE-2024-0003", summary: "más detalle", references: ["https://x"], source: "b" }] };
  const r = await vuln.lookup({ product: "x" }, [a, b], []);
  expect(r.matches).toHaveLength(1);
  expect(r.matches[0]!.sources.sort()).toEqual(["a", "b"]);
  expect(r.matches[0]!.cvss?.score).toBe(8);
  expect(r.matches[0]!.summary).toBe("más detalle");
});

it("a finder that throws does not sink the lookup; it is reported as failed", async () => {
  const good: Finder = { name: "good", available: () => true, find: async () => [{ id: "CVE-2024-0004", source: "good" }] };
  const bad: Finder = { name: "bad", available: () => true, find: async () => { throw new Error("down"); } };
  const r = await vuln.lookup({ product: "x" }, [good, bad], []);
  expect(r.matches).toHaveLength(1);
  expect(r.failed).toEqual([{ name: "bad", error: "down" }]);
});

it("prefers the CVE alias as the id over a GHSA primary id", async () => {
  const f: Finder = { name: "f", available: () => true, find: async () => [{ id: "GHSA-aaaa-bbbb-cccc", aliases: ["CVE-2024-0005"], source: "f" }] };
  const r = await vuln.lookup({ product: "x" }, [f], []);
  expect(r.matches[0]!.id).toBe("CVE-2024-0005");
});

// --- applicability ---------------------------------------------------------------------------

it("marks a local-vector CVE as unlikely for remote testing, a network one as applies", async () => {
  const f: Finder = {
    name: "f",
    available: () => true,
    find: async () => [
      { id: "CVE-2024-0100", cvss: { version: "3.1", vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 7.8 }, source: "f" },
      { id: "CVE-2024-0101", cvss: { version: "3.1", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", score: 9.8 }, source: "f" },
    ],
  };
  const r = await vuln.lookup({ product: "x", version: "1.0" }, [f], []);
  const local = r.matches.find((m) => m.id === "CVE-2024-0100")!;
  const net = r.matches.find((m) => m.id === "CVE-2024-0101")!;
  expect(local.applies).toBe("unlikely");
  expect(local.applyReasons?.[0]).toMatch(/local attack vector/);
  expect(net.applies).toBe("yes");
});

it("marks a CVE already patched in the detected version as unlikely", async () => {
  const f: Finder = { name: "f", available: () => true, find: async () => [{ id: "CVE-2024-0102", affected: "fixed in 3.5.0", cvss: { version: "3.1", vector: "AV:N", score: 7 }, source: "f" }] };
  const patched = await vuln.lookup({ product: "x", version: "3.6.0" }, [f], []);
  expect(patched.matches[0]!.applies).toBe("unlikely");
  expect(patched.matches[0]!.applyReasons?.[0]).toMatch(/at or past the fixed version/);
  const vulnerable = await vuln.lookup({ product: "x", version: "3.4.0" }, [f], []);
  expect(vulnerable.matches[0]!.applies).toBe("yes");
});

it("notes when a CVE may need authentication without disqualifying it", async () => {
  const f: Finder = { name: "f", available: () => true, find: async () => [{ id: "CVE-2024-0103", summary: "Authenticated admin can upload a file", cvss: { version: "3.1", vector: "AV:N", score: 7.2 }, source: "f" }] };
  const r = await vuln.lookup({ product: "x", version: "1" }, [f], []);
  expect(r.matches[0]!.applies).toBe("yes");
  expect(r.matches[0]!.applyReasons).toContain("may need authentication");
});

// --- version compare -------------------------------------------------------------------------

it("compares dotted versions numerically", () => {
  expect(compareVersions("1.2.3", "1.2.10")).toBe(-1);
  expect(compareVersions("2.0", "2.0.0")).toBe(0);
  expect(compareVersions("6.1", "5.9")).toBe(1);
});

// --- providers (faked network) ---------------------------------------------------------------

it("OSV maps aliases, CVSS and the fixed range for a package", async () => {
  const net = fakeNet([
    [/api\.osv\.dev/, { vulns: [{ id: "GHSA-x", aliases: ["CVE-2024-1111"], summary: "proto pollution", severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/baseScore=9.1" }], affected: [{ ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }], references: [{ url: "https://a" }] }] }],
  ]);
  const got = await osvFinder(net).find({ product: "lodash", version: "4.17.0", ecosystem: "npm" });
  expect(got).toHaveLength(1);
  expect(got[0]!.id).toBe("CVE-2024-1111");
  expect(got[0]!.cvss?.score).toBe(9.1);
  expect(got[0]!.affected).toMatch(/4\.17\.21/);
});

it("OSV is skipped without an ecosystem", async () => {
  const got = await osvFinder(fakeNet([])).find({ product: "nginx", version: "1.0" });
  expect(got).toEqual([]);
});

it("Wordfence matches a plugin by slug and version range", async () => {
  const feed = {
    "uuid-1": { id: "wf1", title: "Elementor XSS", cve: "CVE-2024-2222", cvss: { score: 6.4 }, references: ["https://wf"], software: [{ type: "plugin", slug: "elementor", affected_versions: { r1: { from_version: "3.0.0", from_inclusive: true, to_version: "3.5.0", to_inclusive: false } } }] },
    "uuid-2": { id: "wf2", title: "Otro plugin", cve: "CVE-2024-3333", software: [{ type: "plugin", slug: "akismet", affected_versions: { r1: { from_version: "1.0", to_version: "2.0" } } }] },
  };
  const net = fakeNet([[/wordfence\.com/, feed]]);
  const finder = wordfenceFinder(new Feeds(dir, net), "test-key");
  const hit = await finder.find({ product: "elementor", version: "3.2.0", ecosystem: "WordPress" });
  expect(hit.map((v) => v.id)).toEqual(["CVE-2024-2222"]);
  const miss = await finder.find({ product: "elementor", version: "3.6.0", ecosystem: "WordPress" });
  expect(miss).toEqual([]);
});

it("converts an nmap CPE 2.2 URI to an NVD 2.3 match string", () => {
  expect(toCpe23("cpe:/a:openbsd:openssh:8.2p1")).toBe("cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*");
  expect(toCpe23("cpe:/a:nginx:nginx")).toBe("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*");
  expect(toCpe23("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*")).toBe("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*");
});

it("NVD matches only CVEs whose range includes the detected version; skipped without a CPE or version", async () => {
  const crit = "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*";
  const nvd = {
    vulnerabilities: [
      // Applies: 1.18.0 is below the fixed 1.20.1.
      { cve: { id: "CVE-2021-1234", descriptions: [{ lang: "en", value: "nginx buffer overflow" }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, vectorString: "CVSS:3.1/AV:N/AC:L", version: "3.1" } }] }, references: [{ url: "https://n" }], configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: crit, versionEndExcluding: "1.20.1" }] }] }] } },
      // Old CVE, already fixed long before 1.18.0 - must be excluded (the bug we just fixed).
      { cve: { id: "CVE-2013-0001", descriptions: [{ lang: "en", value: "old nginx issue" }], configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: crit, versionEndExcluding: "1.4.1" }] }] }] } },
    ],
  };
  const net = fakeNet([[/services\.nvd\.nist\.gov/, nvd]]);
  const got = await nvdFinder(net).find({ product: "nginx", version: "1.18.0", cpe: "cpe:/a:nginx:nginx:1.18.0" });
  expect(got.map((v) => v.id)).toEqual(["CVE-2021-1234"]);
  expect(got[0]!.affected).toMatch(/1\.20\.1/);
  // No CPE, or a CPE with no usable version: NVD stays out (other sources cover it).
  expect(await nvdFinder(net).find({ product: "nginx", version: "1.18.0" })).toEqual([]);
  expect(await nvdFinder(net).find({ product: "nginx", cpe: "cpe:/a:nginx:nginx" })).toEqual([]);
});

it("WPVulnerability finds a WordPress plugin vuln in range, with its CVE and CVSS (no key)", async () => {
  const feed = {
    data: {
      vulnerability: [
        { uuid: "u1", name: "Elementor < 3.6.3 XSS", operator: { max_version: "3.6.3", max_operator: "lt" }, source: [{ id: "CVE-2021-24891", link: "https://cve" }], impact: { cvss: { version: "3.1", vector: "AV:N", score: "6.1" } } },
        { uuid: "u2", name: "Elementor < 3.0.0 (old)", operator: { max_version: "3.0.0", max_operator: "lt" }, source: [{ id: "CVE-2020-0001" }] },
      ],
    },
  };
  const net = fakeNet([[/wpvulnerability\.net\/plugin\/elementor/, feed]]);
  const finder = wpVulnerabilityFinder(net);
  const hit = await finder.find({ product: "elementor", version: "3.2.0", ecosystem: "WordPress" });
  expect(hit.map((v) => v.id)).toEqual(["CVE-2021-24891"]); // 3.2.0 < 3.6.3 but not < 3.0.0
  expect(hit[0]!.cvss?.score).toBe(6.1);
  expect(hit[0]!.affected).toMatch(/3\.6\.3/);
  // Without a WordPress ecosystem it is not queried.
  expect(await finder.find({ product: "elementor", version: "3.2.0" })).toEqual([]);
});

it("KEV flags a CVE present in the catalog, with its due date", async () => {
  const net = fakeNet([[/known_exploited/, { vulnerabilities: [{ cveID: "CVE-2024-2222", dueDate: "2024-12-01" }] }]]);
  const got = await kevEnricher(new Feeds(dir, net)).enrich(["CVE-2024-2222", "CVE-2024-9999"]);
  expect(got.get("CVE-2024-2222")).toEqual({ kev: true, kevDueDate: "2024-12-01" });
  expect(got.has("CVE-2024-9999")).toBe(false);
});

it("EPSS attaches the probability for the queried CVEs", async () => {
  const net = fakeNet([[/first\.org/, { data: [{ cve: "CVE-2024-2222", epss: "0.42" }] }]]);
  const got = await epssEnricher(net).enrich(["CVE-2024-2222"]);
  expect(got.get("CVE-2024-2222")?.epss).toBeCloseTo(0.42);
});

it("ExploitDB marks CVEs that have a public exploit from the CSV index", async () => {
  const csv = ["id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url", '50123,exploits/php/webapps/50123.py,"Elementor RCE",2024-01-01,x,webapps,php,,,,1,CVE-2024-2222;CVE-2024-0000,,,,,'].join("\n");
  const net = fakeNet([[/files_exploits\.csv/, csv]]);
  const got = await exploitDbEnricher(new Feeds(dir, net)).enrich(["CVE-2024-2222"]);
  expect(got.get("CVE-2024-2222")?.hasExploit).toBe(true);
  expect(got.get("CVE-2024-2222")?.exploitRefs?.[0]).toMatch(/exploit-db\.com\/exploits\/50123/);
});

it("Metasploit marks CVEs that have a weaponised module from the module metadata", async () => {
  const meta = JSON.stringify({
    "exploit/x": { fullname: "exploit/multi/http/elementor_rce", references: ["CVE-2024-2222", "URL-https://x"] },
    "aux/y": { fullname: "auxiliary/scanner/other", references: ["CVE-1999-0001"] },
  });
  const net = fakeNet([[/modules_metadata_base\.json/, meta]]);
  const got = await metasploitEnricher(new Feeds(dir, net)).enrich(["CVE-2024-2222", "CVE-2024-3333"]);
  expect(got.get("CVE-2024-2222")?.hasExploit).toBe(true);
  expect(got.get("CVE-2024-2222")?.exploitRefs?.[0]).toMatch(/Metasploit: exploit\/multi\/http\/elementor_rce/);
  expect(got.has("CVE-2024-3333")).toBe(false);
});

it("EUVD marks CVEs on ENISA's EU exploited list", async () => {
  const rows = JSON.stringify([{ id: "EUVD-2024-1", aliases: "CVE-2024-2222\nGHSA-aaaa" }, { id: "EUVD-2024-2", aliases: "CVE-2024-0000" }]);
  const net = fakeNet([[/exploitedvulnerabilities/, rows]]);
  const got = await euvdEnricher(new Feeds(dir, net)).enrich(["CVE-2024-2222", "CVE-2024-9999"]);
  expect(got.get("CVE-2024-2222")?.kev).toBe(true);
  expect(got.has("CVE-2024-9999")).toBe(false);
});

it("a feed falls back to its cached copy when the network fails", async () => {
  let fail = false;
  const net: Net = {
    async json() { throw new Error("n/a"); },
    async text() {
      if (fail) throw new Error("offline");
      return "v1";
    },
  };
  const feeds = new Feeds(dir, net);
  // ttl 0 forces a fetch each time, so the second call really hits the network (and fails).
  const first = await feeds.get("probe", 0, (n) => n.text("http://x"), (r) => r);
  expect(first.data).toBe("v1");
  fail = true;
  const second = await feeds.get("probe", 0, (n) => n.text("http://x"), (r) => r);
  expect(second.data).toBe("v1");
  expect(second.cached).toBe(true);
  expect(second.asOf).toBe(first.asOf);
});
