import { describe, expect, it } from "vitest";
import { mailIssues, takeoverIssue } from "../src/dnscheck.js";

/** Mail spoofing and subdomain takeover, read from fixed records (no network in the tests). */
describe("mail spoofing defences", () => {
  const keys = (r: Parameters<typeof mailIssues>[0]) => mailIssues(r).map((i) => `${i.key}:${i.severity}`);
  it("the case of a real assessment: SPF ~all and DMARC p=none is spoofable", () => {
    expect(keys({ domain: "cliente.test", spf: "v=spf1 include:_spf.google.com ~all", spfCount: 1, dmarc: "v=DMARC1; p=none; rua=mailto:d@cliente.test", dkimSelectors: ["google"], mx: ["mx.cliente.test"] })).toEqual(["spf:softfail:low", "dmarc:none:medium"]);
  });
  it("missing records, +all, several SPF records, partial enforcement", () => {
    expect(keys({ domain: "a.test", spfCount: 0, dkimSelectors: [], mx: ["mx"] })).toEqual(["spf:missing:medium", "dmarc:missing:medium", "dkim:none-found:info"]);
    expect(keys({ domain: "a.test", spf: "v=spf1 +all", spfCount: 1, dmarc: "v=DMARC1; p=reject; rua=mailto:x", dkimSelectors: [], mx: [] })).toEqual(["spf:pass-all:high"]);
    expect(keys({ domain: "a.test", spf: "v=spf1 -all", spfCount: 2, dmarc: "v=DMARC1; p=quarantine; pct=20; rua=mailto:x", dkimSelectors: ["s1"], mx: ["mx"] })).toEqual(["spf:multiple:medium", "dmarc:pct:low"]);
  });
  it("a well-kept domain says nothing", () => {
    expect(keys({ domain: "a.test", spf: "v=spf1 include:x -all", spfCount: 1, dmarc: "v=DMARC1; p=reject; rua=mailto:x", dkimSelectors: ["google"], mx: ["mx"] })).toEqual([]);
  });
});

describe("subdomain takeover", () => {
  it("a CNAME to an unclaimed service is high; to a name that does not exist, medium; a healthy one, nothing", () => {
    expect(takeoverIssue({ name: "docs.cliente.test", cnames: ["cliente.github.io"], resolves: true, body: "<h1>404</h1> There isn't a GitHub Pages site here." })?.severity).toBe("high");
    expect(takeoverIssue({ name: "files.cliente.test", cnames: ["files-cliente.s3-website-us-east-1.amazonaws.com"], resolves: false })?.key).toBe("takeover:Amazon S3");
    expect(takeoverIssue({ name: "old.cliente.test", cnames: ["old-app.someplatform.example"], resolves: false })).toMatchObject({ key: "dangling-cname", severity: "medium" });
    expect(takeoverIssue({ name: "docs.cliente.test", cnames: ["cliente.github.io"], resolves: true, body: "<html>Docs</html>" })).toBeUndefined();
    expect(takeoverIssue({ name: "www.cliente.test", cnames: [], resolves: true })).toBeUndefined();
  });
});
