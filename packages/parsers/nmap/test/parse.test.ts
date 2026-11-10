import { readFileSync } from "node:fs";
import { IngestBatch } from "@penteos/schema";
import { describe, expect, it } from "vitest";
import { parseNmapXml } from "../src/index.js";

const fixture = readFileSync(new URL("./fixtures/service-scan.xml", import.meta.url), "utf8");
const raw = `sha256:${"a".repeat(64)}`;

describe("parseNmapXml", () => {
  const batch = parseNmapXml(fixture, { rawIds: [raw] });

  it("produces a valid ingest batch", () => {
    expect(IngestBatch.safeParse(batch).success).toBe(true);
    expect(batch.source).toEqual({ parser: "nmap-xml@0.1.0", tool: "nmap", toolVersion: "7.95" });
    expect(batch.observedAt).toBe("2026-10-13T14:32:05.000Z");
  });

  it("extracts the host with hostnames and OS guess", () => {
    expect(batch.items[0]).toEqual({
      op: "upsert",
      kind: "host",
      key: { ip: "203.0.113.10" },
      attributes: {
        status: "up",
        hostnames: ["app.cliente.example", "web-01.hosting.example.net"],
        os: { name: "Linux 5.0 - 6.2", confidence: 0.95 },
      },
      confidence: 1,
    });
  });

  it("only links the user-supplied name as resolving to the host", () => {
    const relations = batch.items.filter((i) => i.op === "relate" && i.type === "resolves_to");
    expect(relations).toHaveLength(1);
    expect(relations[0]).toMatchObject({ from: { key: { fqdn: "app.cliente.example" } } });
  });

  it("extracts services, folding https into http + tls", () => {
    const services = batch.items.filter((i) => i.op === "upsert" && i.kind === "service");
    expect(services.map((s) => s.op === "upsert" && s.key.port)).toEqual([22, 80, 443, 8080]);
    expect(services[2]).toMatchObject({
      attributes: { state: "open", protocol: "http", product: "nginx", version: "1.25.3", tls: true },
      confidence: 1,
    });
    expect(services[0]).toMatchObject({
      // The application CPE is kept (preferred over the OS one), as the key for vulnerability matching.
      attributes: { product: "OpenSSH", version: "9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)", cpe: "cpe:/a:openbsd:openssh:9.6p1" },
    });
    expect(services[3]).toMatchObject({ attributes: { state: "filtered" }, confidence: 0.3 });
  });

  it("rejects documents that are not nmap XML", () => {
    expect(() => parseNmapXml("<html></html>", { rawIds: [raw] })).toThrow(/nmaprun/);
  });
});
