import { describe, expect, it } from "vitest";
import {
  ENTITY_ATTRIBUTES,
  fieldClass,
  IngestBatch,
  isEdgeAllowed,
  naturalKeyFor,
  NormalizationError,
  ulid,
  Ulid,
} from "../src/index.js";

describe("naturalKeyFor", () => {
  it("scopes hosts by network context", () => {
    expect(naturalKeyFor("host", { ip: "10.0.0.5" })).toBe("default|10.0.0.5");
    expect(naturalKeyFor("host", { ip: "10.0.0.5", networkContext: "corp-lan" })).toBe("corp-lan|10.0.0.5");
    expect(naturalKeyFor("host", { ip: "10.0.0.5" }, "dmz")).toBe("dmz|10.0.0.5");
  });

  it("builds service keys on top of host keys", () => {
    expect(naturalKeyFor("service", { ip: "203.0.113.10", transport: "TCP", port: 443 })).toBe(
      "default|203.0.113.10|tcp|443",
    );
  });

  it("templates endpoints and includes the operation for single-route APIs", () => {
    expect(naturalKeyFor("endpoint", { origin: "https://app.cliente.example", path: "/api/users/7" })).toBe(
      "https://app.cliente.example:443|/api/users/{id}|",
    );
    expect(
      naturalKeyFor("endpoint", { origin: "https://app.cliente.example", path: "/graphql", operation: "query:GetUser" }),
    ).toBe("https://app.cliente.example:443|/graphql|query:GetUser");
  });

  it("treats directory realms case-insensitively and web realms as-is", () => {
    expect(naturalKeyFor("principal", { realm: "corp.local", name: "JDoe" })).toBe("CORP.LOCAL|jdoe");
    expect(naturalKeyFor("principal", { realm: "https://app.cliente.example", name: "JDoe" })).toBe(
      "https://app.cliente.example|JDoe",
    );
  });

  it("rejects missing fields and unkeyed kinds", () => {
    expect(() => naturalKeyFor("service", { ip: "10.0.0.5", transport: "tcp" })).toThrow(NormalizationError);
    expect(() => naturalKeyFor("service", { ip: "10.0.0.5", transport: "sctp", port: 1 })).toThrow(NormalizationError);
    expect(() => naturalKeyFor("finding", { title: "x" })).toThrow(NormalizationError);
  });
});

describe("IngestBatch", () => {
  // The example from
  const raw = `sha256:${"9f2c".padEnd(64, "0")}`;
  const batch = {
    format: "penteos.ingest/v0",
    source: { parser: "nmap-xml@1.0.0", tool: "nmap", toolVersion: "7.95" },
    rawIds: [raw],
    observedAt: "2026-10-13T14:32:05Z",
    items: [
      { op: "upsert", kind: "host", key: { ip: "203.0.113.10" }, attributes: { status: "up" }, confidence: 1 },
      { op: "upsert", kind: "domain", key: { fqdn: "app.cliente.example" } },
      {
        op: "relate",
        type: "resolves_to",
        from: { kind: "domain", key: { fqdn: "app.cliente.example" } },
        to: { kind: "host", key: { ip: "203.0.113.10" } },
      },
      {
        op: "upsert",
        kind: "service",
        key: { ip: "203.0.113.10", transport: "tcp", port: 443 },
        attributes: { state: "open", product: "nginx", version: "1.25.3" },
        confidence: 0.95,
      },
    ],
  };

  it("accepts the documented example", () => {
    expect(IngestBatch.safeParse(batch).success).toBe(true);
  });

  it("rejects unknown ops, bad parser ids and out-of-range confidence", () => {
    expect(IngestBatch.safeParse({ ...batch, items: [{ op: "delete", kind: "host", key: {} }] }).success).toBe(false);
    expect(IngestBatch.safeParse({ ...batch, source: { parser: "nmap" } }).success).toBe(false);
    expect(
      IngestBatch.safeParse({ ...batch, items: [{ op: "upsert", kind: "host", key: { ip: "1.1.1.1" }, confidence: 2 }] })
        .success,
    ).toBe(false);
  });
});

describe("graph catalog", () => {
  it("restricts edge endpoints", () => {
    expect(isEdgeAllowed("runs_on", "service", "host")).toBe(true);
    expect(isEdgeAllowed("runs_on", "host", "service")).toBe(false);
    expect(isEdgeAllowed("valid_on", "credential", "webapp")).toBe(true);
    expect(isEdgeAllowed("related_to", "note", "finding")).toBe(true);
  });

  it("classifies fields for merge", () => {
    expect(fieldClass("service", "state")).toBe("volatile");
    expect(fieldClass("service", "version")).toBe("descriptive");
    expect(fieldClass("principal", "sid")).toBe("identity");
  });

  it("applies attribute defaults", () => {
    const finding = ENTITY_ATTRIBUTES.finding.parse({ title: "IDOR en /api/users/{id}", severity: "high" });
    expect(finding.status).toBe("draft");
    expect(finding.instances).toEqual([]);
  });
});

describe("ulid", () => {
  it("generates valid, time-ordered ids", () => {
    const a = ulid(1_700_000_000_000);
    const b = ulid(1_700_000_000_001);
    expect(Ulid.safeParse(a).success).toBe(true);
    expect(a < b).toBe(true);
  });
});
