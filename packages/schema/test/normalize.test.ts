import { describe, expect, it } from "vitest";
import {
  apexOf,
  NormalizationError,
  normalizeFqdn,
  normalizeIp,
  normalizeOrigin,
  pathTemplate,
} from "../src/index.js";

describe("normalizeIp", () => {
  it("strips leading zeros from IPv4", () => {
    expect(normalizeIp(" 010.000.000.005 ")).toBe("10.0.0.5");
  });

  it("compresses IPv6 per RFC 5952", () => {
    expect(normalizeIp("2001:0DB8:0000:0000:0000:0000:0000:0001")).toBe("2001:db8::1");
    expect(normalizeIp("[::1]")).toBe("::1");
  });

  it("rejects invalid addresses", () => {
    expect(() => normalizeIp("256.1.1.1")).toThrow(NormalizationError);
    expect(() => normalizeIp("app.cliente.example")).toThrow(NormalizationError);
    expect(() => normalizeIp("fe80::1%eth0")).toThrow(NormalizationError);
  });
});

describe("normalizeFqdn", () => {
  it("lowercases and drops the trailing dot", () => {
    expect(normalizeFqdn("App.Cliente.EXAMPLE.")).toBe("app.cliente.example");
  });

  it("converts IDN to punycode", () => {
    expect(normalizeFqdn("pañales.example")).toBe("xn--paales-xwa.example");
  });

  it("accepts underscores used by DNS records", () => {
    expect(normalizeFqdn("_dmarc.cliente.example")).toBe("_dmarc.cliente.example");
  });

  it("rejects IPs, ports, paths and garbage", () => {
    for (const bad of ["10.0.0.5", "app.cliente.example:443", "cliente.example/x", "", "a..b"]) {
      expect(() => normalizeFqdn(bad), bad).toThrow(NormalizationError);
    }
  });
});

describe("apexOf", () => {
  it("uses the public suffix list", () => {
    expect(apexOf("a.b.example.co.uk")).toBe("example.co.uk");
    expect(apexOf("app.cliente.example")).toBe("cliente.example");
  });
});

describe("normalizeOrigin", () => {
  it("makes the port explicit", () => {
    expect(normalizeOrigin("https://App.Cliente.Example/login?x=1")).toBe("https://app.cliente.example:443");
    expect(normalizeOrigin("http://app.cliente.example:8080")).toBe("http://app.cliente.example:8080");
  });

  it("brackets IPv6 hosts", () => {
    expect(normalizeOrigin("http://[2001:db8::0001]/")).toBe("http://[2001:db8::1]:80");
  });

  it("rejects non-web schemes", () => {
    expect(() => normalizeOrigin("ftp://cliente.example")).toThrow(NormalizationError);
  });
});

describe("pathTemplate", () => {
  it.each([
    ["/api/users/1001", "/api/users/{id}"],
    ["/api/users/1002/", "/api/users/{id}"],
    ["/orders/3f2b8c1e-9a7d-4e2b-8f1a-2c3d4e5f6a7b/items", "/orders/{uuid}/items"],
    ["/objects/507f1f77bcf86cd799439011", "/objects/{hex}"],
    ["/reset/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "/reset/{token}"],
    ["/search?q=1#top", "/search"],
    ["about", "/about"],
    ["/", "/"],
    ["/api/v2/users", "/api/v2/users"],
  ])("%s → %s", (input, expected) => {
    expect(pathTemplate(input)).toBe(expected);
  });
});
