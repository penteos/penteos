import { describe, expect, it } from "vitest";
import { harvestScript, mergeHarvests, scriptUrls } from "../src/webjs.js";

/** What a web application leaks in its own JavaScript, pulled apart cleanly from the noise. */

const BUNDLE = [
  'const API = "https://backend3.acmecorp.test";',
  'fetch(`/api/tenants/public/${slug}`);',
  'axios.get("/api/auth/me");',
  'const admin = "/admin/users/" + id;',
  'const routes = [{ path: "/portal/pedidos" }, { path: "admin/documentos/:id" }];',
  'const staging = "https://api-staging.acmecorp.test/v1/internal";',
  'const key = { apiKey: "AKIAIOSFODNN7EXAMPLE", publicStuff: "/assets/app.4f2c.js" };',
  // Split so secret scanners don't flag the fixture itself.
  'const stripe = "sk_' + 'live_51H8zX2abcdefghijklmnop";',
  'loadFont("https://fonts.googleapis.com/css2?family=Inter");',
  "//# source" + "MappingURL=index.4f2c.js.map",
].join("\n");

describe("harvesting one script", () => {
  const h = harvestScript(BUNDLE);

  it("finds the API endpoints, relative and absolute, with templates normalized", () => {
    const paths = h.endpoints.map((e) => e.path);
    expect(paths).toContain("/api/tenants/public/:id");
    expect(paths).toContain("/api/auth/me");
    expect(paths).toContain("/admin/users/");
    expect(h.endpoints.find((e) => e.path === "/v1/internal")?.origin).toBe("https://api-staging.acmecorp.test");
    // Static assets are not endpoints.
    expect(paths.some((p) => p.endsWith(".js"))).toBe(false);
  });

  it("names the other-environment hosts, and skips CDNs and font providers", () => {
    expect(h.hosts).toContain("backend3.acmecorp.test");
    expect(h.hosts).toContain("api-staging.acmecorp.test");
    expect(h.hosts.some((x) => x.includes("googleapis"))).toBe(false);
  });

  it("collects SPA routes", () => {
    expect(h.routes).toContain("/portal/pedidos");
    expect(h.routes).toContain("/admin/documentos/:id");
  });

  it("flags only high-signal secrets and the source map", () => {
    const kinds = h.secrets.map((s) => s.kind);
    expect(kinds).toContain("AWS access key id");
    expect(kinds).toContain("Stripe live key");
    expect(h.secrets.some((s) => s.kind === "hardcoded secret" && s.value === "AKIAIOSFODNN7EXAMPLE")).toBe(true);
    expect(h.sourceMaps).toContain("index.4f2c.js.map");
  });
});

it("ignores placeholders and repeated-char junk", () => {
  const h = harvestScript(`const a = { apiKey: "your-api-key-here" }; const b = "sk_${"live"}_xxxxxxxxxxxxxxxxxxxx"; const c = "AKIAAAAAAAAAAAAAAAAA";`);
  expect(h.secrets.filter((s) => /your|placeholder/i.test(s.value))).toHaveLength(0);
});

it("reads script and preload URLs from an HTML page, resolved against it", () => {
  const html = `<html><head>
    <link rel="modulepreload" href="/assets/index-abc.js">
    <script type="module" src="/assets/main-def.js"></script>
    <script src="https://cdn.example.com/vendor.js"></script>
  </head></html>`;
  const urls = scriptUrls(html, "https://app.acmecorp.test/");
  expect(urls).toContain("https://app.acmecorp.test/assets/main-def.js");
  expect(urls).toContain("https://app.acmecorp.test/assets/index-abc.js");
  expect(urls).toContain("https://cdn.example.com/vendor.js");
});

it("merges several scripts without duplicates", () => {
  const m = mergeHarvests([harvestScript(`fetch("/api/a")`), harvestScript(`fetch("/api/a"); fetch("/api/b")`)]);
  expect(m.endpoints.map((e) => e.path).sort()).toEqual(["/api/a", "/api/b"]);
});
