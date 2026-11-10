import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PluginManifest } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PANEL_CSP, PANEL_LIMITS, PanelTickets } from "../src/index.js";

/**
 * Panels of code plugins: served with a ticket, a policy that forbids
 * any network, and a bridge that is the only way out of the frame.
 */

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-panels-"));
  mkdirSync(join(dir, "plugin"), { recursive: true });
  writeFileSync(join(dir, "plugin", "panel.html"), "<!doctype html><html><head><title>P</title></head><body><div id=x></div></body></html>");
  writeFileSync(join(dir, "secret.txt"), "operator's file");
});
afterEach(() => {
  vi.useRealTimers();
  rmSync(dir, { recursive: true, force: true });
});

describe("panel tickets", () => {
  it("serve the page with no network allowed and the bridge first in its head", () => {
    const tickets = new PanelTickets();
    const ticket = tickets.issue("lab.p", "main", join(dir, "plugin"), "panel.html", { entityId: "E1", kind: "host" });
    const page = tickets.serve(ticket);
    expect(page.status).toBe(200);
    expect(page.headers["content-security-policy"]).toBe(PANEL_CSP);
    expect(PANEL_CSP).toMatch(/default-src 'none'/);
    expect(PANEL_CSP).not.toMatch(/connect-src/);
    expect(page.body.indexOf("window,\"penteos\"")).toBeGreaterThan(page.body.indexOf("<head>"));
    expect(page.body.indexOf("window,\"penteos\"")).toBeLessThan(page.body.indexOf("<title>"));
    expect(page.body).toContain('"plugin":"lab.p"');
    expect(page.body).toContain('"entityId":"E1"');
  });

  it("refuse files outside the plugin folder, through .. or a link", () => {
    const tickets = new PanelTickets();
    expect(() => tickets.issue("lab.p", "x", join(dir, "plugin"), "../secret.txt", {})).toThrow(/not a file inside the plugin folder/);
    symlinkSync(join(dir, "secret.txt"), join(dir, "plugin", "link.html"));
    expect(() => tickets.issue("lab.p", "x", join(dir, "plugin"), "link.html", {})).toThrow(/not a file inside the plugin folder/);
  });

  it("expire, and unknown or malformed tickets get nothing", () => {
    vi.useFakeTimers();
    const tickets = new PanelTickets();
    const ticket = tickets.issue("lab.p", "main", join(dir, "plugin"), "panel.html", {});
    expect(tickets.serve("nope").status).toBe(404);
    expect(tickets.serve("../../etc/passwd").status).toBe(404);
    vi.advanceTimersByTime(PANEL_LIMITS.ticketMs + 1);
    expect(tickets.serve(ticket).status).toBe(404);
  });

  it("context cannot break out of the bridge script", () => {
    const tickets = new PanelTickets();
    const ticket = tickets.issue("lab.p", "main", join(dir, "plugin"), "panel.html", { kind: "</script><script>alert(1)</script>" });
    expect(tickets.serve(ticket).body).not.toContain("</script><script>alert(1)");
  });
});

describe("the manifest", () => {
  const base = { id: "lab.p", name: "P", version: "1.0.0", apiVersion: 1, author: { type: "human" } };
  const issues = (m: Record<string, unknown>) => {
    const r = PluginManifest.safeParse({ ...base, ...m });
    return r.success ? "" : r.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(" | ");
  };
  it("only code plugins with ui:panel have panels, inside their folder", () => {
    expect(issues({ level: "declarative", permissions: ["ui:panel"], contributes: { panels: [{ id: "main", title: "Main", file: "panel.html" }] } })).toMatch(/only code plugins have them/);
    expect(issues({ level: "code", main: "main.mjs", permissions: [], contributes: { panels: [{ id: "main", title: "Main", file: "panel.html" }] } })).toMatch(/ui:panel permission/);
    expect(issues({ level: "code", main: "main.mjs", permissions: ["ui:panel"], contributes: { panels: [{ id: "main", title: "Main", file: "../x.html" }] } })).toMatch(/inside the plugin folder/);
    expect(issues({ level: "code", main: "../main.mjs", permissions: [] })).toMatch(/inside the plugin folder/);
    expect(issues({ level: "code", main: "main.mjs", permissions: ["ui:panel"], contributes: { panels: [{ id: "main", title: "Main", file: "panel.html" }] } })).toBe("");
  });
});
