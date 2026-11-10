import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Engagement, executeOperation, FindingLibrary, type OperationContext, templateId, ToolRunner, Workspace } from "../src/index.js";

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let library: FindingLibrary;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-library-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Cliente", name: "Web", mode: "web" }, human);
  library = new FindingLibrary(join(dir, "library"));
});

afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

function ctx(actor: Actor): OperationContext {
  const runner = new ToolRunner(eng);
  return {
    workspace: ws,
    caller: { actor, policy: actor.type === "agent" ? { type: "agent", autonomy: "autonomous", maxRisk: "active" } : { type: "human" } },
    defaultEngagementId: eng.info.id,
    engagement: () => eng,
    runner: () => runner,
    library,
  };
}

describe("findings library", () => {
  it("ships common web findings and searches them", async () => {
    const all = (await executeOperation("library.list", {}, ctx(agent))) as Array<{ id: string }>;
    expect(all.length).toBeGreaterThanOrEqual(12);
    const cors = (await executeOperation("library.list", { query: "cors" }, ctx(agent))) as Array<{ id: string }>;
    expect(cors.map((t) => t.id)).toContain("permissive-cors");
  });

  it("creates a draft finding from a template, adapted to the case", async () => {
    const webapp = eng.ingest(
      { format: "penteos.ingest/v0", source: { parser: "test@1" }, rawIds: [], observedAt: "2026-10-13T10:00:00Z", items: [{ op: "upsert", kind: "webapp", key: { origin: "https://app.cliente.example" } }] },
      agent,
    );
    expect(webapp.created).toEqual({ webapp: 1 });
    const id = eng.findByKey("webapp", "https://app.cliente.example:443")!.id;
    const finding = (await executeOperation(
      "finding.from_template",
      { templateId: "version-disclosure", instances: [{ entityId: id }], title: "Divulgación de versión de nginx en app.cliente.example" },
      ctx(agent),
    )) as { attributes: Record<string, unknown> };
    expect(finding.attributes).toMatchObject({
      title: "Divulgación de versión de nginx en app.cliente.example",
      severity: "info",
      cwe: ["CWE-200"],
      status: "draft",
      templateRef: "version-disclosure",
    });
    expect(String(finding.attributes.remediation)).toContain("Server");
  });

  it("saves the organization's own templates as git-friendly files, overriding built-ins", async () => {
    await executeOperation("library.save", { template: { id: "version-disclosure", title: "Divulgación de versión (estilo de la casa)", severity: "low" } }, ctx(human));
    const t = (await executeOperation("library.get", { id: "version-disclosure" }, ctx(agent))) as { title: string };
    expect(t.title).toBe("Divulgación de versión (estilo de la casa)");
    expect(JSON.parse(readFileSync(join(dir, "library", "version-disclosure.json"), "utf8"))).toMatchObject({ severity: "low" });
    await expect(executeOperation("library.save", { template: { title: "x", severity: "low" } }, ctx(agent))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("derives readable ids", () => {
    expect(templateId("Divulgación de versión en CUPS!")).toBe("divulgacion-de-version-en-cups");
  });
});
