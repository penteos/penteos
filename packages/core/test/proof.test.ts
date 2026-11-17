import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Caller, type Engagement, executeOperation, type OperationContext, pseudonym, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/**
 * A finding is backed by what the target answered, not by what the model says it answered: quotes
 * are checked against the stored output, and what goes before the operator carries one.
 */

const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
const AGENT: Caller = { actor: { type: "agent", id: "01JA0000000000000000000AGT" }, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
const ctx = (caller: Caller): OperationContext => ({ workspace: ws, caller, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner }) as unknown as OperationContext;

const RESPONSE = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"users":[{"id":7,"email":"ana.perez@cliente.test","hash":"$2b$10$Qz8kfa9Yc1Lm0pXv7E2rUe"}]}';

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-proof-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Cliente", name: "Web", mode: "web" }, HUMAN.actor);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
});
afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const raw = (text: string | Uint8Array) => eng.putRaw(text, { type: "http", mime: "message/http" });

describe("quotes are checked against the output", () => {
  it("accepts a quote that is there, whitespace aside, and keeps it", async () => {
    const rawId = raw(RESPONSE);
    const ev = (await executeOperation("evidence.from_raw", { rawId, caption: "GET /api/users sin sesión", quotes: ['"hash":"$2b$10$Qz8kfa9Yc1Lm0pXv7E2rUe"', '{"users":[{"id":7,'] }, ctx(AGENT))) as { attributes: { quotes: string[] } };
    expect(ev.attributes.quotes).toHaveLength(2);
  });

  it("refuses a quote the target never sent, and says which", async () => {
    const rawId = raw(RESPONSE);
    await expect(executeOperation("evidence.from_raw", { rawId, caption: "admin", quotes: ['"role":"admin"', '{"users":[{"id":7,'] }, ctx(AGENT))).rejects.toThrow(/not in sha256:.*«"role":"admin"»/);
    expect(eng.query({ kind: "evidence" })).toHaveLength(0);
  });

  it("matches the client's data the model only saw masked", async () => {
    const rawId = raw(RESPONSE);
    const marker = pseudonym(eng, "email", "ana.perez@cliente.test");
    expect(marker).toMatch(/^«email:\d+/);
    const ev = await executeOperation("evidence.from_raw", { rawId, caption: "otro usuario", quotes: [`"email":"${marker}"`] }, ctx(AGENT));
    expect(ev).toBeTruthy();
  });

  it("reads a compressed body", async () => {
    const body = gzipSync(Buffer.from("<h1>Panel de administración</h1><p>Usuarios: 4213</p>"));
    const rawId = raw(Buffer.concat([Buffer.from("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: text/html\r\n\r\n"), body]));
    await expect(executeOperation("evidence.from_raw", { rawId, caption: "panel", quotes: ["Panel de administración</h1><p>Usuarios: 4213"] }, ctx(AGENT))).resolves.toBeTruthy();
  });
});

describe("what goes before the operator is proven", () => {
  const draft = async (severity: string, extra: Record<string, unknown> = {}) => (await executeOperation("finding.create", { title: `Hallazgo ${severity}`, severity, ...extra }, ctx(AGENT))) as { id: string };

  it("a medium or higher finding needs a checked quote or an absence", async () => {
    const high = await draft("high");
    const low = await draft("low");
    await expect(executeOperation("finding.request_approval", { ids: [high.id, low.id], reason: "listos" }, ctx(AGENT))).rejects.toThrow(/no textual proof yet for: .*Hallazgo high/);
    // With quoted evidence it goes.
    const ev = (await executeOperation("evidence.from_raw", { rawId: raw(RESPONSE), caption: "hash expuesto", quotes: ['"hash":"$2b$10$Qz8kfa9Yc1Lm0pXv7E2rUe"'] }, ctx(AGENT))) as { id: string };
    await executeOperation("finding.update", { id: high.id, addEvidenceIds: [ev.id] }, ctx(AGENT));
    await expect(executeOperation("finding.request_approval", { ids: [high.id, low.id], reason: "listos" }, ctx(AGENT))).resolves.toMatchObject({ status: "pending_approval" });
  });

  it("a finding proved by something missing says what and where", async () => {
    const f = await draft("medium", { absenceProof: "sin Strict-Transport-Security en /, /login y /api/me" });
    await expect(executeOperation("finding.request_approval", { ids: [f.id], reason: "listo" }, ctx(AGENT))).resolves.toMatchObject({ status: "pending_approval" });
    expect(eng.get(f.id)!.attributes.absenceProof).toMatch(/Strict-Transport-Security/);
  });

  it("the operator is not held to it", async () => {
    const f = (await executeOperation("finding.create", { title: "Visto a mano", severity: "high" }, ctx(HUMAN))) as { id: string };
    await expect(executeOperation("finding.request_approval", { ids: [f.id], reason: "lo vi yo" }, ctx(HUMAN))).resolves.toMatchObject({ status: "pending_approval" });
  });
});

describe("the report shows the proof", () => {
  it("with the real values for the readers, and what a finding proved by absence is", async () => {
    const marker = pseudonym(eng, "email", "ana.perez@cliente.test");
    const ev = (await executeOperation("evidence.from_raw", { rawId: raw(RESPONSE), caption: "Otro usuario visible", quotes: [`"email":"${marker}"`] }, ctx(AGENT))) as { id: string };
    const a = (await executeOperation("finding.create", { title: "IDOR en /api/users", severity: "high", evidenceIds: [ev.id] }, ctx(AGENT))) as { id: string };
    const b = (await executeOperation("finding.create", { title: "Sin HSTS", severity: "low", absenceProof: "sin Strict-Transport-Security en / y /login" }, ctx(AGENT))) as { id: string };
    for (const id of [a.id, b.id]) await executeOperation("finding.set_status", { id, status: "approved" }, ctx(HUMAN));
    const md = ((await executeOperation("report.render", {}, ctx(HUMAN))) as { markdown: string }).markdown;
    expect(md).toMatch(/(Checked in the response|Verificado en la respuesta):_ `"email":"ana\.perez@cliente\.test"`/);
    expect(md).not.toContain(marker);
    expect(md).toMatch(/(Proved by absence|Probado por ausencia):\*\* sin Strict-Transport-Security en \/ y \/login/);
  });
});

