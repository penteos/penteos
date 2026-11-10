import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import { type ChangeEvent, type Engagement, executeOperation, type OperationContext, Workspace } from "../src/index.js";

/** A round ends with where we stand and the paths worth exploring; what depends on the client becomes a question for them. */

const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
const human: Actor = { type: "human", id: "01JA00000000000000000000H1" };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let events: ChangeEvent[];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-paths-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ language: "es", clientName: "Lab", name: "Web", mode: "web" }, human);
  events = [];
  eng.events.on("change", (e: ChangeEvent) => events.push(e));
});
afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const ctx = (actor: Actor): OperationContext =>
  ({ workspace: ws, caller: { actor, policy: actor.type === "agent" ? { type: "agent", autonomy: "autonomous", maxRisk: "active" } : { type: "human" } }, defaultEngagementId: eng.info.id, engagement: () => eng }) as unknown as OperationContext;

it("the Maestro proposes paths; only agents do, and they need at least two", async () => {
  const paths = [
    { title: "Aislamiento entre clientes", why: "La API acepta una cabecera de inquilino.", needs: "credentials", question: "¿Nos dan dos cuentas de clientes distintos?" },
    { title: "Política de transporte del correo", why: "DMARC ya estaba mal configurado.", needs: "nothing", noise: "low" },
  ];
  const r = (await executeOperation("plan.propose_paths", { status: "Cuatro hallazgos aprobados; sin cuentas no se probó la separación entre clientes.", paths }, ctx(agent))) as { status: string; paths: number };
  expect(r).toMatchObject({ status: "shown", paths: 2 });
  await expect(executeOperation("plan.propose_paths", { status: "x", paths: paths.slice(0, 1) }, ctx(agent))).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
  await expect(executeOperation("plan.propose_paths", { status: "x", paths }, ctx(human))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
});

it("questions for the client: added once, answered by a person, and the answer is announced", async () => {
  const q = (await executeOperation("client_question.add", { text: "¿Nos dan dos cuentas de clientes distintos?", path: "Aislamiento entre clientes" }, ctx(agent))) as { id: string };
  const again = (await executeOperation("client_question.add", { text: "¿nos dan dos cuentas de clientes distintos? " }, ctx(human))) as { id: string };
  expect(again.id).toBe(q.id);
  await expect(executeOperation("client_question.answer", { id: q.id, answer: "Sí" }, ctx(agent))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  await executeOperation("client_question.answer", { id: q.id, answer: "Sí, el lunes." }, ctx(human));
  const list = (await executeOperation("client_question.list", {}, ctx(agent))) as Array<{ status: string; answer?: string }>;
  expect(list).toMatchObject([{ status: "answered", answer: "Sí, el lunes." }]);
  expect(events.find((e) => e.type === "client_question.answered")).toMatchObject({ answer: "Sí, el lunes." });
});

it("traces left on the target are recorded, resolved by a person and listed in the report", async () => {
  const { renderReport } = await import("../src/report.js");
  const tr = (await executeOperation("trace.record", { what: "La dirección prueba1@example.com quedó suscrita al boletín", where: "POST https://shop.test/api/public/blog-subscribe.php", cleanup: "Darla de baja desde el enlace del correo" }, ctx(agent))) as { id: string; status: string };
  expect(tr.status).toBe("pending");
  expect(renderReport(eng)).toMatch(/Rastros en el entorno[\s\S]*prueba1@example\.com[\s\S]*pendiente de limpieza/);
  await expect(executeOperation("trace.resolve", { id: tr.id, status: "cleaned" }, ctx(agent))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  await executeOperation("trace.resolve", { id: tr.id, status: "cleaned" }, ctx(human));
  expect(renderReport(eng)).toMatch(/prueba1@example\.com.*retirado/);
});

it("an agent cannot ask to move to the reporting phase: that is the operator's call", async () => {
  await expect(executeOperation("phase.request", { to: "reporting", summary: "Análisis terminado" }, ctx(agent))).rejects.toMatchObject({ code: "PERMISSION_DENIED", message: expect.stringMatching(/plan_propose_paths/) });
});
