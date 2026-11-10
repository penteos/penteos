import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Caller, type ChangeEvent, type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/**
 * The Maestro asks the operator to browse what automated requests cannot get through; the proxy
 * records it and the Maestro hears how much was captured. And a host that stops accepting
 * connections after answering is reported once, as a probable IP ban.
 */

const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
const MAESTRO: Caller = { actor: { type: "agent", id: "01JA000000000000000000MSTR" }, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let events: ChangeEvent[];
let seq = 0;

const ctx = (caller: Caller): OperationContext => ({ workspace: ws, caller, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner });

const exchange = (host: string, extra: { status?: number; error?: string } = {}) =>
  eng.addProxyEntry({
    id: `x${++seq}`,
    at: new Date().toISOString(),
    source: "browser",
    method: "GET",
    url: `https://${host}/`,
    host,
    path: "/",
    reqSize: 100,
    resSize: extra.status ? 2000 : 0,
    inScope: true,
    blocked: false,
    static: false,
    edited: false,
    ...extra,
  });

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-browse-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Cliente", name: "Web", mode: "web" }, HUMAN.actor);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  eng.addScopeRule({ effect: "include", target: { type: "domain", value: "arbitraje.cliente.test" } }, HUMAN.actor);
  events = [];
  eng.events.on("change", (e: ChangeEvent) => events.push(e));
});

afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("browsing on request", () => {
  it("the Maestro asks, the operator browses, the Maestro hears what the proxy captured", async () => {
    await expect(executeOperation("browser.request", { url: "https://otro.test/", title: "x", steps: ["y"] }, ctx(MAESTRO))).rejects.toMatchObject({ code: "OUT_OF_SCOPE" });

    const r = (await executeOperation("browser.request", { url: "https://arbitraje.cliente.test/", title: "Pasar el reto anti-bot y recorrer el login", steps: ["Abrir la página y esperar el reto", "Ingresar al formulario de login"] }, ctx(MAESTRO))) as { taskId: string; status: string };
    expect(r.status).toBe("requested");
    const task = eng.get(r.taskId)!.attributes;
    expect(task).toMatchObject({ assignee: { type: "human" }, priority: "high", browse: { url: "https://arbitraje.cliente.test/", steps: ["Abrir la página y esperar el reto", "Ingresar al formulario de login"] } });
    // Asking twice for the same site does not make a second card.
    expect(await executeOperation("browser.request", { url: "https://arbitraje.cliente.test/login", title: "otra vez", steps: ["z"] }, ctx(MAESTRO))).toMatchObject({ taskId: r.taskId, status: "already_requested" });

    exchange("arbitraje.cliente.test", { status: 200 });
    exchange("arbitraje.cliente.test", { status: 302 });
    expect(await executeOperation("browser.progress", { taskId: r.taskId }, ctx(HUMAN))).toEqual({ exchanges: 2, hosts: ["arbitraje.cliente.test"] });

    await expect(executeOperation("browser.respond", { taskId: r.taskId, outcome: "done" }, ctx(MAESTRO))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await executeOperation("browser.respond", { taskId: r.taskId, outcome: "done" }, ctx(HUMAN));
    expect(eng.get(r.taskId)!.attributes).toMatchObject({ status: "done", browse: { result: { outcome: "done", exchanges: 2 } } });
    expect(events.find((e) => e.type === "browse.responded")).toMatchObject({ taskId: r.taskId, outcome: "done", exchanges: 2, hosts: ["arbitraje.cliente.test"], askedBy: MAESTRO.actor });
  });

  it("declining closes the card and tells the Maestro", async () => {
    const r = (await executeOperation("browser.request", { url: "https://arbitraje.cliente.test/", title: "Recorrer el login", steps: ["Ingresar"] }, ctx(MAESTRO))) as { taskId: string };
    await executeOperation("browser.respond", { taskId: r.taskId, outcome: "declined", note: "hoy no" }, ctx(HUMAN));
    expect(eng.get(r.taskId)!.attributes.status).toBe("cancelled");
    expect(events.find((e) => e.type === "browse.responded")).toMatchObject({ outcome: "declined", note: "hoy no" });
  });
});

describe("a host that stops answering", () => {
  it("is reported once after answering and then dropping connections twice", () => {
    const unreachable = () => events.filter((e) => e.type === "host.unreachable");
    // Never answered: nothing to say (it may simply be down).
    exchange("caido.cliente.test", { error: "no TCP connection to caido.cliente.test:443 after 30 s" });
    exchange("caido.cliente.test", { error: "no TCP connection to caido.cliente.test:443 after 30 s" });
    expect(unreachable()).toHaveLength(0);

    exchange("arbitraje.cliente.test", { status: 200 });
    exchange("arbitraje.cliente.test", { error: "no TCP connection to arbitraje.cliente.test:443 after 30 s" });
    expect(unreachable()).toHaveLength(0);
    exchange("arbitraje.cliente.test", { error: "no TCP connection to arbitraje.cliente.test:443 after 30 s" });
    exchange("arbitraje.cliente.test", { error: "no TCP connection to arbitraje.cliente.test:443 after 30 s" });
    expect(unreachable()).toEqual([expect.objectContaining({ type: "host.unreachable", host: "arbitraje.cliente.test", failures: 2 })]);
  });
});
