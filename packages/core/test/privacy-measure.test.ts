import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import {
  canariesOf,
  type Engagement,
  forModel,
  meterEgress,
  privacyReport,
  resetPrivacyMeter,
  setCanaries,
  setPrivacyLevel,
  type SyntheticPerson,
  syntheticPeople,
  textForModel,
  Workspace,
} from "../src/index.js";

/**
 * Automatic leak + capacity measurement: no lab, no manual injection.
 * We generate synthetic people (whose every value is a canary), simulate the tool outputs a real
 * run would read from a target, pass them through the privacy layer exactly as the agent does, and
 * count how many canary values reach the model - with masking ON vs OFF - plus how much text still
 * reaches it (capacity). A canary is fake and unique, so any that reaches the model is a sure leak,
 * and this also catches names written in prose, which the regex detectors cannot see.
 */

const human: Actor = { type: "human", id: "01JA00000000000000000000H1" };
let dir: string;
let ws: Workspace;
let eng: Engagement;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-measure-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Measurement", mode: "web" }, human);
});
afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

/** The tool outputs a scan of a real target would feed the agent, carrying the canary values. */
function targetOutputs(people: SyntheticPerson[]): unknown[] {
  const out: unknown[] = [];
  for (const p of people) {
    // 1) A JSON API response with named fields (structured PII).
    out.push({ endpoint: "/api/users", body: { id: p.id, fullName: p.name, email: p.email, cuit: p.cuit, dni: p.dni, card: p.card, phone: p.phone, address: p.address } });
    // 2) A SQL/DB dump row.
    out.push(`INSERT INTO clientes (nombre,email,cuit,tarjeta) VALUES ('${p.name}','${p.email}','${p.cuit}','${p.card}');`);
    // 3) An application log line (name + email in prose).
    out.push(`2026-10-29T10:12:03Z INFO login ok user="${p.name}" <${p.email}> ip=10.0.0.5`);
    // 4) An HTML page body (name in prose, card in text).
    out.push(`<h1>Hola ${p.name}</h1><p>Tu tarjeta terminada en ${p.card} fue aprobada. DNI ${p.dni}.</p>`);
    // 5) A health record (name + diagnosis in prose - the hardest for a detector).
    out.push(`Historia ${p.health.record}: paciente ${p.name}, plan ${p.health.plan}, ${p.health.diagnosis}.`);
    // 6) A payments API: bank account, birth date and a foreign ID document in named fields.
    out.push({ endpoint: "/api/payouts", body: { holder: p.name, cbu: p.cbu, birthDate: p.birthdate, document: p.foreign.value } });
    // 7) The same data in prose, as an error message or a support ticket would carry it.
    out.push(`Pago rechazado: CBU ${p.cbu}, titular ${p.name}, documento ${p.foreign.value}, nacido el ${p.birthdate}.`);
  }
  // 8) A CSV export of all of them, by its header.
  out.push(["nombre;cbu;fecha_nacimiento;documento", ...people.map((p) => [p.name, p.cbu, p.birthdate, p.foreign.value].join(";"))].join("\n"));
  return out;
}

/** Feed every output through the model boundary and read the leak meter. */
function run(level: "standard" | "off", outputs: unknown[]) {
  setPrivacyLevel(eng, level);
  resetPrivacyMeter(eng);
  for (const o of outputs) {
    const sent = typeof o === "string" ? textForModel(eng, o) : forModel(eng, o);
    meterEgress(eng, "tool", sent);
  }
  return privacyReport(eng);
}

const pct = (leaked: number, total: number) => (total ? Math.round((leaked / total) * 1000) / 10 : 0);

it("measures leak and capacity automatically, ON vs OFF", () => {
  const people = syntheticPeople(20);
  const list = canariesOf(people);
  setCanaries(eng, list);
  const outputs = targetOutputs(people);

  const off = run("off", outputs);
  const on = run("standard", outputs);

  const cats = Object.keys({ ...on.canaries.byCategory, ...off.canaries.byCategory }).sort();
  const lines: string[] = [];
  lines.push("");
  lines.push(`== Privacy measurement (automatic, no lab): ${people.length} people, ${list.length} canaries ==`);
  lines.push("");
  lines.push("category           OFF (leaked)      ON (leaked)       blocked");
  for (const c of cats) {
    const o = off.canaries.byCategory[c] ?? { total: 0, leaked: 0 };
    const n = on.canaries.byCategory[c] ?? { total: 0, leaked: 0 };
    const blocked = o.leaked ? Math.round(((o.leaked - n.leaked) / o.leaked) * 100) : 0;
    lines.push(`${c.padEnd(18)} ${String(`${o.leaked}/${o.total} (${pct(o.leaked, o.total)}%)`).padEnd(17)} ${String(`${n.leaked}/${n.total} (${pct(n.leaked, n.total)}%)`).padEnd(17)} ${blocked}%`);
  }
  const offChars = off.chars.system + off.chars.prompt + off.chars.tool;
  const onChars = on.chars.system + on.chars.prompt + on.chars.tool;
  lines.push("");
  lines.push(`TOTAL leaked:      OFF ${off.canaries.leaked}/${list.length} (${pct(off.canaries.leaked, list.length)}%)   ON ${on.canaries.leaked}/${list.length} (${pct(on.canaries.leaked, list.length)}%)`);
  lines.push(`Capacity (chars to the model):   OFF ${offChars}   ON ${onChars}   (${onChars >= offChars * 0.6 ? "intact" : "REDUCED"})`);
  lines.push("");
  lines.push("Reading: whatever still leaks with the layer ON is a blind spot to harden.");
  lines.push("");
  // eslint-disable-next-line no-console
  console.log(lines.join("\n"));

  // Guarantees that must hold on every run:
  // 1) With the layer off, the sensitive data leaks wholesale.
  expect(off.canaries.leaked).toBeGreaterThan(0);
  // 2) The layer blocks the large majority of the leak.
  expect(on.canaries.leaked).toBeLessThan(off.canaries.leaked * 0.3);
  // 3) Every category is fully protected, including when the value is written in prose.
  for (const [c, n] of Object.entries(on.canaries.byCategory)) expect(n.leaked, `${c} should not leak`).toBe(0);
  // Every category is really exercised: with the layer off, each one reaches the model.
  for (const [c, n] of Object.entries(off.canaries.byCategory)) expect(n.leaked, `${c} is not in the simulated outputs`).toBe(n.total);
  // 4) Clinical prose (record numbers, diagnoses in free text) is caught by its context.
  for (const c of ["diagnosis", "health_record"]) expect(on.canaries.byCategory[c]?.leaked ?? 0, `${c} should not leak`).toBe(0);
  // 5) Capacity is preserved: masking replaces values with markers, it does not drop the text.
  expect(onChars).toBeGreaterThan(offChars * 0.6);
});

it("keeps references consistent: the same value always masks to the same marker", () => {
  const [p] = syntheticPeople(1);
  setPrivacyLevel(eng, "standard");
  // The same email seen twice must become the same marker, so IDOR/enumeration by reference survives.
  const a = textForModel(eng, `contacto principal: ${p!.email}`);
  const b = textForModel(eng, `el alta la hizo ${p!.email}`);
  const markerA = a.match(/«[^»]+»/)?.[0];
  const markerB = b.match(/«[^»]+»/)?.[0];
  expect(markerA).toBeTruthy();
  expect(markerA).toBe(markerB);
  expect(a).not.toContain(p!.email);
});
