import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import { detect, type Engagement, meterEgress, privacyReport, setCanaries, Workspace } from "../src/index.js";
import { validCbu, validCpf, validCuit, validEsDni, validIban, validRut } from "../src/privacy/detectors.js";
import { canariesOf, syntheticPeople } from "../src/privacy/synthetic.js";

/** The leak meter: detectors with check digits and canaries as ground truth. */

const human: Actor = { type: "human", id: "01JA00000000000000000000H1" };
let dir: string;
let ws: Workspace;
let eng: Engagement;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-privacy-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Privacidad", mode: "web" }, human);
});
afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

it("synthetic documents carry valid check digits", () => {
  const people = syntheticPeople(60);
  for (const p of people) {
    expect(validCuit(p.cuit)).toBe(true);
    expect(validCbu(p.cbu)).toBe(true);
    if (p.foreign.type === "br_cpf") expect(validCpf(p.foreign.value)).toBe(true);
    if (p.foreign.type === "cl_rut") expect(validRut(p.foreign.value)).toBe(true);
    if (p.foreign.type === "es_dni") expect(validEsDni(p.foreign.value)).toBe(true);
    if (p.foreign.type === "iban") expect(validIban(p.foreign.value)).toBe(true);
  }
});

it("detectors find structured values and reject look-alikes", () => {
  const p = syntheticPeople(12);
  const text = JSON.stringify(p);
  const types = new Set(detect(text).map((d) => d.type));
  for (const t of ["email", "card", "ar_cuit", "ar_cbu", "br_cpf", "cl_rut", "mx_curp", "es_dni", "us_ssn", "iban", "phone"]) expect(types).toContain(t);
  // Numbers that merely look like documents are not taken for them.
  expect(detect("pedido 20123456780 y cuenta 1234567890123456789012 y tarjeta 4111 1111 1111 1112").map((d) => d.type)).toEqual([]);
});

it("counts the canaries that reach the model, also when written another way", () => {
  const people = syntheticPeople(5);
  const list = canariesOf(people);
  setCanaries(eng, list);
  // A tool result shows the first person's record; the second person's CUIT comes without dashes.
  const p0 = people[0]!;
  meterEgress(eng, "tool", JSON.stringify({ name: p0.name, email: p0.email, cuit: p0.cuit, note: p0.health.diagnosis }));
  meterEgress(eng, "prompt", `revisar el ${people[1]!.cuit.replace(/-/g, "")}`);
  const r = privacyReport(eng);
  expect(r.canaries.total).toBe(list.length);
  expect(r.canaries.byCategory.name).toEqual({ total: 5, leaked: 1 });
  expect(r.canaries.byCategory.ar_cuit).toEqual({ total: 5, leaked: 2 });
  expect(r.canaries.byCategory.diagnosis).toEqual({ total: 5, leaked: 1 });
  expect(r.detected.email).toBe(1);
  expect(r.chars.tool).toBeGreaterThan(0);
});
