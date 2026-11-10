import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import {
  canariesOf,
  type Engagement,
  executeOperation,
  fitForModel,
  forModel,
  maskForModel,
  fieldClassification,
  classifyFields,
  meterEgress,
  type OperationContext,
  privacyReport,
  resetPrivacyMeter,
  setCanaries,
  setPrivacyLevel,
  syntheticPeople,
  ToolRegistry,
  ToolRunner,
  Workspace,
} from "../src/index.js";

/** Phase 1: masking at the source, restoring at the target, measured. */

const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
const human: Actor = { type: "human", id: "01JA00000000000000000000H1" };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let origin: string;
const received: string[] = [];

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-mask-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Privacidad", mode: "web" }, human);
  received.length = 0;
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      received.push(`${req.url} ${Buffer.concat(chunks).toString()}`);
      res.writeHead(200, { "Content-Type": "application/json", "Set-Cookie": "sid=abc123secretvalue; Path=/; HttpOnly" });
      res.end(JSON.stringify({ contact: { nombre: "Ana Ejemplo", email: "aejemplo@municipio.example", telefono: "+54 9 11 4000-0000" }, id: 41 }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, human);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
});

afterEach(async () => {
  await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const ctx = (actor: Actor = agent): OperationContext => ({
  workspace: ws,
  caller: { actor, policy: actor.type === "agent" ? { type: "agent", autonomy: "autonomous", maxRisk: "active" } : { type: "human" } },
  defaultEngagementId: eng.info.id,
  engagement: () => eng,
  runner: () => runner,
});

it("masks personal data by field and by format, and keeps what the agent works with", () => {
  const { value } = maskForModel(eng, {
    tenant: { id: 3, name: "Municipalidad de Villa Ejemplo", slug: "villaejemplo", domain: "villaejemplo.example" },
    contacts: [{ nombre: "Ana Ejemplo", email: "aejemplo@villaejemplo.example", telefono: "+54 9 11 4000-0000", dni: 12345678 }],
    dictionary: [{ name: "failedAttempts", type: "int" }, { name: "email", type: "string" }],
    note: "Escribir a juan.perez@example.com, CUIT 20-12345678-6",
    headers: [["Set-Cookie", "sid=abc123secretvalue; Path=/; HttpOnly"]],
    patient: { diagnostico: "diabetes tipo 2 en tratamiento" },
  }) as Record<string, any>;
  const text = JSON.stringify(value);
  for (const real of ["Ana Ejemplo", "aejemplo@villaejemplo.example", "4000-0000", "12345678", "juan.perez@example.com", "20-12345678-6", "abc123secretvalue", "diabetes"]) expect(text).not.toContain(real);
  // What the agent needs stays: IDs, the tenant, the schema, the organisation's domain, cookie names.
  expect(value.tenant).toEqual({ id: 3, name: "Municipalidad de Villa Ejemplo", slug: "villaejemplo", domain: "villaejemplo.example" });
  expect(value.dictionary).toEqual([{ name: "failedAttempts", type: "int" }, { name: "email", type: "string" }]);
  expect(value.contacts[0].email).toMatch(/^«email:\d+ @villaejemplo\.example»$/);
  expect(value.headers[0][1]).toMatch(/^sid=«secret:\d+»; Path=\/; HttpOnly$/);
  expect(value.patient.diagnostico).toMatch(/^«content:\d+ 30 chars»$/);
});

it("the same value is always the same marker", () => {
  const a = JSON.stringify(maskForModel(eng, { email: "a@x.example" }).value);
  const b = JSON.stringify(maskForModel(eng, { correo: "a@x.example", otro: "b@x.example" }).value);
  const marker = /«email:\d+ @x\.example»/.exec(a)![0];
  expect(b).toContain(marker);
  expect(b.match(/«email:\d+/g)!.length).toBe(2);
});

it("the agent reads markers and Penteos sends the real values to the target", async () => {
  // The agent reads a response: the contact is masked for it.
  const read = (await executeOperation("http.send", { origin, raw: "GET /api/tenants/3 HTTP/1.1" }, ctx())) as unknown;
  const seen = forModel(eng, read);
  expect(seen).not.toContain("aejemplo@municipio.example");
  const marker = /«email:\d+ @municipio\.example»/.exec(seen)![0];
  // It uses that marker in a request: the target receives the real address.
  await executeOperation("http.send", { origin, raw: `POST /api/auth/forgot HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"email":"${marker}"}` }, ctx());
  expect(received.at(-1)).toContain('{"email":"aejemplo@municipio.example"}');
});

it("a marker Penteos never issued is refused and nothing is sent", async () => {
  const before = received.length;
  await expect(executeOperation("http.send", { origin, raw: 'POST /x HTTP/1.1\r\n\r\n{"email":"«email:999 @x.com»"}' }, ctx())).rejects.toMatchObject({ code: "VALIDATION_ERROR", message: expect.stringMatching(/unknown masked value/) });
  expect(received.length).toBe(before);
});

it("what an agent writes keeps the markers; a person reads the real values", async () => {
  const marker = /«email:\d+[^»]*»/.exec(JSON.stringify(maskForModel(eng, { email: "aejemplo@municipio.example" }).value))![0];
  const f = (await executeOperation("finding.create", { title: "Contactos expuestos", severity: "medium", description: `La ruta devuelve ${marker} sin sesión.` }, ctx())) as { id: string };
  expect(String(eng.get(f.id)!.attributes.description)).toContain(marker);
  const forHuman = (await executeOperation("entity.get", { id: f.id }, ctx(human))) as { attributes: { description: string } };
  expect(forHuman.attributes.description).toContain("aejemplo@municipio.example");
});

it("off means the model sees the data as it comes (labs)", () => {
  setPrivacyLevel(eng, "off");
  expect(forModel(eng, { email: "a@x.example" })).toContain("a@x.example");
});

it("a big result is shrunk by structure, not cut: totals and fields of every item survive", () => {
  const rows = Array.from({ length: 5000 }, (_, i) => ({ id: i, municipio: `M${i}`, activo: i % 2 === 0, notas: "x".repeat(200) }));
  const { text, info } = fitForModel({ rows, total: 5000, rawId: "sha256:abc" }, 24_000, "raw_get with rawId sha256:abc");
  expect(text.length).toBeLessThanOrEqual(24_000);
  expect(info.shrunk).toBe(true);
  expect(text).toContain("more of 5000 items not shown");
  expect(text).toMatch(/"fieldsAcrossAllItems"[\s\S]*"notas": 5000/);
  expect(text).toContain('"total": 5000');
  expect(text).toContain("raw_get with rawId sha256:abc");
});

it("the leak meter: structured records from six countries reach the model with zero canaries", () => {
  const people = syntheticPeople(40);
  setCanaries(eng, canariesOf(people));
  const records = people.map((p) => ({
    id: p.id,
    nombre: p.name,
    email: p.email,
    dni: p.dni,
    cuit: p.cuit,
    telefono: p.phone,
    domicilio: p.address,
    fecha_nacimiento: p.birthdate,
    cbu: p.cbu,
    tarjeta: p.card,
    documento_extranjero: p.foreign.value,
    historia_clinica: p.health.record,
    obra_social: p.health.plan,
    diagnostico: p.health.diagnosis,
  }));
  // Masked, as the agent would read the API's answer.
  meterEgress(eng, "tool", forModel(eng, { untrusted: true, content: JSON.stringify(records) }, 2_000_000));
  const masked = privacyReport(eng);
  expect(masked.canaries.leaked).toBe(0);

  // The same records without masking: everything would have reached the model.
  resetPrivacyMeter(eng);
  setPrivacyLevel(eng, "off");
  meterEgress(eng, "tool", forModel(eng, { untrusted: true, content: JSON.stringify(records) }, 2_000_000));
  expect(privacyReport(eng).canaries.rate).toBe(100);
});

it("the leak meter on a CSV export: its header says what each column is, nothing leaks", () => {
  const people = syntheticPeople(30, 7);
  setCanaries(eng, canariesOf(people));
  const csv = ["nombre;email;cuit;telefono;cbu;tarjeta;doc;domicilio", ...people.map((p) => [p.name, p.email, p.cuit, p.phone, p.cbu, p.card, p.foreign.value, p.address].join(";"))].join("\n");
  meterEgress(eng, "tool", forModel(eng, { untrusted: true, content: csv }, 2_000_000));
  const r = privacyReport(eng).canaries.byCategory;
  for (const [k, v] of Object.entries(r)) if (["name", "email", "ar_cuit", "phone", "ar_cbu", "card", "address"].includes(k)) expect({ k, leaked: v.leaked }).toEqual({ k, leaked: 0 });
});

it("free text: a name already in the vault is masked wherever it appears again", () => {
  const first = JSON.stringify(maskForModel(eng, { nombre: "Ana Ejemplo Prueba", email: "mq@x.example" }).value);
  const marker = /«name:\d+»/.exec(first)![0];
  const later = forModel(eng, { error: "El usuario Ejemplo Prueba, Ana no está autorizado (ana ejemplo prueba)" });
  expect(later).not.toMatch(/Ejemplo Prueba|Ana Ejemplo|ana ejemplo/);
  expect(later.split(marker).length - 1).toBe(2);
});

it("free text: labelled lines, HTML tables and form fields; code is left alone", () => {
  const out = forModel(eng, {
    letter: "Constancia\nTitular: Juan Pérez Acosta\nDomicilio: Calle Falsa 123, Paraná\nTrámite: 4412",
    page: '<table><tr><th>Nombre</th><th>Legajo</th></tr><tr><td>Ana Ríos</td><td>88</td></tr></table><input name="email" value="ana.rios@x.example">',
    script: "const f = { email: e.target.value, nombre: form.nombre.value }; function go() { return f; }",
  });
  for (const real of ["Juan Pérez Acosta", "Calle Falsa 123", "Ana Ríos", "ana.rios@x.example"]) expect(out).not.toContain(real);
  expect(out).toContain("Trámite: 4412");
  expect(out).toContain("<td>88</td>");
  expect(out).toContain("email: e.target.value");
});

it("an ambiguous name/nombre is a person only when its neighbours or its value say so", () => {
  const out = JSON.stringify(
    maskForModel(eng, {
      body: JSON.stringify({
        diccionario: [{ nombre: "nro_documento", tipo: "varchar", descripcion: "Documento" }, { nombre: "Fecha Alta", tipo: "date" }],
        tenant: { name: "Municipalidad de Villa Ejemplo" },
        app: { name: "Mesa de Entradas" },
        persona: { nombre: "Rocío Ledesma Sosa", id: 7 },
      }),
    }).value,
  );
  expect(out).toContain("nro_documento");
  expect(out).toContain("Fecha Alta");
  expect(out).toContain("Municipalidad de Villa Ejemplo");
  expect(out).toContain("Mesa de Entradas");
  expect(out).not.toContain("Rocío Ledesma Sosa");
});

it("classifying nombre as a person does not cover the data dictionary's nombre", () => {
  classifyFields(eng, [{ name: "nombre", kind: "name" }]);
  const out = JSON.stringify(
    maskForModel(eng, {
      body: JSON.stringify({ diccionario: [{ nombre: "Fecha Alta", tipo: "date", descripcion: "Alta del trámite" }], vecino: { nombre: "Ana" } }),
    }).value,
  );
  expect(out).toContain("Fecha Alta");
  expect(out).not.toContain('"Ana"');
});

it("Penteos's own result fields are not offered to classify; the target's are", () => {
  maskForModel(eng, { mode: "web", ai_level: "asistido", body: JSON.stringify([{ responsable_obra: "Alta Gracia", estado: "abierto" }]) });
  const pending = fieldClassification(eng).unclassified;
  expect(pending).toEqual(expect.arrayContaining(["responsable_obra", "estado"]));
  expect(pending).not.toContain("mode");
  expect(pending).not.toContain("ai_level");
});

it("the agent classifies field names it saw (names only), and their values are masked from then on", async () => {
  const before = forModel(eng, { body: JSON.stringify({ rows: [{ responsable_tramite: "Juan Pérez", estado: "abierto" }] }) });
  expect(before).toContain("Juan Pérez");
  const pending = (await executeOperation("privacy.fields", {}, ctx())) as { unclassified: string[] };
  expect(pending.unclassified).toEqual(expect.arrayContaining(["responsable_tramite", "estado"]));
  await executeOperation("privacy.classify_fields", { fields: [{ name: "responsable_tramite", kind: "name" }, { name: "estado", kind: "none" }] }, ctx());
  const after = forModel(eng, { rows: [{ responsable_tramite: "Juan Pérez", estado: "abierto" }] });
  expect(after).not.toContain("Juan Pérez");
  expect(after).toContain('"estado": "abierto"');
});

it("with a model on this machine nothing is masked (the data does not leave it)", () => {
  expect(forModel(eng, { email: "a@x.example" }, 24_000, { local: true })).toContain("a@x.example");
});

it("still not covered: a name in prose with no structure and never seen before (measured)", () => {
  const out = forModel(eng, { note: "Ayer llamó Rocío Ledesma Sosa para pedir el turno." });
  expect(out).toContain("Rocío Ledesma Sosa");
});

it("clinical prose is a note the model never reads: record numbers and diagnoses, in any shape", () => {
  const notes = {
    es: "Historia HC-204518: paciente Marta Gil, plan Galeno, hipertensión arterial (control 12/05).",
    en: "Patient seen on Monday was diagnosed with type 2 diabetes and started treatment with metformin.",
    json: JSON.stringify({ observaciones: "Paciente con asma bronquial, en tratamiento con salbutamol." }),
    mrn: "MRN 004512 - discharged",
  };
  const out = forModel(eng, notes);
  for (const real of ["HC-204518", "hipertensión arterial", "type 2 diabetes", "metformin", "asma bronquial", "salbutamol", "004512"]) expect(out).not.toContain(real);
  // The model still knows what kind of data this is, and how much.
  expect(out).toMatch(/«content:\d+ clinical note, \d+ chars»/);
  expect(out).toMatch(/«health_record:\d+»/);
});

it("one clinical word is not a clinical note: menus, docs and code stay readable", () => {
  const out = forModel(eng, {
    menu: "Patients",
    page: "Treatment of user input is described in the security guide.",
    code: "const patients = api.get('/patients'); if (diagnosis) render(diagnosis);",
  });
  expect(out).toContain("Patients");
  expect(out).toContain("Treatment of user input is described in the security guide.");
  expect(out).toContain("api.get('/patients')");
});

it("a birth date in prose is masked by the words before it; other dates stay", () => {
  const out = forModel(eng, {
    a: "Titular nacido el 1975-03-12, cliente desde 2019.",
    b: "Patient DOB: 03/12/1975, admitted on 2026-11-02.",
    c: "Born on 12 March 1975 in Rosario.",
    d: "Deploy finished 2026-11-09 at 10:12; next window 2026-11-16.",
  });
  for (const real of ["1975-03-12", "03/12/1975", "12 March 1975"]) expect(out).not.toContain(real);
  for (const kept of ["2019", "2026-11-02", "2026-11-09", "2026-11-16"]) expect(out).toContain(kept);
  expect(out).toMatch(/«birthdate:\d+»/);
});
