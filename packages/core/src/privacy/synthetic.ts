import type { Canary } from "./meter.js";

/**
 * Synthetic sensitive data for the privacy lab. Deterministic (seeded),
 * with valid check digits, from several countries and a health record per person, so the leak
 * meter has ground truth that looks like the real thing. Every value is invented.
 */

function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const FIRST = ["Mariela", "Gonzalo", "Florencia", "Ezequiel", "Valentina", "Joaquín", "Rocío", "Matías", "Lucía", "Agustín", "Camila", "Santiago", "Brenda", "Facundo", "Milagros", "Tomás", "Antonella", "Nicolás", "Julieta", "Franco"];
const LAST = ["Quiroga", "Benítez", "Ledesma", "Villalba", "Acosta", "Sosa", "Ojeda", "Medina", "Godoy", "Aguirre", "Cabrera", "Domínguez", "Ferreyra", "Pereyra", "Ríos", "Vera", "Maidana", "Correa", "Ibarra", "Lescano"];
const STREETS = ["Av. Belgrano", "Calle Sarmiento", "Av. San Martín", "Pasaje Las Heras", "Calle Moreno", "Av. Rivadavia", "Calle Mitre", "Calle Alvear"];
const CITIES = ["Paraná", "Rafaela", "Villa María", "Tandil", "Rawson", "Posadas", "Río Cuarto", "Concordia"];
const PLANS = ["OSDE 210", "Swiss Medical SMG20", "Galeno Oro", "IOMA", "PAMI", "Medifé Bronce"];
const DIAGNOSES = [
  "diabetes tipo 2 en tratamiento con metformina",
  "hipertensión arterial controlada",
  "trastorno de ansiedad generalizada",
  "asma bronquial persistente leve",
  "hipotiroidismo en seguimiento",
  "lumbalgia crónica con indicación de kinesiología",
  "migraña con aura",
  "embarazo de 24 semanas sin complicaciones",
];

const pad = (n: number, len: number) => String(n).padStart(len, "0");

function cuit(prefix: number, dni: string): string {
  const w = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
  // A check digit of 10 is not allowed: the real rule moves to prefix 23 (or 24).
  for (const p of [prefix, 23, 24]) {
    const base = `${p}${dni}`;
    const sum = w.reduce((acc, x, i) => acc + x * Number(base[i]), 0);
    let check = 11 - (sum % 11);
    if (check === 11) check = 0;
    if (check !== 10) return `${p}-${dni}-${check}`;
  }
  return cuit(prefix, String((Number(dni) + 1) % 100_000_000).padStart(8, "0"));
}

function cbu(r: () => number): string {
  const digitsOf = (n: number) => Array.from({ length: n }, () => Math.floor(r() * 10));
  const block = (body: number[], w: number[]) => [...body, (10 - (body.reduce((acc, d, i) => acc + d * w[i]!, 0) % 10)) % 10];
  return [...block(digitsOf(7), [7, 1, 3, 9, 7, 1, 3]), ...block(digitsOf(13), [3, 9, 7, 1, 3, 9, 7, 1, 3, 9, 7, 1, 3])].join("");
}

function cpf(r: () => number): string {
  const d = Array.from({ length: 9 }, () => Math.floor(r() * 10));
  const next = (n: number) => {
    const sum = d.slice(0, n).reduce((acc, x, i) => acc + x * (n + 1 - i), 0);
    const v = (sum * 10) % 11;
    return v === 10 ? 0 : v;
  };
  d.push(next(9));
  d.push(next(10));
  const s = d.join("");
  return `${s.slice(0, 3)}.${s.slice(3, 6)}.${s.slice(6, 9)}-${s.slice(9)}`;
}

function rut(r: () => number): string {
  const body = String(10_000_000 + Math.floor(r() * 15_000_000));
  let sum = 0;
  let mul = 2;
  for (let i = body.length - 1; i >= 0; i--) {
    sum += Number(body[i]) * mul;
    mul = mul === 7 ? 2 : mul + 1;
  }
  const v = 11 - (sum % 11);
  const check = v === 11 ? "0" : v === 10 ? "K" : String(v);
  return `${body.slice(0, -6)}.${body.slice(-6, -3)}.${body.slice(-3)}-${check}`;
}

function esDni(r: () => number): string {
  const n = 10_000_000 + Math.floor(r() * 89_999_999);
  return `${n}${"TRWAGMYFPDXBNJZSQVHLCKE"[n % 23]}`;
}

function curp(r: () => number, first: string, last: string): string {
  const up = (s: string) => s.normalize("NFD").replace(/[^A-Za-z]/g, "").toUpperCase();
  const L = up(last);
  const F = up(first);
  const vowel = (L.slice(1).match(/[AEIOU]/) ?? ["X"])[0];
  const yy = pad(60 + Math.floor(r() * 39), 2);
  const mm = pad(1 + Math.floor(r() * 12), 2);
  const dd = pad(1 + Math.floor(r() * 28), 2);
  return `${L[0]}${vowel}X${F[0]}${yy}${mm}${dd}HDFRRN0${Math.floor(r() * 10)}`;
}

function ssn(r: () => number): string {
  return `${100 + Math.floor(r() * 500)}-${pad(10 + Math.floor(r() * 89), 2)}-${pad(1000 + Math.floor(r() * 8999), 4)}`;
}

function card(r: () => number): string {
  const d = [4, ...Array.from({ length: 14 }, () => Math.floor(r() * 10))];
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let x = d[d.length - 1 - i]!;
    if (i % 2 === 0) {
      x *= 2;
      if (x > 9) x -= 9;
    }
    sum += x;
  }
  d.push((10 - (sum % 10)) % 10);
  const s = d.join("");
  return `${s.slice(0, 4)} ${s.slice(4, 8)} ${s.slice(8, 12)} ${s.slice(12)}`;
}

function iban(r: () => number): string {
  const bban = Array.from({ length: 20 }, () => Math.floor(r() * 10)).join("");
  const moved = `${bban}142800`; // "ES" = 14 28, check digits 00
  let rem = 0;
  for (const ch of moved) rem = (rem * 10 + Number(ch)) % 97;
  const check = pad(98 - rem, 2);
  return `ES${check}${bban}`.replace(/(.{4})/g, "$1 ").trim();
}

export interface SyntheticPerson {
  id: number;
  name: string;
  email: string;
  dni: string;
  cuit: string;
  phone: string;
  address: string;
  birthdate: string;
  cbu: string;
  card: string;
  /** One foreign document per person, from a rotating country. */
  foreign: { type: "br_cpf" | "cl_rut" | "mx_curp" | "es_dni" | "us_ssn" | "iban"; value: string };
  health: { plan: string; record: string; diagnosis: string };
}

export function syntheticPeople(count: number, seed = 1337): SyntheticPerson[] {
  const r = rng(seed);
  const pick = <T>(list: T[]) => list[Math.floor(r() * list.length)]!;
  const used = new Set<string>();
  const people: SyntheticPerson[] = [];
  for (let i = 0; i < count; i++) {
    let first: string;
    let last: string;
    do {
      first = pick(FIRST);
      last = `${pick(LAST)} ${pick(LAST)}`;
    } while (used.has(`${first} ${last}`));
    used.add(`${first} ${last}`);
    const dni = String(20_000_000 + Math.floor(r() * 25_000_000));
    const slug = `${first}.${last.split(" ")[0]}`.normalize("NFD").replace(/[^A-Za-z.]/g, "").toLowerCase();
    const kinds = ["br_cpf", "cl_rut", "mx_curp", "es_dni", "us_ssn", "iban"] as const;
    const kind = kinds[i % kinds.length]!;
    const foreign = kind === "br_cpf" ? cpf(r) : kind === "cl_rut" ? rut(r) : kind === "mx_curp" ? curp(r, first, last) : kind === "es_dni" ? esDni(r) : kind === "us_ssn" ? ssn(r) : iban(r);
    people.push({
      id: 1000 + i,
      name: `${first} ${last}`,
      email: `${slug}${i}@correo-lab.example`,
      dni,
      cuit: cuit(r() < 0.5 ? 20 : 27, dni),
      phone: `+54 9 ${pick(["11", "341", "351", "343"])} ${pad(4000 + Math.floor(r() * 5999), 4)}-${pad(Math.floor(r() * 9999), 4)}`,
      address: `${pick(STREETS)} ${100 + Math.floor(r() * 4800)}, ${pick(CITIES)}`,
      birthdate: `${1950 + Math.floor(r() * 55)}-${pad(1 + Math.floor(r() * 12), 2)}-${pad(1 + Math.floor(r() * 28), 2)}`,
      cbu: cbu(r),
      card: card(r),
      foreign: { type: kind, value: foreign },
      health: { plan: pick(PLANS), record: `HC-${pad(Math.floor(r() * 999999), 6)}`, diagnosis: `${pick(DIAGNOSES)} (control ${pad(1 + Math.floor(r() * 28), 2)}/${pad(1 + Math.floor(r() * 12), 2)})` },
    });
  }
  return people;
}

/** The canaries of a set of people: every value the model should never see. */
export function canariesOf(people: SyntheticPerson[]): Canary[] {
  const out: Canary[] = [];
  for (const p of people) {
    const add = (category: string, value: string) => out.push({ id: `${p.id}:${category}`, category, value });
    add("name", p.name);
    add("email", p.email);
    add("ar_dni", p.dni);
    add("ar_cuit", p.cuit);
    add("phone", p.phone);
    add("address", p.address);
    add("birthdate", p.birthdate);
    add("ar_cbu", p.cbu);
    add("card", p.card);
    add(p.foreign.type, p.foreign.value);
    add("health_record", p.health.record);
    add("diagnosis", p.health.diagnosis);
  }
  return out;
}
