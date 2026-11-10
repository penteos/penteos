/**
 * Sensitive-value detectors. Each one recognises a format and, where
 * the format has one, validates its check digit, so a random number is not taken for a document.
 * Used first by the leak meter (what reached the model) and later by the masking itself.
 * Universal formats first; national documents grouped by country.
 */

export type SensitiveType =
  | "email"
  | "card"
  | "iban"
  | "phone"
  | "jwt"
  | "private_key"
  | "api_key"
  | "ar_cuit"
  | "ar_cbu"
  | "br_cpf"
  | "cl_rut"
  | "mx_curp"
  | "es_dni"
  | "ar_dni"
  | "us_ssn";

export interface Detection {
  type: SensitiveType;
  value: string;
  index: number;
}

const digits = (s: string) => s.replace(/\D/g, "");

function luhn(num: string): boolean {
  let sum = 0;
  let dbl = false;
  for (let i = num.length - 1; i >= 0; i--) {
    let d = Number(num[i]);
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

/** CUIT/CUIL: module 11 with weights 5,4,3,2,7,6,5,4,3,2. */
export function validCuit(value: string): boolean {
  const d = digits(value);
  if (d.length !== 11 || !/^(20|23|24|27|30|33|34)/.test(d)) return false;
  const w = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
  const sum = w.reduce((acc, x, i) => acc + x * Number(d[i]), 0);
  let check = 11 - (sum % 11);
  if (check === 11) check = 0;
  if (check === 10) return false;
  return check === Number(d[10]);
}

/** CBU: two blocks (8 and 14 digits), each with its own check digit. */
export function validCbu(value: string): boolean {
  const d = digits(value);
  if (d.length !== 22) return false;
  const block = (b: string, w: number[]) => {
    const sum = w.reduce((acc, x, i) => acc + x * Number(b[i]), 0);
    return (10 - (sum % 10)) % 10 === Number(b[b.length - 1]);
  };
  return block(d.slice(0, 8), [7, 1, 3, 9, 7, 1, 3]) && block(d.slice(8), [3, 9, 7, 1, 3, 9, 7, 1, 3, 9, 7, 1, 3]);
}

/** CPF (Brazil): two check digits, module 11. */
export function validCpf(value: string): boolean {
  const d = digits(value);
  if (d.length !== 11 || /^(\d)\1{10}$/.test(d)) return false;
  const check = (n: number) => {
    let sum = 0;
    for (let i = 0; i < n; i++) sum += Number(d[i]) * (n + 1 - i);
    const r = (sum * 10) % 11;
    return (r === 10 ? 0 : r) === Number(d[n]);
  };
  return check(9) && check(10);
}

/** RUT (Chile): module 11 with weights 2..7, check digit 0-9 or K. */
export function validRut(value: string): boolean {
  const m = /^(\d{1,2}\.?\d{3}\.?\d{3})-?([\dkK])$/.exec(value.trim());
  if (!m) return false;
  const body = digits(m[1]!);
  let sum = 0;
  let mul = 2;
  for (let i = body.length - 1; i >= 0; i--) {
    sum += Number(body[i]) * mul;
    mul = mul === 7 ? 2 : mul + 1;
  }
  const r = 11 - (sum % 11);
  const expected = r === 11 ? "0" : r === 10 ? "K" : String(r);
  return expected === m[2]!.toUpperCase();
}

/** DNI/NIE (Spain): the letter is the number modulo 23. */
export function validEsDni(value: string): boolean {
  const m = /^([XYZ]?)(\d{7,8})([A-Z])$/.exec(value.trim().toUpperCase());
  if (!m) return false;
  const prefix = { "": "", X: "0", Y: "1", Z: "2" }[m[1]!] ?? "";
  const n = Number(prefix + m[2]);
  return "TRWAGMYFPDXBNJZSQVHLCKE"[n % 23] === m[3];
}

/** IBAN: module 97 over the rearranged number. */
export function validIban(value: string): boolean {
  const s = value.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(s)) return false;
  const moved = (s.slice(4) + s.slice(0, 4)).replace(/[A-Z]/g, (c) => String(c.charCodeAt(0) - 55));
  let rem = 0;
  for (const ch of moved) rem = (rem * 10 + Number(ch)) % 97;
  return rem === 1;
}

interface Rule {
  type: SensitiveType;
  re: RegExp;
  valid?: (v: string) => boolean;
}

const RULES: Rule[] = [
  { type: "email", re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  { type: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { type: "private_key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
  { type: "api_key", re: /\b(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|(?:sk|rk)_live_[0-9A-Za-z]{20,}|gh[pousr]_[0-9A-Za-z]{30,}|xox[baprs]-[0-9A-Za-z-]{10,})\b/g },
  { type: "card", re: /\b(?:\d[ -]?){12,18}\d\b/g, valid: (v) => /^[3456]/.test(digits(v)) && digits(v).length >= 13 && luhn(digits(v)) },
  { type: "iban", re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g, valid: validIban },
  { type: "ar_cbu", re: /\b\d{22}\b/g, valid: validCbu },
  { type: "ar_cuit", re: /\b(?:20|23|24|27|30|33|34)-?\d{8}-?\d\b/g, valid: validCuit },
  { type: "br_cpf", re: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b|\b\d{11}\b/g, valid: validCpf },
  { type: "cl_rut", re: /\b\d{1,2}\.\d{3}\.\d{3}-[\dkK]\b/g, valid: validRut },
  { type: "mx_curp", re: /\b[A-Z][AEIOUX][A-Z]{2}\d{6}[HM][A-Z]{5}[A-Z\d]\d\b/g },
  { type: "es_dni", re: /\b[XYZ]?\d{7,8}[A-Z]\b/g, valid: validEsDni },
  // Argentine DNI has no check digit, so it is only taken as one next to a cue word ("DNI 20.123.456"),
  // never as a bare number (which would hide ports, counts or IDs the agent needs).
  { type: "ar_dni", re: /(?<=\b(?:dni|d\.n\.i\.?|documento|doc\.?)\b[\s.:#=-]*(?:n[°ºo]?\.?\s*)?)\d{1,2}\.?\d{3}\.?\d{3}\b/gi, valid: (v) => digits(v).length === 7 || digits(v).length === 8 },
  { type: "us_ssn", re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  { type: "phone", re: /\+\d{1,3}[ -]?(?:\(?\d{1,4}\)?[ -]?){1,3}\d{3,4}[ -]?\d{3,4}\b/g },
];

/** Every sensitive value found in a text, at most once per (type, value). */
export function detect(text: string): Detection[] {
  const out: Detection[] = [];
  const seen = new Set<string>();
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    for (const m of text.matchAll(rule.re)) {
      const value = m[0];
      if (rule.valid && !rule.valid(value)) continue;
      // A CUIT is also 11 digits: do not count it again as a Brazilian CPF.
      if (rule.type === "br_cpf" && /^\d{11}$/.test(value) && validCuit(value)) continue;
      const key = `${rule.type}:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ type: rule.type, value, index: m.index ?? 0 });
    }
  }
  return out;
}
