import type { Engagement } from "../engagement.js";
import { detect, type SensitiveType } from "./detectors.js";
import { flushVault, knownValues, pseudonym } from "./vault.js";

/** Code (a script, a bundle, a template): structure rules for prose must not touch it. */
function looksLikeCode(text: string): boolean {
  const sample = text.slice(0, 20_000);
  const hits = (sample.match(/=>|\bfunction\b|\bconst\b|\breturn\b|[;{}]\s*$/gm) ?? []).length;
  return hits > 5 && hits / Math.max(1, sample.split("\n").length) > 0.05;
}

/**
 * Masking at the source: what a tool returns is walked as a
 * structure before the model reads it. Sensitive values become markers from the vault; the shape,
 * the field names, hosts, routes, IDs and versions stay, because that is what the agent works with.
 *
 * Layers: field names (the most precise: `email`, `dni`, `domicilio`…), detectors with check
 * digits on every string, embedded JSON bodies parsed as structure, session headers, and content
 * fields (health records, notes) replaced by their shape instead of their text.
 */

type Kind = SensitiveType | "name" | "doc" | "address" | "birthdate" | "bank" | "secret" | "content";

/** Field names that say what a value is (Spanish and English, any casing or separator). */
const FIELD: Array<[RegExp, Kind]> = [
  [/^(e?mail|correo|email_?address|correo_?electronico)$/, "email"],
  [/^(password|passwd|pass|contrase(n|ñ)a|clave|pin|otp|secret|client_?secret|api_?key|apikey|x_?api_?key|access_?token|refresh_?token|id_?token|token|session|session_?id|sid|jwt|bearer|authorization|cookie|set_?cookie)$/, "secret"],
  [/^(tel(efono)?|phone(_?number)?|celular|movil|mobile|whatsapp|fax)$/, "phone"],
  [/^(dni|documento|nro_?doc(umento)?|num(ero)?_?doc(umento)?|cedula|ci|pasaporte|passport|ssn|cpf|rut|curp|nie|nif)$/, "doc"],
  [/^(cuit|cuil)$/, "ar_cuit"],
  [/^(cbu|cvu|iban|nro_?cuenta|numero_?cuenta|account_?number|alias_?cbu)$/, "bank"],
  [/^(tarjeta|card(_?number)?|pan|nro_?tarjeta)$/, "card"],
  [/^(direccion|domicilio|address|calle|street|street_?address|direccion_?completa)$/, "address"],
  [/^(fecha_?(de_?)?nacimiento|nacimiento|birth_?date|birthdate|date_?of_?birth|dob|fecha_?nac)$/, "birthdate"],
  [/^(nombre|apellido|apellidos|first_?name|last_?name|full_?name|fullname|nombre_?completo|nombre_?y_?apellido|contacto|contact_?name|responsable|referente|titular|paciente|patient_?name|owner_?name|display_?name|intendente)$/, "name"],
  [/^(diagnostico|diagnosis|historia_?clinica|clinical_?history|medical_?record|obra_?social|health_?insurance|tratamiento|treatment|medicacion|medication|antecedentes|observaciones_?medicas|notas_?clinicas)$/, "content"],
];

const norm = (k: string) => k.normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/([a-z])([A-Z])/g, "$1_$2").replace(/[-\s.]+/g, "_").toLowerCase();

function kindOfField(key: string): Kind | undefined {
  const k = norm(key);
  return FIELD.find(([re]) => re.test(k))?.[1];
}

/**
 * "name" and "nombre" alone are ambiguous (a person, but also a table, a field, an app, an
 * organisation): next to personal data they are a person; next to schema words they are not;
 * otherwise the value decides (it has to look like a person's name).
 */
const AMBIGUOUS_NAME = /^(name|nombre)$/;
const PERSONAL_SIBLINGS = /^(e?mail|correo|tel(efono)?|phone|celular|dni|documento|cuit|cuil|apellido|apellidos|last_?name|direccion|domicilio|address|fecha_?nacimiento|birth_?date|legajo|genero|sexo)$/;
const SCHEMA_SIBLINGS = /^(tipo|type|data_?type|campo|field|fields|columna|column|tabla|table|entidad|entity|modelo|model|descripcion|description|label|etiqueta|slug|codigo|code|clave|key|valor_?por_?defecto|default|nullable|required|requerido|formato|format|longitud|length|version|icon|icono|ruta|route|path|url|endpoint|method|metodo|permisos?|permissions?|scope|domain|dominio|schema)$/;
const NAME_CONNECTOR = /^(de|del|la|las|los|y|da|das|do|dos|van|von|di)$/i;
const ORG_WORD = /^(ministerio|secretar[ií]a|direcci[oó]n|subsecretar[ií]a|municipalidad|municipio|gobierno|provincia|departamento|[aá]rea|sistema|servicio|oficina|instituto|consejo|tribunal|juzgado|banco|hospital|escuela|universidad|empresa|sociedad|asociaci[oó]n|fundaci[oó]n|club|grupo|equipo|admin|administrador|usuario|test|demo)$/i;

/** A value with the shape of a person's name: 2 to 5 capitalised words (connectors allowed), no organisation words. */
function personShaped(v: string): boolean {
  const words = v.trim().split(/\s+/);
  if (words.length < 2 || words.length > 6) return false;
  let capitalised = 0;
  for (const w of words) {
    if (NAME_CONNECTOR.test(w)) continue;
    if (ORG_WORD.test(w) || !/^\p{Lu}[\p{Ll}'’-]+\.?$/u.test(w)) return false;
    capitalised++;
  }
  return capitalised >= 2;
}

/**
 * Whether an ambiguous "name"/"nombre" holds a person here. One classification cannot cover every
 * use of it in an application (a person in one place, a field of the data dictionary in another):
 * the neighbours decide, and only when they say nothing do the agent's word or the value's shape.
 */
function ambiguousIsPerson(value: string, siblings: Record<string, unknown> | undefined, classifiedAsName: boolean): boolean {
  const keys = Object.keys(siblings ?? {}).map(norm);
  if (keys.some((k) => PERSONAL_SIBLINGS.test(k))) return true;
  if (keys.some((k) => SCHEMA_SIBLINGS.test(k))) return false;
  return classifiedAsName || personShaped(value);
}

/** Words that only clinical text uses together (Spanish, English, Portuguese). */
const CLINICAL_TERMS =
  "pacientes?|patients?|diagn[oó]stic[oa]s?|diagnos(?:is|es|ed)|dx|historia cl[ií]nica|historial m[eé]dico|medical record|prontu[aá]rio|motivo de consulta|antecedentes|tratamientos?|treatments?|medicaci[oó]n|medicamentos?|medications?|prescripci[oó]n|prescriptions?|internaci[oó]n|hospitalizaci[oó]n|alergias?|allerg(?:y|ies)|patolog[ií]as?|epicrisis|s[ií]ntomas|symptoms|obra social|prepaga";
const CLINICAL_WORD = new RegExp(`\\b(?:${CLINICAL_TERMS})\\b`, "giu");
/**
 * A date of birth in prose: a date only right after a birth cue ("nacido el 1975-03-12", "DOB:
 * 12/03/1975", "born on 12 March 1975"). Dates alone are everywhere in pages and logs.
 */
const BIRTH_IN_PROSE =
  /\b((?:nacid[oa]s?|nascid[oa]|born)(?: (?:el|on|em|en))?|fecha de nacimiento|f\. ?nac\.?|fecha nac\.?|date of birth|birth ?date|dob|data de nascimento)([ \t]*[:,]?[ \t]*)(\d{4}-\d{2}-\d{2}|\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{1,2} (?:de )?[\p{L}]{3,10}\.?(?: (?:de )?| )\d{4})/giu;

/** A medical record number: HC-123456, NHC 98765, MRN 004512. */
const RECORD_NUMBER = /\b(?:HC|NHC|HCE|MRN)[-\s#:]?\s?\d{4,}\b/g;
const CLINICAL_HINT = new RegExp(`\\b(?:${CLINICAL_TERMS}|HC|NHC|HCE|MRN)\\b`, "iu");

const HEADER_SECRETS =/^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token)$/i;

const emailHint = (v: string) => {
  const at = v.lastIndexOf("@");
  return at > 0 ? v.slice(at) : undefined;
};

export interface MaskStats {
  masked: number;
  byKind: Record<string, number>;
}

/** Kinds a field can be classified as (by the agent, seeing only names). */
export const FIELD_KINDS = ["name", "email", "phone", "doc", "ar_cuit", "address", "birthdate", "bank", "card", "content", "secret", "none"] as const;
export type FieldKind = (typeof FIELD_KINDS)[number];

const UNCLASSIFIED_CAP = 3000;

class Masker {
  readonly stats: MaskStats = { masked: 0, byKind: {} };
  /** This application's own field names, as the agent classified them (only names, never values). */
  private readonly classes: Record<string, FieldKind>;
  /** Field names seen with text values that no rule recognises: candidates for classification. */
  readonly unseen = new Set<string>();
  /** Inside data the target sent (a response body), as opposed to Penteos's own result fields. */
  private inTarget = false;
  constructor(private readonly e: Engagement) {
    this.classes = e.getState<Record<string, FieldKind>>("fieldClasses") ?? {};
  }

  /** What a field is: this application's classification first, then the general rules. */
  private kindOf(key: string): Kind | undefined {
    const c = this.classes[norm(key)];
    if (c) return c === "none" ? undefined : (c as Kind);
    return kindOfField(key);
  }

  private mark(kind: string, value: string, hint?: string): string {
    this.stats.masked++;
    this.stats.byKind[kind] = (this.stats.byKind[kind] ?? 0) + 1;
    return pseudonym(this.e, kind, value, hint);
  }

  /** A whole value under a field whose name says what it is. */
  private byField(kind: Kind, value: string): string {
    if (kind === "email") return this.mark("email", value, emailHint(value));
    if (kind === "secret") return this.secretValue(value);
    if (kind === "content") return this.mark("content", value, `${value.length} chars`);
    if (kind === "card") return this.mark("card", value, value.replace(/\D/g, "").length >= 4 ? `ends in ${value.replace(/\D/g, "").slice(-4)}` : undefined);
    return this.mark(kind, value);
  }

  /** Session values keep their structure: cookie names, "Bearer", JWT header and claim names. */
  private secretValue(value: string): string {
    const bearer = /^(Bearer|Basic|Token)\s+(.+)$/i.exec(value);
    if (bearer) return `${bearer[1]} ${this.mark("secret", bearer[2]!, this.jwtHint(bearer[2]!))}`;
    // Cookies: "a=1; b=2; Path=/; HttpOnly" - names and attributes stay, values go.
    if (/^[\w.-]+=/.test(value) && /;|=/.test(value)) {
      return value
        .split(/;\s*/)
        .map((part) => {
          const eq = part.indexOf("=");
          if (eq < 0) return part;
          const name = part.slice(0, eq);
          const v = part.slice(eq + 1);
          if (/^(path|domain|expires|max-age|samesite)$/i.test(name) || v === "") return part;
          return `${name}=${this.mark("secret", v, this.jwtHint(v))}`;
        })
        .join("; ");
    }
    return this.mark("secret", value, this.jwtHint(value));
  }

  /** What a JWT reveals that matters for testing: its algorithm and claim names, never the values. */
  private jwtHint(v: string): string | undefined {
    const m = /^eyJ([A-Za-z0-9_-]+)\.eyJ([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)$/.exec(v.trim());
    if (!m) return undefined;
    try {
      const head = JSON.parse(Buffer.from(`eyJ${m[1]}`, "base64url").toString("utf8")) as { alg?: string };
      const body = JSON.parse(Buffer.from(`eyJ${m[2]}`, "base64url").toString("utf8")) as Record<string, unknown>;
      return `JWT ${head.alg ?? "?"} claims ${Object.keys(body).slice(0, 8).join(",")}`;
    } catch {
      return "JWT";
    }
  }

  /** Any string: embedded JSON as structure, else every detected value replaced. */
  text(s: string): string {
    // A raw HTTP message (raw_get, an exchange): headers line by line, the body as structure.
    const http = /^(?:HTTP\/[\d.]+ \d{3}[^\n]*|[A-Z]+ \S+ HTTP\/[\d.]+)\r?\n/.exec(s);
    if (http) {
      const split = s.search(/\r?\n\r?\n/);
      const head = split >= 0 ? s.slice(0, split) : s;
      const rest = split >= 0 ? s.slice(split) : "";
      const sep = /^\r?\n\r?\n/.exec(rest)?.[0] ?? "";
      const lines = head.split(/\r?\n/).map((line, i) => {
        if (i === 0) return this.text(line);
        const colon = line.indexOf(":");
        if (colon < 0) return line;
        const name = line.slice(0, colon);
        const value = line.slice(colon + 1).trim();
        return HEADER_SECRETS.test(name) ? `${name}: ${this.secretValue(value)}` : `${name}: ${this.text(value)}`;
      });
      return lines.join("\r\n") + sep + (rest ? this.text(rest.slice(sep.length)) : "");
    }
    const t = s.trim();
    if (t.length > 1 && ((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]")))) {
      try {
        const parsed: unknown = JSON.parse(t);
        // JSON inside a text is a body the target sent: its field names are the application's.
        const was = this.inTarget;
        this.inTarget = true;
        try {
          return JSON.stringify(this.value(parsed));
        } finally {
          this.inTarget = was;
        }
      } catch {
        /* not JSON: masked as text */
      }
    }
    // Layer 2: structure inside the text (tables, forms, "Label: value" lines).
    let out = this.structured(s);
    // A birth date in prose, recognised by the words before it.
    if (/\d/.test(out)) out = out.replace(BIRTH_IN_PROSE, (_m, cue: string, gap: string, date: string) => `${cue}${gap}${this.mark("birthdate", date)}`);
    // Values with a format (and a check digit where there is one).
    if (/[@\d]|eyJ|-----BEGIN/.test(out)) {
      // Longest first: a value that contains another is replaced whole.
      const found = detect(out).sort((a, b) => b.value.length - a.value.length);
      for (const d of found) {
        // Replace every occurrence of the value (detect reports each value once).
        const marker = d.type === "jwt" || d.type === "private_key" || d.type === "api_key" ? this.secretValue(d.value) : this.mark(d.type, d.value, d.type === "email" ? emailHint(d.value) : undefined);
        out = out.split(d.value).join(marker);
      }
    }
    // Layer 1: whatever the vault already knows, wherever it appears again.
    return this.propagate(out);
  }

  /** Values the vault already holds, replaced by their markers in free text. */
  private propagate(text: string): string {
    if (text.length < 5) return text;
    const known = knownValues(this.e);
    const re = known.regexFor(text);
    if (!re) return text;
    return text.replace(re, (found) => {
      const marker = known.markerOf(found);
      if (!marker) return found;
      this.stats.masked++;
      this.stats.byKind.known = (this.stats.byKind.known ?? 0) + 1;
      return marker;
    });
  }

  /**
   * Structure hidden in text: CSV/TSV tables (by their header), HTML tables and form fields, and
   * "Label: value" lines. Never applied to code: in a script, `email: e.target.value` is not an
   * e-mail address.
   */
  private structured(text: string): string {
    let out = text;
    if (/<table[\s>]/i.test(out)) out = this.htmlTables(out);
    if (/<input\b/i.test(out)) out = this.htmlInputs(out);
    if (looksLikeCode(out)) return out;
    const table = this.csv(out);
    return this.clinical(table ?? this.labelLines(out));
  }

  /**
   * Clinical prose: a diagnosis has no format to detect, so the context decides. A line that
   * carries a medical record number, or two different clinical words, is a clinical note: its label
   * stays, the note becomes one marker («content:N clinical note, 54 chars»). The agent still knows
   * health data is exposed, and how much; it never reads it. One word alone ("Patients" in a menu)
   * is not enough.
   */
  private clinical(text: string): string {
    if (!CLINICAL_HINT.test(text)) return text;
    return text.replace(/^([ \t]*)([^\r\n]+)$/gm, (whole, indent: string, line: string) => {
      const record = RECORD_NUMBER.test(line);
      RECORD_NUMBER.lastIndex = 0;
      const signals = new Set([...line.matchAll(CLINICAL_WORD)].map((m) => m[0]!.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").slice(0, 6)));
      if (!record && signals.size < 2) return whole;
      // A line of code that names clinical things (`const patients = …`) is not a note.
      if (/[{};]|=>/.test(line) || /\b(const|let|var|function|return|import|class)\b/.test(line)) return whole;
      // A short label before the first colon stays ("Historia «health_record:1»:"); the rest is the note.
      const colon = line.replace(RECORD_NUMBER, (code) => "#".repeat(code.length)).indexOf(":");
      RECORD_NUMBER.lastIndex = 0;
      const hasLabel = colon > 0 && colon <= 60;
      const label = hasLabel ? line.slice(0, colon + 1).replace(RECORD_NUMBER, (code) => this.mark("health_record", code)) : "";
      RECORD_NUMBER.lastIndex = 0;
      const rest = (hasLabel ? line.slice(colon + 1) : line).trim();
      // The record number is the note's handle: masked on its own, so the agent can still tell notes apart.
      const note = rest.replace(RECORD_NUMBER, (code) => this.mark("health_record", code));
      RECORD_NUMBER.lastIndex = 0;
      if (!rest) return `${indent}${label}`;
      const free = note.replace(/«[^»]+»/g, "").replace(/[\s.,;:()-]/g, "");
      if (!free) return `${indent}${label}${label ? " " : ""}${note}`;
      return `${indent}${label}${label ? " " : ""}${this.mark("content", rest, `clinical note, ${rest.length} chars`)}`;
    });
  }

  private csv(text: string): string | undefined {
    const lines = text.split(/\r?\n/);
    if (lines.length < 3) return undefined;
    const sep = [";", "\t", ",", "|"].find((d) => {
      const n = lines[0]!.split(d).length;
      if (n < 2) return false;
      const rows = lines.slice(1).filter((l) => l.trim());
      return rows.length >= 2 && rows.filter((l) => l.split(d).length === n).length / rows.length >= 0.8;
    });
    if (!sep) return undefined;
    const header = lines[0]!.split(sep).map((h) => h.trim().replace(/^"|"$/g, ""));
    const kinds = header.map((h) => (/^[\p{L}_ .-]{1,40}$/u.test(h) ? this.kindOf(h) : undefined));
    if (!kinds.some(Boolean)) return undefined;
    return lines
      .map((line, i) => {
        if (i === 0 || !line.trim()) return line;
        const cells = line.split(sep);
        if (cells.length !== header.length) return line;
        return cells.map((cell, c) => (kinds[c] && cell.trim() ? cell.replace(cell.trim().replace(/^"|"$/g, ""), (v) => (v ? this.byField(kinds[c]!, v) : v)) : cell)).join(sep);
      })
      .join("\n");
  }

  private labelLines(text: string): string {
    if (!/:/.test(text)) return text;
    return text.replace(/^([ \t]*)([\p{L}][\p{L} ._-]{1,38}?)([ \t]*:[ \t]*)([^\r\n]+?)[ \t]*$/gmu, (whole, indent: string, label: string, colon: string, value: string) => {
      const kind = this.kindOf(label.trim());
      if (!kind || /^[«]/.test(value) || /[{}();=]|=>|\breturn\b/.test(value)) return whole;
      return `${indent}${label}${colon}${this.byField(kind, value)}`;
    });
  }

  private htmlInputs(html: string): string {
    return html.replace(/<input\b[^>]*>/gi, (tag) => {
      const name = /\b(?:name|id)\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1];
      const kind = name ? this.kindOf(name) : undefined;
      if (!kind) return tag;
      return tag.replace(/(\bvalue\s*=\s*["'])([^"']+)(["'])/i, (_m, a: string, v: string, b: string) => `${a}${this.byField(kind, v)}${b}`);
    });
  }

  private htmlTables(html: string): string {
    return html.replace(/<table[\s\S]*?<\/table>/gi, (table) => {
      const heads = [...table.matchAll(/<th\b[^>]*>([\s\S]*?)<\/th>/gi)].map((m) => m[1]!.replace(/<[^>]+>/g, "").trim());
      const kinds = heads.map((h) => this.kindOf(h));
      if (!kinds.some(Boolean)) return table;
      return table.replace(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi, (row) => {
        let col = -1;
        return row.replace(/(<td\b[^>]*>)([\s\S]*?)(<\/td>)/gi, (_m, open: string, cell: string, close: string) => {
          col++;
          const kind = kinds[col];
          const text = cell.replace(/<[^>]+>/g, "").trim();
          return kind && text ? `${open}${this.byField(kind, text)}${close}` : `${open}${cell}${close}`;
        });
      });
    });
  }

  value(v: unknown, key?: string, siblings?: Record<string, unknown>): unknown {
    if (typeof v === "string") {
      if (!v) return v;
      let kind = key ? this.kindOf(key) : undefined;
      if (kind === "name" && AMBIGUOUS_NAME.test(norm(key!)) && !ambiguousIsPerson(v, siblings, this.classes[norm(key!)] === "name")) kind = undefined;
      // A text value under a name no rule knows, in the target's data: a candidate for the agent
      // to classify (Penteos's own result fields are not the application's).
      if (!kind && this.inTarget && key && key in (siblings ?? {}) && !AMBIGUOUS_NAME.test(norm(key)) && this.classes[norm(key)] === undefined && /^[\p{L} .'-]{3,80}$/u.test(v.trim())) this.unseen.add(norm(key));
      return kind ? this.byField(kind, v) : this.text(v);
    }
    if (typeof v === "number" && key) {
      const kind = this.kindOf(key);
      if (kind && ["doc", "phone", "ar_cuit", "bank", "card"].includes(kind)) return this.byField(kind, String(v));
      return v;
    }
    if (Array.isArray(v)) {
      // Header lists: [["Set-Cookie", "sid=…"], …]
      if (v.length === 2 && typeof v[0] === "string" && typeof v[1] === "string" && HEADER_SECRETS.test(v[0])) return [v[0], this.secretValue(v[1])];
      return v.map((x) => this.value(x));
    }
    if (v && typeof v === "object") {
      const o = v as Record<string, unknown>;
      return Object.fromEntries(Object.entries(o).map(([k, x]) => [k, HEADER_SECRETS.test(k) && typeof x === "string" ? this.secretValue(x) : this.value(x, k, o)]));
    }
    return v;
  }
}

/** A tool's result as the model may see it, with the counts of what was masked. */
export function maskForModel(e: Engagement, value: unknown): { value: unknown; stats: MaskStats; newFields: number } {
  const m = new Masker(e);
  const out = m.value(value);
  flushVault(e);
  return { value: out, stats: m.stats, newFields: rememberUnclassified(e, m.unseen) };
}

/** Field names no rule knows, kept (names only) for the agent to classify. Returns how many are new. */
function rememberUnclassified(e: Engagement, names: Set<string>): number {
  if (!names.size) return 0;
  try {
    const list = new Set(e.getState<string[]>("unclassifiedFields") ?? []);
    const before = list.size;
    for (const n of names) if (list.size < UNCLASSIFIED_CAP) list.add(n);
    if (list.size !== before) e.setState("unclassifiedFields", [...list]);
    return list.size - before;
  } catch {
    return 0;
  }
}

/** The application's field names still to classify, and the ones already classified. */
export function fieldClassification(e: Engagement): { unclassified: string[]; classified: Record<string, FieldKind> } {
  const classified = e.getState<Record<string, FieldKind>>("fieldClasses") ?? {};
  return { unclassified: (e.getState<string[]>("unclassifiedFields") ?? []).filter((n) => !(n in classified)), classified };
}

/** The agent's classification of field names (it saw names only). */
export function classifyFields(e: Engagement, fields: Array<{ name: string; kind: FieldKind }>): number {
  const classified = { ...(e.getState<Record<string, FieldKind>>("fieldClasses") ?? {}) };
  for (const f of fields) classified[norm(f.name)] = f.kind;
  e.setState("fieldClasses", classified);
  return Object.keys(classified).length;
}

/** Free text (an operator's message, an error) as the model may see it. */
export function maskText(e: Engagement, text: string): { text: string; stats: MaskStats } {
  const m = new Masker(e);
  const out = m.text(text);
  flushVault(e);
  return { text: out, stats: m.stats };
}
