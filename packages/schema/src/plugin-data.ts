import { z } from "zod";
import { ENTITY_KINDS, EntityKind } from "./entities.js";

/**
 * What a plugin keeps. Three places, never a table or
 * a column in the project's own database:
 *  - entity types of its own in the graph (`acme.shodan:banner`), validated by declared fields;
 *  - annotations on official entities, in a space of its own (never an official field);
 *  - tables in a SQLite of its own, created and migrated by Penteos from declared migrations.
 * Everything here is data: the core turns it into validation and SQL; a plugin never writes SQL.
 */

// ---------------------------------------------------------------------------------------------
// Fields: the one vocabulary for entity attributes, annotations and (later) forms
// ---------------------------------------------------------------------------------------------

export const FieldName = z.string().regex(/^[a-z][a-zA-Z0-9_]{0,39}$/, "expected a field name like port or bannerText");

export const FIELD_TYPES = ["string", "text", "number", "integer", "boolean", "date", "url", "host", "enum", "tags", "json"] as const;

/**
 * A plugin's own words: one string, or Spanish and English. The interface shows the operator's
 * language and falls back to the other; a plugin never writes into Penteos's catalogs.
 */
export const pluginText = (max: number) =>
  z.union([
    z.string().min(1).max(max),
    z
      .object({ es: z.string().min(1).max(max), en: z.string().min(1).max(max) })
      .partial()
      .strict()
      .refine((t) => Boolean(t.es || t.en), "give es, en or both"),
  ]);
export const PluginText = pluginText(500);
export type PluginText = z.infer<typeof PluginText>;

/** The text in a language, falling back to the other one. */
export function textOf(t: PluginText | undefined, lang: "es" | "en" = "en"): string {
  if (t === undefined) return "";
  if (typeof t === "string") return t;
  return (lang === "es" ? (t.es ?? t.en) : (t.en ?? t.es)) ?? "";
}

export const FieldSpec = z
  .object({
    name: FieldName,
    type: z.enum(FIELD_TYPES),
    label: pluginText(80).optional(),
    /** One line under the field in a form. */
    help: pluginText(300).optional(),
    placeholder: pluginText(120).optional(),
    required: z.boolean().default(false),
    /** The value when none is given (forms show it; operations use it). */
    default: z.unknown().optional(),
    /** enum: the allowed values. */
    values: z.array(z.string().min(1).max(80)).min(1).max(100).optional(),
    /** string/text: maximum length; number/integer: maximum value. */
    max: z.number().optional(),
    min: z.number().optional(),
    /**
     * Settings only: an API key or token. Stored encrypted, never shown again, and usable only
     * inside an HTTP request of the plugin (never in a result, a log or the graph).
     */
    secret: z.boolean().default(false),
  })
  .strict()
  .refine((f) => f.type !== "enum" || Boolean(f.values), { message: "an enum field needs values", path: ["values"] })
  .refine((f) => !f.secret || f.type === "string", { message: "a secret field is a string", path: ["secret"] })
  .refine((f): boolean => f.default === undefined || fieldSchema({ ...(f as FieldShape), required: true, default: undefined }).safeParse(f.default).success, { message: "the default does not fit the field", path: ["default"] });
export type FieldSpec = z.infer<typeof FieldSpec>;

const MAX_STRING = 100_000;
const MAX_TEXT = 200_000;
/** A json field holds at most this many bytes once serialized. */
export const MAX_JSON_FIELD_BYTES = 64 * 1024;

const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$|^\d{1,3}(?:\.\d{1,3}){3}$|^[0-9a-f:]+$/i;

/** Size of a value once serialized as JSON (what it costs to store). */
export function jsonBytes(v: unknown): number {
  return new TextEncoder().encode(JSON.stringify(v) ?? "").length;
}

/** What building a validator needs from a field (kept apart from FieldSpec to avoid a cycle). */
interface FieldShape {
  type: (typeof FIELD_TYPES)[number];
  required?: boolean;
  default?: unknown;
  values?: string[] | undefined;
  max?: number | undefined;
  min?: number | undefined;
}

function fieldSchema(f: FieldShape): z.ZodType {
  let s: z.ZodType;
  switch (f.type) {
    case "string":
      s = z.string().max(Math.min(f.max ?? 2000, MAX_STRING));
      break;
    case "text":
      s = z.string().max(Math.min(f.max ?? 20_000, MAX_TEXT));
      break;
    case "number": {
      let n = z.number().finite();
      if (f.min !== undefined) n = n.min(f.min);
      if (f.max !== undefined) n = n.max(f.max);
      s = n;
      break;
    }
    case "integer": {
      let n = z.number().int();
      if (f.min !== undefined) n = n.min(f.min);
      if (f.max !== undefined) n = n.max(f.max);
      s = n;
      break;
    }
    case "boolean":
      s = z.boolean();
      break;
    case "date":
      s = z.string().datetime({ offset: true });
      break;
    case "url":
      s = z.string().max(4000).url();
      break;
    case "host":
      s = z.string().max(253).regex(HOST_RE, "expected a host name or an IP address");
      break;
    case "enum":
      s = z.enum(f.values as [string, ...string[]]);
      break;
    case "tags":
      s = z.array(z.string().min(1).max(200)).max(200);
      break;
    default:
      s = z.unknown().refine((v) => v !== undefined && jsonBytes(v) <= MAX_JSON_FIELD_BYTES, {
        message: `expected JSON of at most ${MAX_JSON_FIELD_BYTES} bytes`,
      });
      break;
  }
  if (f.default !== undefined) return s.default(f.default);
  return f.required ? s : s.optional();
}

/** Fields that may never be secret (graph data is shown, searched and sent to the model). */
function noSecrets(fields: FieldSpec[], ctx: z.RefinementCtx, path: (string | number)[]): void {
  fields.forEach((f, i) => {
    if (f.secret) ctx.addIssue({ code: "custom", message: "secret fields belong in settings, not in the graph", path: [...path, i, "secret"] });
  });
}

/** The validator for a set of declared fields: strict (an unknown field is an error, not lost data). */
export function fieldsSchema(fields: readonly FieldSpec[]): z.ZodObject<Record<string, z.ZodType>> {
  return z.object(Object.fromEntries(fields.map((f) => [f.name, fieldSchema(f)]))).strict();
}

export function uniqueNames(list: Array<{ name: string }>, ctx: z.RefinementCtx, path: (string | number)[], what: string): void {
  const seen = new Set<string>();
  list.forEach((item, i) => {
    if (seen.has(item.name)) ctx.addIssue({ code: "custom", message: `duplicate ${what} "${item.name}"`, path: [...path, i, "name"] });
    seen.add(item.name);
  });
}

// ---------------------------------------------------------------------------------------------
// Entity types of its own
// ---------------------------------------------------------------------------------------------

/** `<pluginId>:<name>`: every plugin kind carries its owner, so it can never clash with an official one. */
export const PLUGIN_KIND_RE = /^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+:[a-z][a-z0-9_]{0,31}$/;
export type PluginKind = `${string}:${string}`;
export const PluginKindName = z
  .string()
  .regex(PLUGIN_KIND_RE, "expected a plugin kind like acme.shodan:banner")
  .transform((k) => k as PluginKind);

export function pluginKind(pluginId: string, name: string): PluginKind {
  return `${pluginId}:${name}`;
}

export function isPluginKind(kind: string): kind is PluginKind {
  return PLUGIN_KIND_RE.test(kind);
}

/** The plugin that owns a kind, or undefined for an official kind. */
export function ownerOfKind(kind: string): string | undefined {
  return isPluginKind(kind) ? kind.slice(0, kind.indexOf(":")) : undefined;
}

/** Official kind or a plugin's own kind (what an `entity.query` accepts). */
export const AnyEntityKind = z.union([EntityKind, PluginKindName]);
export type AnyEntityKind = EntityKind | PluginKind;

export const EntityTypeSpec = z
  .object({
    name: z.string().regex(/^[a-z][a-z0-9_]{0,31}$/, "expected a type name like banner"),
    label: pluginText(80),
    /** One-line description, shown in the generic view and to the Maestro. */
    description: pluginText(300).optional(),
    fields: z.array(FieldSpec).min(1).max(64),
    /** Fields that identify one: putting the same key again updates it instead of adding another. */
    key: z.array(FieldName).min(1).max(4).optional(),
    /** The field shown as its name in lists. */
    title: FieldName.optional(),
    /** A host or url field: an entity outside the scope is marked so, like an official one. */
    target: FieldName.optional(),
  })
  .strict()
  .superRefine((t, ctx) => {
    uniqueNames(t.fields, ctx, ["fields"], "field");
    noSecrets(t.fields, ctx, ["fields"]);
    const byName = new Map(t.fields.map((f) => [f.name, f]));
    for (const [i, k] of (t.key ?? []).entries()) {
      const f = byName.get(k);
      if (!f) ctx.addIssue({ code: "custom", message: `key field "${k}" is not declared`, path: ["key", i] });
      else if (!f.required) ctx.addIssue({ code: "custom", message: `key field "${k}" must be required`, path: ["key", i] });
      else if (f.type === "json" || f.type === "tags" || f.type === "text") ctx.addIssue({ code: "custom", message: `key field "${k}" cannot be ${f.type}`, path: ["key", i] });
    }
    if (t.title && !byName.has(t.title)) ctx.addIssue({ code: "custom", message: `title field "${t.title}" is not declared`, path: ["title"] });
    if (t.target) {
      const f = byName.get(t.target);
      if (!f) ctx.addIssue({ code: "custom", message: `target field "${t.target}" is not declared`, path: ["target"] });
      else if (f.type !== "host" && f.type !== "url") ctx.addIssue({ code: "custom", message: `target field "${t.target}" must be host or url`, path: ["target"] });
    }
  });
export type EntityTypeSpec = z.infer<typeof EntityTypeSpec>;

// ---------------------------------------------------------------------------------------------
// Annotations on official entities
// ---------------------------------------------------------------------------------------------

/** Kinds a plugin may annotate. The engagement itself, scope rules and secrets-like kinds are not. */
export const ANNOTATABLE_KINDS = ENTITY_KINDS.filter((k) => k !== "engagement" && k !== "client" && k !== "scope_rule" && k !== "credential");

export const AnnotationSpec = z
  .object({
    on: z.array(EntityKind).min(1).max(ANNOTATABLE_KINDS.length),
    fields: z.array(FieldSpec).min(1).max(32),
  })
  .strict()
  .superRefine((a, ctx) => {
    uniqueNames(a.fields, ctx, ["fields"], "field");
    noSecrets(a.fields, ctx, ["fields"]);
    a.on.forEach((k, i) => {
      if (!(ANNOTATABLE_KINDS as readonly string[]).includes(k)) ctx.addIssue({ code: "custom", message: `"${k}" entities cannot be annotated by plugins`, path: ["on", i] });
    });
    // Annotations are partial by nature: a plugin fills them in as it learns.
    a.fields.forEach((f, i) => {
      if (f.required) ctx.addIssue({ code: "custom", message: "annotation fields cannot be required", path: ["fields", i, "required"] });
    });
  });
export type AnnotationSpec = z.infer<typeof AnnotationSpec>;

/** An annotation is at most this big once serialized. */
export const MAX_ANNOTATION_BYTES = 64 * 1024;

// ---------------------------------------------------------------------------------------------
// Tables of its own: declared migrations, replayed by the core
// ---------------------------------------------------------------------------------------------

const SqlName = z
  .string()
  .regex(/^[a-z][a-z0-9_]{0,39}$/, "expected a lowercase name like scan_cache")
  .refine((n) => !n.startsWith("sqlite_") && !n.startsWith("_penteos"), "reserved name");

/** Columns every table gets on its own: a row id and when it was written. */
export const IMPLICIT_COLUMNS = ["id", "created_at", "updated_at"] as const;

export const COLUMN_TYPES = ["text", "integer", "real", "boolean", "date", "json"] as const;

export const ColumnSpec = z
  .object({
    name: SqlName.refine((n) => !(IMPLICIT_COLUMNS as readonly string[]).includes(n), "id, created_at and updated_at are added by Penteos"),
    type: z.enum(COLUMN_TYPES),
    required: z.boolean().default(false),
    /** Encrypted with the project's key at rest; not filterable, not sortable, not indexable. */
    sensitive: z.boolean().default(false),
    default: z.union([z.string().max(1000), z.number().finite(), z.boolean()]).optional(),
  })
  .strict()
  .superRefine((c, ctx) => {
    if (c.sensitive && c.type !== "text" && c.type !== "json") ctx.addIssue({ code: "custom", message: "only text and json columns can be sensitive", path: ["sensitive"] });
    if (c.sensitive && c.default !== undefined) ctx.addIssue({ code: "custom", message: "a sensitive column cannot have a default", path: ["default"] });
    if (c.default !== undefined && !defaultFits(c.type, c.default)) ctx.addIssue({ code: "custom", message: `default does not fit a ${c.type} column`, path: ["default"] });
  });
export type ColumnSpec = z.infer<typeof ColumnSpec>;

function defaultFits(type: ColumnSpec["type"], v: string | number | boolean): boolean {
  switch (type) {
    case "text":
    case "date":
      return typeof v === "string";
    case "integer":
      return typeof v === "number" && Number.isInteger(v);
    case "real":
      return typeof v === "number";
    case "boolean":
      return typeof v === "boolean";
    case "json":
      return typeof v === "string" && isJson(v);
  }
}

function isJson(v: string): boolean {
  try {
    JSON.parse(v);
    return true;
  } catch {
    return false;
  }
}

export const MigrationStep = z.discriminatedUnion("op", [
  z.object({ op: z.literal("create_table"), table: SqlName, columns: z.array(ColumnSpec).min(1).max(64) }).strict(),
  z.object({ op: z.literal("add_column"), table: SqlName, column: ColumnSpec }).strict(),
  z.object({ op: z.literal("rename_column"), table: SqlName, from: SqlName, to: SqlName }).strict(),
  z.object({ op: z.literal("drop_column"), table: SqlName, column: SqlName }).strict(),
  z.object({ op: z.literal("create_index"), table: SqlName, name: SqlName, columns: z.array(SqlName).min(1).max(8), unique: z.boolean().default(false) }).strict(),
  z.object({ op: z.literal("drop_index"), name: SqlName }).strict(),
  z.object({ op: z.literal("drop_table"), table: SqlName }).strict(),
]);
export type MigrationStep = z.infer<typeof MigrationStep>;

export const Migration = z
  .object({
    version: z.number().int().min(1),
    steps: z.array(MigrationStep).min(1).max(50),
  })
  .strict();
export type Migration = z.infer<typeof Migration>;

/** Quota of one plugin database, in megabytes. */
export const STORAGE_QUOTA_MB = { default: 64, max: 1024 } as const;

export const StorageSpec = z
  .object({
    quotaMb: z.number().int().min(1).max(STORAGE_QUOTA_MB.max).default(STORAGE_QUOTA_MB.default),
    /** Tables per project: `<project>/plugins/<id>/data.db` (travels with the project). */
    project: z.array(Migration).max(200).default([]),
    /** Tables shared by every project: `<dataDir>/plugin-data/<id>/global.db` (settings, caches). */
    global: z.array(Migration).max(200).default([]),
  })
  .strict()
  .superRefine((s, ctx) => {
    for (const scope of ["project", "global"] as const) {
      try {
        replayMigrations(s[scope]);
      } catch (e) {
        ctx.addIssue({ code: "custom", message: e instanceof Error ? e.message : String(e), path: [scope] });
      }
    }
  });
export type StorageSpec = z.infer<typeof StorageSpec>;

export interface TableShape {
  columns: ColumnSpec[];
}

export interface IndexShape {
  table: string;
  columns: string[];
  unique: boolean;
}

/** What a list of migrations leaves behind: the tables and indexes, at a version. */
export interface StorageShape {
  version: number;
  tables: Record<string, TableShape>;
  indexes: Record<string, IndexShape>;
}

/**
 * Replays migrations on paper and returns the schema they produce, or throws saying which step
 * cannot apply. The manifest is refused at discovery when this throws, so a database never sees an
 * impossible migration; the core runs exactly the steps checked here.
 */
export function replayMigrations(migrations: readonly Migration[], upTo = Number.POSITIVE_INFINITY): StorageShape {
  const shape: StorageShape = { version: 0, tables: {}, indexes: {} };
  let steps = 0;
  for (const [i, m] of migrations.entries()) {
    if (m.version !== i + 1) throw new Error(`migration ${i + 1} has version ${m.version}: versions go 1, 2, 3… with no gaps`);
    if (m.version > upTo) break;
    for (const [j, step] of m.steps.entries()) {
      steps++;
      if (steps > 500) throw new Error("more than 500 migration steps");
      const at = `migration ${m.version}, step ${j + 1} (${step.op})`;
      applyStep(shape, step, at);
    }
    shape.version = m.version;
  }
  return shape;
}

function applyStep(shape: StorageShape, step: MigrationStep, at: string): void {
  const table = (name: string): TableShape => {
    const t = shape.tables[name];
    if (!t) throw new Error(`${at}: table "${name}" does not exist`);
    return t;
  };
  const indexed = (tableName: string, column: string) =>
    Object.entries(shape.indexes).find(([, ix]) => ix.table === tableName && ix.columns.includes(column))?.[0];
  switch (step.op) {
    case "create_table": {
      if (shape.tables[step.table]) throw new Error(`${at}: table "${step.table}" already exists`);
      if (Object.keys(shape.tables).length >= 64) throw new Error(`${at}: more than 64 tables`);
      const seen = new Set<string>();
      for (const c of step.columns) {
        if (seen.has(c.name)) throw new Error(`${at}: duplicate column "${c.name}"`);
        seen.add(c.name);
      }
      shape.tables[step.table] = { columns: step.columns.map((c) => ({ ...c })) };
      return;
    }
    case "add_column": {
      const t = table(step.table);
      if (t.columns.some((c) => c.name === step.column.name)) throw new Error(`${at}: column "${step.column.name}" already exists`);
      if (t.columns.length >= 64) throw new Error(`${at}: more than 64 columns`);
      // Existing rows need a value: a required column added later must say which.
      if (step.column.required && step.column.default === undefined) throw new Error(`${at}: a required column added later needs a default`);
      t.columns.push({ ...step.column });
      return;
    }
    case "rename_column": {
      const t = table(step.table);
      const c = t.columns.find((x) => x.name === step.from);
      if (!c) throw new Error(`${at}: column "${step.from}" does not exist`);
      if ((IMPLICIT_COLUMNS as readonly string[]).includes(step.to)) throw new Error(`${at}: "${step.to}" is reserved`);
      if (t.columns.some((x) => x.name === step.to)) throw new Error(`${at}: column "${step.to}" already exists`);
      c.name = step.to;
      for (const ix of Object.values(shape.indexes)) if (ix.table === step.table) ix.columns = ix.columns.map((n) => (n === step.from ? step.to : n));
      return;
    }
    case "drop_column": {
      const t = table(step.table);
      if (!t.columns.some((c) => c.name === step.column)) throw new Error(`${at}: column "${step.column}" does not exist`);
      const ix = indexed(step.table, step.column);
      if (ix) throw new Error(`${at}: column "${step.column}" is used by index "${ix}"; drop the index first`);
      if (t.columns.length === 1) throw new Error(`${at}: a table keeps at least one column; drop the table instead`);
      t.columns = t.columns.filter((c) => c.name !== step.column);
      return;
    }
    case "create_index": {
      if (shape.indexes[step.name]) throw new Error(`${at}: index "${step.name}" already exists`);
      const t = table(step.table);
      for (const name of step.columns) {
        if ((IMPLICIT_COLUMNS as readonly string[]).includes(name)) continue;
        const c = t.columns.find((x) => x.name === name);
        if (!c) throw new Error(`${at}: column "${name}" does not exist`);
        if (c.sensitive) throw new Error(`${at}: column "${name}" is sensitive and cannot be indexed`);
        if (c.type === "json") throw new Error(`${at}: column "${name}" is json and cannot be indexed`);
      }
      shape.indexes[step.name] = { table: step.table, columns: [...step.columns], unique: step.unique };
      return;
    }
    case "drop_index":
      if (!shape.indexes[step.name]) throw new Error(`${at}: index "${step.name}" does not exist`);
      delete shape.indexes[step.name];
      return;
    case "drop_table":
      table(step.table);
      delete shape.tables[step.table];
      for (const [name, ix] of Object.entries(shape.indexes)) if (ix.table === step.table) delete shape.indexes[name];
      return;
  }
}
