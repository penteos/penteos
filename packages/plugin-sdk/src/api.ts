/**
 * What a code plugin's code gets. Everything goes through the core,
 * under the plugin's declared permissions: requests to its net: hosts, the graph, its storage,
 * draft findings, notices. The code never sees a secret, a socket or a database file - a secret
 * is written as "{{settings.apiKey}}" or "{{secret:name}}" and the core fills it in.
 */

export interface HttpRequest {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD";
  /** https, to a host of the plugin's net: permissions. */
  url: string;
  headers?: Record<string, string>;
  query?: Record<string, unknown>;
  body?: unknown;
  form?: Record<string, unknown>;
  /** Statuses that count as success (default: any 2xx). */
  expect?: number[];
  maxBytes?: number;
  timeoutMs?: number;
}

export interface HttpResponse {
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  /** Parsed when it is JSON; text otherwise. */
  body: unknown;
}

export interface OutputFile {
  /** Path inside the plugin's files folder, "reports/acme.docx". */
  name: string;
  size: number;
  modifiedAt: string;
  type: string;
}

export type ReportSection = "executive_summary" | "scope" | "paths" | "retest" | "findings" | "detailed" | "surface" | "coverage" | "conclusion" | "traces" | "annex";

export interface ReportOptions {
  format?: "docx" | "markdown";
  /** File name among the plugin's files ("informes/acme.docx"). */
  name?: string;
  includeDrafts?: boolean;
  title?: string;
  author?: string;
  company?: string;
  /** "#1f6feb" */
  color?: string;
  /** A data: URL, or a PNG/JPEG of the plugin's folder or of its files. */
  logo?: string;
  confidentiality?: string;
  /** Only these official sections. */
  sections?: ReportSection[];
  skip?: ReportSection[];
  minSeverity?: "critical" | "high" | "medium" | "low" | "info";
  /** Sections of the plugin's own, in markdown. */
  extra?: Array<{ title: string; markdown: string; after?: ReportSection }>;
}

export interface EntityView {
  id: string;
  kind: string;
  naturalKey: string;
  attributes: Record<string, unknown>;
  outOfScope: boolean;
  tags: string[];
  ext?: Record<string, Record<string, unknown>>;
  /** This plugin's own annotation on it. */
  mine?: Record<string, unknown>;
}

export type Where = Record<string, string | number | boolean | null | { op: "eq" | "ne" | "lt" | "lte" | "gt" | "gte" | "like" | "in" | "null"; value: unknown }>;
export type StoreScope = { scope?: "project" | "global" };

export interface PenteosApi {
  /** The operation's input, as validated by the manifest. */
  readonly input: Record<string, unknown>;
  readonly engagement: { id: string; name: string; clientName: string; mode: string; language?: string };
  http(request: HttpRequest): Promise<HttpResponse>;
  readonly graph: {
    query(kind: string, options?: { text?: string; limit?: number }): Promise<EntityView[]>;
    get(entityId: string): Promise<EntityView | null>;
    /** An entity of one of the plugin's own types; the same key updates it. */
    put(type: string, attributes: Record<string, unknown>, options?: { relate?: string }): Promise<{ id: string; created: boolean; naturalKey: string }>;
    annotate(entityId: string, data: Record<string, unknown>): Promise<Record<string, unknown>>;
    relate(fromId: string, toId: string): Promise<{ id: string }>;
  };
  readonly store: {
    insert(table: string, row: Record<string, unknown>, options?: StoreScope): Promise<Record<string, unknown>>;
    insertMany(table: string, rows: Array<Record<string, unknown>>, options?: StoreScope): Promise<{ inserted: number }>;
    query(table: string, options?: StoreScope & { where?: Where; orderBy?: { column: string; dir?: "asc" | "desc" }; limit?: number }): Promise<Array<Record<string, unknown>>>;
    update(table: string, where: Where, set: Record<string, unknown>, options?: StoreScope): Promise<{ updated: number }>;
    delete(table: string, where: Where, options?: StoreScope): Promise<{ deleted: number }>;
  };
  /** Always a draft: only a person approves findings. */
  findingDraft(finding: { title: string; severity: "critical" | "high" | "medium" | "low" | "info"; description?: string; impact?: string; remediation?: string; affects?: string[] }): Promise<{ id: string; status: "draft" }>;
  notify(title: string, body?: string, level?: "info" | "warn"): Promise<{ sent: boolean }>;
  /**
   * Files for the operator in the project's folder (needs files:write): they show up after the run
   * to download or open, and travel with the project's export. `dir` is that folder, only for a
   * free plugin, to write there itself with any library.
   */
  readonly files: {
    write(name: string, data: string | Uint8Array | ArrayBuffer | unknown): Promise<OutputFile>;
    readonly dir?: string;
  };
  /**
   * The official deliverable, made by Penteos with this plugin's choices (needs graph:read and
   * files:write), saved among its files: a Word document, or its markdown.
   */
  report(options?: ReportOptions): Promise<OutputFile & { markdown?: string }>;
  /** The plugin's settings without the secret ones. */
  settings(): Promise<Record<string, unknown>>;
  /** A line in the plugin's log (console.log goes there too). */
  log(...parts: unknown[]): void;
}

/** What `activate` receives: register each operation's code under the handler name the manifest gives. */
export interface PluginRegistrar {
  operation(handler: string, fn: (input: Record<string, unknown>, penteos: PenteosApi) => unknown | Promise<unknown>): void;
}

/** A code plugin's main module exports this. */
export type Activate = (plugin: PluginRegistrar) => void | Promise<void>;

/** What a panel's page gets as `window.penteos` (its only way out of the frame). */
export interface PanelBridge {
  readonly context: { plugin: string; panel: string; entityId?: string; kind?: string };
  call(operation: string, input?: Record<string, unknown>): Promise<unknown>;
  /** One of the plugin's files in the open project: save it, open it with its program, show it in its folder. */
  readonly files: { download(name: string): Promise<void>; open(name: string): Promise<void>; reveal(name: string): Promise<void> };
}
