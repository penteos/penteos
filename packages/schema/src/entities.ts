import { z } from "zod";
import { Actor, IsoDate, Markdown, RiskLevel, Severity, Sha256Ref, Ulid } from "./common.js";

/**
 * Entity kinds of the v0 graph. Every entity is stored as the
 * common envelope plus kind-specific `attributes`, validated by the schemas below. Plugins
 * register extra kinds with a prefix (`aws:bucket`), see §17.
 */

export const ENTITY_KINDS = [
  "client",
  "engagement",
  "scope_rule",
  "host",
  "domain",
  "service",
  "webapp",
  "endpoint",
  "technology",
  "principal",
  "credential",
  "observation",
  "finding",
  "evidence",
  "task",
  "note",
  "memory",
] as const;
export const EntityKind = z.enum(ENTITY_KINDS);
export type EntityKind = z.infer<typeof EntityKind>;

export const EntityRef = z.object({ kind: EntityKind, id: Ulid });
export type EntityRef = z.infer<typeof EntityRef>;

export const EntityBase = z.object({
  id: Ulid,
  kind: EntityKind,
  engagementId: Ulid.nullable(),
  naturalKey: z.string().min(1),
  createdAt: IsoDate,
  createdBy: Actor,
  updatedAt: IsoDate,
  revision: z.number().int().nonnegative(),
  deletedAt: IsoDate.optional(),
  tags: z.array(z.string()),
  outOfScope: z.boolean().optional(),
});
export type EntityBase = z.infer<typeof EntityBase>;

// ---------------------------------------------------------------------------------------------
// Organizational
// ---------------------------------------------------------------------------------------------

export const ClientAttributes = z.object({
  name: z.string().min(1),
  aliases: z.array(z.string()).default([]),
  notes: z.string().optional(),
});

export const NetworkContext = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  name: z.string().min(1),
  description: z.string().optional(),
});

export const DataPolicy = z.enum(["any_provider", "approved_providers", "local_only", "no_ai"]);

/** What is being tested. The target type shapes the workspace (sections, plan, default risk). */
export const EngagementMode = z.enum(["web", "infra", "custom"]);

/**
 * When/how in time, inside a project that persists (a folder). `pentest`: the first round. `retest`:
 * a round that re-verifies the findings of a previous round. `continuous`: scheduled recurring rounds
 * that compare against the last photo. Drives the plan nuance, the report kind and the prompt.
 */
export const RoundMode = z.enum(["pentest", "retest", "continuous"]);
export type RoundMode = z.infer<typeof RoundMode>;

/**
 * How autonomous the AI is, changeable at any time. `copilot`: the Maestro suggests, every target
 * action needs the operator's approval. `maestro`: one agent runs it, interrupting on decisions and
 * phase changes. `maestro_auto` (autopilot): it runs the round within scope and the risk ceiling
 * without interrupting, and gathers every decision into a tray shown when it runs out of independent
 * work. Auto never widens scope, raises the ceiling, advances phases or auto-approves.
 */
export const Autonomy = z.enum(["copilot", "maestro", "maestro_auto"]);
export type Autonomy = z.infer<typeof Autonomy>;

/** Copiloto: suggests, the operator approves each action. */
export const isCopilot = (a: Autonomy): boolean => a === "copilot";
/** The Maestro runs autonomously (maestro or maestro auto), as opposed to copilot. */
export const runsAgent = (a: Autonomy): boolean => a !== "copilot";
/** Autopilot: runs without interrupting and batches decisions. */
export const isAutoPilot = (a: Autonomy): boolean => a === "maestro_auto";

/** The target type, or `custom` for anything unknown. */
export function normalizeMode(mode: string): z.infer<typeof EngagementMode> {
  return EngagementMode.safeParse(mode).success ? (mode as z.infer<typeof EngagementMode>) : "custom";
}

/** The round mode of a project (a one-shot pentest unless set). */
export function roundModeOf(raw: { roundMode?: unknown }): RoundMode {
  return raw.roundMode === "retest" || raw.roundMode === "continuous" ? raw.roundMode : "pentest";
}

/** The autonomy of a project (the Maestro unless set). */
export function autonomyOf(raw: { autonomy?: unknown }): Autonomy {
  return raw.autonomy === "copilot" || raw.autonomy === "maestro_auto" ? raw.autonomy : "maestro";
}

export const EngagementAttributes = z.object({
  clientId: Ulid,
  name: z.string().min(1),
  mode: EngagementMode,
  /** When/how in time; default keeps a one-shot pentest. */
  roundMode: RoundMode.default("pentest"),
  /** Plugins this project uses: installed plugins run only where enabled. */
  plugins: z.array(z.string().max(80)).max(100).default([]),
  status: z.enum(["planning", "active", "paused", "reporting", "closed", "archived"]),
  startsAt: IsoDate.optional(),
  endsAt: IsoDate.optional(),
  networkContexts: z.array(NetworkContext).default([{ id: "default", name: "Default" }]),
  dataPolicy: DataPolicy,
  /** How autonomous the AI is; default keeps today's behaviour untouched. */
  autonomy: Autonomy.default("maestro"),
  /** Language of everything that ends up in the deliverable (findings, report, tasks, verdicts). */
  language: z.enum(["es", "en"]).default("en"),
  maxRisk: RiskLevel,
  previousEngagementId: Ulid.optional(),
  stopWork: z
    .object({ active: z.boolean(), by: Actor, at: IsoDate, reason: z.string() })
    .optional(),
});
export type EngagementAttributes = z.infer<typeof EngagementAttributes>;

export const TimeWindow = z.object({
  /** 0 = Sunday … 6 = Saturday, evaluated in `timeZone`. */
  days: z.array(z.number().int().min(0).max(6)).min(1),
  start: z.string().regex(/^\d{2}:\d{2}$/),
  end: z.string().regex(/^\d{2}:\d{2}$/),
  timeZone: z.string().min(1),
});
export type TimeWindow = z.infer<typeof TimeWindow>;

export const ScopeTarget = z.discriminatedUnion("type", [
  z.object({ type: z.literal("ip"), value: z.string() }),
  z.object({ type: z.literal("cidr"), value: z.string() }),
  z.object({ type: z.literal("range"), from: z.string(), to: z.string() }),
  z.object({ type: z.literal("domain"), value: z.string() }),
  z.object({ type: z.literal("wildcard"), value: z.string().startsWith("*.") }),
  z.object({ type: z.literal("url"), value: z.string() }),
  z.object({ type: z.literal("entity"), entityId: Ulid }),
]);
export type ScopeTarget = z.infer<typeof ScopeTarget>;

export const ScopeRuleAttributes = z.object({
  effect: z.enum(["include", "exclude"]),
  target: ScopeTarget,
  networkContext: z.string().optional(),
  /** "80,443,8000-8100" */
  ports: z.string().regex(/^\d+(-\d+)?(,\d+(-\d+)?)*$/).optional(),
  maxRisk: RiskLevel.optional(),
  windows: z.array(TimeWindow).optional(),
  reason: z.string().optional(),
});
export type ScopeRuleAttributes = z.infer<typeof ScopeRuleAttributes>;

// ---------------------------------------------------------------------------------------------
// Target side
// ---------------------------------------------------------------------------------------------

export const HostAttributes = z.object({
  networkContext: z.string(),
  ip: z.string(),
  status: z.enum(["up", "down", "unknown"]).default("unknown"),
  os: z.object({ name: z.string(), version: z.string().optional(), confidence: z.number() }).optional(),
  hostnames: z.array(z.string()).default([]),
  mac: z.string().optional(),
});

export const DnsRecord = z.object({
  type: z.enum(["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "CAA", "PTR"]),
  value: z.string(),
  observedAt: IsoDate,
});

export const DomainAttributes = z.object({
  fqdn: z.string(),
  apex: z.string(),
  records: z.array(DnsRecord).optional(),
  wildcard: z.boolean().optional(),
});

export const ServiceAttributes = z.object({
  hostId: Ulid,
  transport: z.enum(["tcp", "udp"]),
  port: z.number().int().min(0).max(65535),
  state: z.enum(["open", "closed", "filtered", "open|filtered"]),
  protocol: z.string().optional(),
  product: z.string().optional(),
  version: z.string().optional(),
  /** nmap's CPE for the service (cpe:/a:vendor:product:version), the key for vulnerability matching. */
  cpe: z.string().optional(),
  tls: z.boolean().optional(),
  banner: z.string().optional(),
});

export const WebAppAttributes = z.object({
  origin: z.string(),
  title: z.string().optional(),
  technologies: z
    .array(z.object({ name: z.string(), version: z.string().optional(), confidence: z.number() }))
    .default([]),
  waf: z.string().optional(),
  /** OWASP WSTG categories: what was tested on this application and how it went. */
  coverage: z
    .record(z.string(), z.object({ status: z.enum(["untested", "in_progress", "tested", "partial", "vulnerable", "n/a"]), note: z.string().optional(), by: z.string().optional(), at: z.string().optional() }))
    .optional(),
  auth: z
    .object({ type: z.enum(["none", "form", "basic", "oauth", "saml", "other"]), notes: z.string().optional() })
    .optional(),
});

export const HttpMethod = z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"]);

export const EndpointAttributes = z.object({
  webappId: Ulid,
  pathTemplate: z.string().startsWith("/"),
  operation: z.string().optional(),
  methods: z.array(HttpMethod).default([]),
  params: z
    .array(
      z.object({
        name: z.string(),
        location: z.enum(["path", "query", "body", "header", "cookie"]),
        type: z.enum(["string", "int", "uuid", "json", "file", "unknown"]).optional(),
        examples: z.array(z.string()).optional(),
      }),
    )
    .default([]),
  statusesSeen: z.array(z.number().int()).default([]),
  requiresAuth: z.boolean().optional(),
  coverage: z.record(z.string(), z.enum(["untested", "tested", "vulnerable", "n/a"])).optional(),
});

/**
 * A product with a version found running on a target: the unit that known
 * vulnerabilities are matched against. Detected from headers, the API contract, JS bundles, nmap
 * banners… `where` is the origin or host it was seen on; `confidence` tells a banner guess from the
 * app's own contract. `cpe` maps it to the CVE databases; `ecosystem` routes library lookups (OSV).
 */
export const TechnologyAttributes = z.object({
  /** The origin ("https://x") or host key it runs on; the first part of the natural key. */
  where: z.string().min(1),
  product: z.string().min(1),
  vendor: z.string().optional(),
  version: z.string().optional(),
  /** Common Platform Enumeration, e.g. "cpe:2.3:a:wordpress:wordpress:6.1:*:*:*:*:*:*:*". */
  cpe: z.string().optional(),
  /** a = application, o = operating system, h = hardware. */
  part: z.enum(["a", "o", "h"]).optional(),
  /** For library lookups: npm, PyPI, composer, Go, WordPress… (OSV ecosystem). */
  ecosystem: z.string().optional(),
  /** The host's distribution when known ("ubuntu", "debian", "ubuntu:22.04"): enables backport awareness. */
  distro: z.string().optional(),
  /** How it was detected (header, api_contract, js_bundle, nmap, favicon, generator…). */
  source: z.string().optional(),
  confidence: z.number().min(0).max(1).default(0.5),
  /** The entities it was found on (webapp, service, host). */
  affects: z.array(EntityRef).default([]),
});

export const PrincipalAttributes = z.object({
  principalType: z.enum(["user", "group", "computer", "service_account", "role"]),
  realm: z.string().min(1),
  name: z.string().min(1),
  displayName: z.string().optional(),
  email: z.string().optional(),
  enabled: z.boolean().optional(),
  privileged: z.boolean().optional(),
  sid: z.string().optional(),
});

export const CredentialType = z.enum([
  "password",
  "ntlm_hash",
  "netntlm",
  "kerberos_ticket",
  "hash_other",
  "token",
  "api_key",
  "ssh_key",
  "cookie",
  "certificate",
]);
export type CredentialType = z.infer<typeof CredentialType>;

/** The secret itself never lives here: only a vault reference. Vault design is pending. */
export const CredentialAttributes = z.object({
  credentialType: CredentialType,
  vaultRef: z.string(),
  fingerprint: z.string(),
  hint: z.string().optional(),
  status: z.enum(["untested", "valid", "invalid", "expired", "cracked"]),
  source: z.string().optional(),
});

// ---------------------------------------------------------------------------------------------
// Findings and evidence
// ---------------------------------------------------------------------------------------------

export const ObservationAttributes = z.object({
  title: z.string().min(1),
  detail: z.string().optional(),
  severityHint: Severity.optional(),
  sourceRule: z.string().min(1),
  affects: z.array(EntityRef).min(1),
  location: z.string().optional(),
  triage: z.enum(["new", "confirmed", "false_positive", "duplicate", "accepted_risk"]).default("new"),
  /** Why it was triaged this way (e.g. "static asset, public by design"). */
  triageReason: z.string().optional(),
  findingId: Ulid.optional(),
  /** The raw output that shows it (e.g. the body an endpoint returned without credentials). */
  rawId: Sha256Ref.optional(),
});

export const FindingInstance = z.object({
  id: Ulid,
  entity: EntityRef,
  location: z.string().optional(),
  status: z.enum(["open", "fixed", "not_verified"]),
  observationIds: z.array(Ulid).default([]),
});

export const FindingStatus = z.enum([
  "draft",
  "in_review",
  "approved",
  "reported",
  "fixed",
  "partially_fixed",
  "not_fixed",
  "not_verifiable",
  "reopened",
  "wont_fix",
]);

/** Independent reproduction of a finding by someone who did not find it. */
export const FindingVerification = z.object({
  state: z.enum(["pending", "running", "done", "failed"]),
  verdict: z.enum(["reproduced", "not_reproduced", "inconclusive"]).optional(),
  summary: z.string().optional(),
  /** Who verified (the verifier agent, or a human who reproduced it by hand). */
  by: Actor.optional(),
  requestedBy: Actor,
  requestedAt: IsoDate,
  at: IsoDate.optional(),
  evidenceIds: z.array(Ulid).default([]),
});

/**
 * Deepening a finding: detecting a gap is not the end. Three questions turn "it answers without
 * credentials" into its real impact - how far it reaches, what the exposed data lets an attacker
 * do, and what it chains with. Penteos opens them on serious findings and computes leads.
 */
export const ImpactQuestionKey = z.enum(["reach", "exposed", "chain"]);
export type ImpactQuestionKey = z.infer<typeof ImpactQuestionKey>;

export const ImpactQuestion = z.object({
  key: ImpactQuestionKey,
  status: z.enum(["open", "answered", "not_applicable"]),
  /** What was found (answered) or why it does not apply. */
  answer: z.string().max(3000).optional(),
  evidenceIds: z.array(Ulid).default([]),
  by: Actor.optional(),
  at: IsoDate.optional(),
});

export const FindingDeepening = z.object({
  /** Why Penteos opened it (severity, exposure). */
  reason: z.string(),
  openedAt: IsoDate,
  questions: z.array(ImpactQuestion),
});

export const FindingAttributes = z.object({
  title: z.string().min(1),
  templateRef: z.string().optional(),
  description: Markdown.default(""),
  impact: Markdown.default(""),
  remediation: Markdown.default(""),
  /** How to reproduce it, step by step (the technical report shows it per finding). */
  reproduction: Markdown.default(""),
  severity: Severity,
  cvss: z
    .object({ version: z.enum(["4.0", "3.1"]), vector: z.string(), score: z.number().min(0).max(10) })
    .optional(),
  cwe: z.array(z.string().regex(/^CWE-\d+$/)).default([]),
  attack: z.array(z.string().regex(/^T\d{4}(\.\d{3})?$/)).default([]),
  references: z.array(z.string()).default([]),
  status: FindingStatus.default("draft"),
  instances: z.array(FindingInstance).default([]),
  evidenceIds: z.array(Ulid).default([]),
  owner: Actor.optional(),
  reviewer: Actor.optional(),
  fingerprint: z.string().optional(),
  verification: FindingVerification.optional(),
  deepening: FindingDeepening.optional(),
});

export const EvidenceAttributes = z.object({
  caption: z.string().min(1),
  source: z.discriminatedUnion("type", [
    z.object({
      type: z.literal("raw_excerpt"),
      rawId: Sha256Ref,
      range: z.object({ start: z.number().int().nonnegative(), end: z.number().int().nonnegative() }).optional(),
    }),
    z.object({
      type: z.literal("http_exchange"),
      rawId: Sha256Ref,
      highlight: z
        .array(z.object({ part: z.enum(["request", "response"]), start: z.number().int(), end: z.number().int() }))
        .optional(),
    }),
    z.object({ type: z.literal("file"), rawId: Sha256Ref }),
  ]),
  redactions: z.array(z.object({ start: z.number().int(), end: z.number().int(), label: z.string().optional() })).optional(),
  capturedAt: IsoDate,
});

// ---------------------------------------------------------------------------------------------
// Work
// ---------------------------------------------------------------------------------------------

export const TaskAttributes = z.object({
  title: z.string().min(1),
  description: Markdown.optional(),
  status: z.enum(["todo", "in_progress", "blocked", "awaiting_approval", "done", "cancelled"]).default("todo"),
  assignee: Actor.nullable().optional(),
  priority: z.enum(["low", "normal", "high", "urgent"]).default("normal"),
  parentTaskId: Ulid.optional(),
  related: z.array(EntityRef).default([]),
  requiredRisk: RiskLevel.optional(),
  dueAt: IsoDate.optional(),
  /**
   * A decision an agent needs from the operator. The operator answers on the card; the answer
   * closes the task and reaches the agent as news, so it never has to be asked twice.
   */
  question: z.string().max(2000).optional(),
  /** Quick-reply options for the question (buttons); free text is always available too. */
  options: z.array(z.string().min(1).max(120)).max(4).optional(),
  answer: z.object({ text: z.string(), by: Actor, at: IsoDate }).optional(),
  /**
   * The agent needs the operator to browse something in the project browser (a JavaScript
   * challenge, a login flow, an MFA step): where to start and what to do. The traffic is recorded
   * by the proxy; when the operator says it is done, the agent hears how much was captured.
   */
  browse: z
    .object({
      url: z.string().url(),
      steps: z.array(z.string().min(1).max(300)).min(1).max(8),
      requestedAt: IsoDate,
      result: z.object({ outcome: z.enum(["done", "declined"]), exchanges: z.number().int(), hosts: z.array(z.string()), note: z.string().optional(), by: Actor, at: IsoDate }).optional(),
    })
    .optional(),
});

export const NoteAttributes = z.object({
  title: z.string().min(1),
  body: Markdown,
  mentions: z.array(EntityRef).default([]),
  visibility: z.enum(["engagement", "private"]).default("engagement"),
});

export const MemoryAttributes = z.object({
  memoryType: z.enum(["fact", "decision", "attempt", "hypothesis", "preference", "lesson"]),
  scope: z.enum(["task", "engagement", "client", "user", "agent", "organization"]),
  content: z.string().min(1),
  entities: z.array(EntityRef).default([]),
  rawRef: Sha256Ref.optional(),
  validity: z.discriminatedUnion("type", [
    z.object({ type: z.literal("permanent") }),
    z.object({ type: z.literal("until_reverified") }),
    z.object({ type: z.literal("expires"), at: IsoDate }),
  ]),
  confidence: z.number().min(0).max(1),
  /** False when derived from target-controlled content (prompt-injection defense). */
  trusted: z.boolean(),
  /** No longer true (corrected by a human or the agent): kept for history, not used as context. */
  invalidated: z.object({ at: IsoDate, reason: z.string() }).optional(),
});

// ---------------------------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------------------------

export const ENTITY_ATTRIBUTES = {
  client: ClientAttributes,
  engagement: EngagementAttributes,
  scope_rule: ScopeRuleAttributes,
  host: HostAttributes,
  domain: DomainAttributes,
  service: ServiceAttributes,
  webapp: WebAppAttributes,
  endpoint: EndpointAttributes,
  technology: TechnologyAttributes,
  principal: PrincipalAttributes,
  credential: CredentialAttributes,
  observation: ObservationAttributes,
  finding: FindingAttributes,
  evidence: EvidenceAttributes,
  task: TaskAttributes,
  note: NoteAttributes,
  memory: MemoryAttributes,
} as const satisfies Record<EntityKind, z.ZodType>;

export type EntityAttributes<K extends EntityKind> = z.infer<(typeof ENTITY_ATTRIBUTES)[K]>;

/**
 * How conflicting values for a scalar field are handled when merging sightings.
 * Fields not listed default to `descriptive`.
 */
export type FieldClass = "volatile" | "descriptive" | "identity";

export const FIELD_CLASSES: Partial<Record<EntityKind, Record<string, FieldClass>>> = {
  host: { status: "volatile", ip: "identity", networkContext: "identity" },
  service: { state: "volatile", transport: "identity", port: "identity" },
  principal: { principalType: "identity", sid: "identity", enabled: "volatile" },
  credential: { credentialType: "identity", status: "volatile" },
};

export function fieldClass(kind: EntityKind, field: string): FieldClass {
  return FIELD_CLASSES[kind]?.[field] ?? "descriptive";
}
