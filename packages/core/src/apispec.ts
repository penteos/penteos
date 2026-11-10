/**
 * Reads an API's own contract (OpenAPI 3 or Swagger 2, as JSON): every route, its methods, its
 * parameters and whether the contract says it needs authentication. When an API publishes this,
 * the whole surface is known; the work is to test every route, not a handful.
 */

export interface SpecEndpoint {
  method: string;
  /** Path template as the contract writes it, e.g. "/api/tenants/{id}". */
  path: string;
  params: Array<{ name: string; location: "path" | "query" | "header" | "cookie" | "body" }>;
  /** What the contract declares: true if it needs credentials, false if explicitly public. */
  requiresAuth?: boolean;
  summary?: string;
}

export interface ParsedSpec {
  title?: string;
  version?: string;
  /** Base path or server URL path the routes hang from ("/api", "/v1"…), if any. */
  basePath: string;
  endpoints: SpecEndpoint[];
}

const METHODS = ["get", "post", "put", "patch", "delete", "head", "options"];

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {});

/** Parses an OpenAPI/Swagger document (already JSON-decoded or as text). Throws if it is neither. */
export function parseApiSpec(doc: unknown): ParsedSpec {
  const d = obj(typeof doc === "string" ? JSON.parse(doc) : doc);
  if (!d.openapi && !d.swagger) throw new Error("not an OpenAPI or Swagger document (no 'openapi' or 'swagger' field)");
  const info = obj(d.info);
  // Swagger 2: basePath. OpenAPI 3: the path of the first server URL.
  let basePath = typeof d.basePath === "string" ? d.basePath : "";
  const servers = Array.isArray(d.servers) ? d.servers : [];
  if (!basePath && servers.length) {
    const url = String(obj(servers[0]).url ?? "");
    try {
      basePath = new URL(url, "http://x").pathname;
    } catch {
      basePath = "";
    }
  }
  basePath = basePath.replace(/\/+$/, "");
  const globalSecurity = Array.isArray(d.security) ? d.security : undefined;
  const endpoints: SpecEndpoint[] = [];
  for (const [path, item] of Object.entries(obj(d.paths))) {
    const pathItem = obj(item);
    const shared = Array.isArray(pathItem.parameters) ? pathItem.parameters : [];
    for (const method of METHODS) {
      const op = pathItem[method];
      if (!op) continue;
      const o = obj(op);
      const params = [...shared, ...(Array.isArray(o.parameters) ? o.parameters : [])].map((p) => {
        const x = obj(p);
        const loc = String(x.in ?? "query");
        return { name: String(x.name ?? ""), location: (["path", "query", "header", "cookie"].includes(loc) ? loc : "body") as SpecEndpoint["params"][number]["location"] };
      });
      if (o.requestBody) params.push({ name: "body", location: "body" });
      // Security: the operation's own list wins; an empty list means explicitly public.
      const security = Array.isArray(o.security) ? o.security : globalSecurity;
      const requiresAuth = security === undefined ? undefined : security.length > 0 && security.some((s) => Object.keys(obj(s)).length > 0);
      endpoints.push({
        method: method.toUpperCase(),
        path: `${basePath}${path.startsWith("/") ? path : `/${path}`}`,
        params: params.filter((p) => p.name),
        ...(requiresAuth !== undefined ? { requiresAuth } : {}),
        ...(typeof o.summary === "string" ? { summary: o.summary } : {}),
      });
    }
  }
  return {
    ...(typeof info.title === "string" ? { title: info.title } : {}),
    ...(typeof info.version === "string" ? { version: info.version } : {}),
    basePath,
    endpoints,
  };
}

/** A concrete path to request from a template: {id} and :id become a harmless sample value. */
export function samplePath(template: string): string {
  return template.replace(/\{[^}/]+\}/g, "1").replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, "1");
}
