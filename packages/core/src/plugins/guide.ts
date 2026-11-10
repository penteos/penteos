import { FIELD_TYPES, PLUGIN_EVENTS, REPORT_SECTION_IDS } from "@penteos/schema";

/**
 * What the Maestro reads before building a plugin: the declarative
 * language in one page, with a complete example that validates. English, for the model. Kept next
 * to the code that enforces it; the test suite validates the example.
 */

export const GUIDE_EXAMPLE = {
  id: "maestro.crtsh",
  name: "crt.sh subdomains",
  version: "0.1.0",
  apiVersion: 1,
  level: "declarative",
  author: { type: "maestro", name: "Maestro" },
  description: { en: "Finds subdomains of a domain in certificate transparency logs (crt.sh). Passive.", es: "Busca subdominios de un dominio en los registros de transparencia de certificados (crt.sh). Pasivo." },
  permissions: ["net:crt.sh", "graph:read", "graph:write", "ui:menu"],
  contributes: {
    entityTypes: [
      {
        name: "ct_name",
        label: { en: "CT name", es: "Nombre en CT" },
        fields: [
          { name: "name", type: "string", required: true },
          { name: "domain", type: "string", required: true },
          { name: "issuer", type: "string" },
        ],
        key: ["name"],
        title: "name",
      },
    ],
    storage: { project: [{ version: 1, steps: [{ op: "create_table", table: "lookups", columns: [{ name: "domain", type: "text", required: true }, { name: "found", type: "integer", required: true }] }] }] },
    operations: [
      {
        name: "subdomains",
        title: { en: "Subdomains from crt.sh", es: "Subdominios en crt.sh" },
        description: "Lists names under a domain seen in certificate transparency logs (passive: the target is not contacted) and records each one.",
        input: [{ name: "domain", type: "string", required: true, label: { en: "Domain", es: "Dominio" }, placeholder: "example.com" }],
        steps: [
          { do: "http", id: "r", url: "https://crt.sh/", query: { q: "%.{{input.domain}}", output: "json" }, timeoutMs: 30000, maxBytes: 5000000 },
          { do: "set", vars: { names: "{{steps.r.body | pluck:'name_value' | join:'\\n' | lower | split:'\\n' | unique | take:200}}" } },
          {
            do: "each",
            id: "saved",
            over: "{{vars.names}}",
            as: "n",
            steps: [{ do: "put", type: "ct_name", attributes: { name: "{{n | lower}}", domain: "{{input.domain}}" } }],
            collect: { name: "{{n | lower}}" },
          },
          { do: "store_insert", table: "lookups", row: { domain: "{{input.domain}}", found: "{{steps.saved | length}}" } },
        ],
        result: { domain: "{{input.domain}}", names: "{{steps.saved}}", count: "{{steps.saved | length}}" },
        view: { type: "table", items: "names", columns: [{ field: "name", label: { en: "Name", es: "Nombre" } }] },
      },
    ],
    menus: [{ id: "subs", title: { en: "Subdomains (crt.sh)", es: "Subdominios (crt.sh)" }, operation: "subdomains", where: "entity", kinds: ["domain"], prefill: { domain: "{{entity.attributes.fqdn}}" } }],
  },
};

export function pluginGuide(): string {
  return `# Building a Penteos plugin (declarative)

A plugin is ONE JSON manifest: data, no code. Penteos runs it with its own code, under the
permissions it declares. You write it as a draft (plugin_draft_write), test it in a sandbox with
recorded responses (plugin_draft_test: nothing leaves the machine), and propose it
(plugin_draft_propose): the operator approves seeing its permissions and where it sends data.
Approved, it is installed and enabled in THIS project only. You never install anything yourself.

## Manifest
- id: "maestro.<name>" (lowercase, a-z 0-9 -). name, version ("0.1.0"; raise it for each new
  proposal of an installed plugin), apiVersion: 1, level: "declarative", author is set for you.
- description: a string or { "en": "...", "es": "..." } (texts shown to people accept both forms).
- permissions (ask for the minimum):
  graph:read, graph:write, findings:draft, notify, files:write, ui:menu, ai:provider,
  net:<host> or net:*.<domain> (each host it talks to), secrets:<name> (a project secret).
- contributes: operations, menus, settings, events, entityTypes, annotations, storage, providers.

## Fields (inputs, settings, entity types, annotations)
{ "name", "type": ${FIELD_TYPES.join("|")}, "label", "help", "placeholder",
  "required", "default", "values" (enum), "min", "max", "secret" (settings only: API keys) }

## Operations
{ "name": "lookup_ip", "title", "description" (say what it does and when to use it),
  "actors": ["human","agent"] (default both; agent = it becomes YOUR tool), "input": [fields],
  "steps": [...], "result": <template>, "view": table|card|message|json|markdown|document, "timeoutMs",
  "action": the run button's text ("Generate report", not "Run"), "icon" }
Steps run in order; each may have "id" (read later as steps.<id>) and "if" (runs when truthy):
- {"do":"http","method":"GET|POST|PUT|PATCH|DELETE","url":"https://host/path/{{...}}",
   "headers":{}, "query":{}, "body":<json> | "form":{}, "expect":[200,404], "timeoutMs", "maxBytes"}
   → {status, ok, headers, body} (body parsed when JSON). https only; host written literally
   (or "https://{{settings.site}}.example.com" under net:*.example.com). A status outside
   "expect" (default 2xx) is an error.
- {"do":"graph_query","kind":"host|domain|webapp|service|finding|…|<own type>","text","limit"}
   → [{id, kind, naturalKey, attributes, mine}] (mine = this plugin's annotation on it)
- {"do":"graph_get","entity":"<id>"} → one entity or null
- {"do":"put","type":"<own type>","attributes":{…},"relate":"<entity id>"} → {id, created}
   (same key = update; official entities are never created by plugins)
- {"do":"annotate","entity":"<id>","data":{…}} (fields declared in annotations; null removes)
- {"do":"relate","from":"<id>","to":"<id>"}
- {"do":"store_insert","table","row"|"rows"} {"do":"store_query","table","where","orderBy","limit"}
  {"do":"store_update","table","where","set"} {"do":"store_delete","table","where"}
  ("scope":"global" for the plugin's global database; where: {col: value | {"op":"eq|ne|lt|lte|gt|gte|like|in|null","value"}})
- {"do":"finding_draft","title","severity","description","impact","remediation","affects":[ids]}
- {"do":"notify","title","body","level":"info|warn"}
- {"do":"file","name":"reports/{{input.client}}.csv","content":<template>,"encoding":"text|base64|json"}
   → {name, size, type}. A file for the operator in the project's folder (needs files:write): it
   shows up with Download / Open after the run and travels with the project's export.
- {"do":"report","format":"docx|markdown","name":"informes/{{input.client}}.docx","title","author",
   "company","color":"#0f766e","logo":"assets/logo.png" (a PNG/JPEG in the plugin's folder, or a
   data: URL),"confidentiality","includeDrafts","minSeverity":"high","sections":[ids] | "skip":[ids],
   "extra":[{"title","markdown","after":"<id>"}]} → {name, size, type, markdown?}
   The OFFICIAL deliverable (Word, professional layout, the project's real findings and evidence)
   with this plugin's choices, saved among its files (needs graph:read and files:write). Use it
   for any "make me a report" request instead of building a document by hand. Section ids:
   ${REPORT_SECTION_IDS.join(", ")}.
- {"do":"set","vars":{"x": <template>}} → read as vars.x
- {"do":"each","over":"{{list}}","as":"item","max":100,"steps":[…],"collect":<template>} → list
- {"do":"fail","message":"…"} with "if": stops with a clear error for the caller.

## Templates
"{{path | filter:arg | filter}}". A string that is exactly one {{…}} keeps its type.
Paths: input.x, steps.<id>.body.a[0].b, vars.x, settings.x, engagement.{id,name,clientName,mode,language},
the loop variable and index; entity.* in menu prefill; event.entity.* (and event.detail.* for oob.interaction, verification.done, host.unreachable, scope.redirect_outside) in events; result.* in a message view.
Filters: default:x lower upper trim string number int bool json parse_json length first last take:n
slice:a:b join:sep split:sep pluck:'a.b' where:'a.b':value keys values unique compact sort concat:x
replace:a:b contains:x starts_with:x eq:x ne:x gt:x gte:x lt:x lte:x not and:x or:x exists empty
if:a:b urlencode base64 round:n private_ip. Arguments: 'quoted text', numbers, true/false or paths.
Secrets ({{secret:<name>}} or a secret setting) may ONLY be used inside an http step (headers,
query, body, url path - never the host). Basic auth:
"Basic {{settings.user | concat:':' | concat:settings.token | base64}}".

## Entity types, annotations, storage
- entityTypes: [{ "name", "label", "fields", "key": [required fields], "title", "target": host|url field }]
  → kind "<id>:<name>". Use them for what the plugin brings that is not an official entity.
- annotations: [{ "on": ["host","finding",…], "fields": [...] }] (never required fields).
- storage: { "project": [migrations], "global": [migrations] }; a migration is
  { "version": 1, "steps": [{ "op": "create_table", "table", "columns": [{ "name", "type": text|integer|real|boolean|date|json, "required", "sensitive", "default" }] }] }
  (also add_column, rename_column, drop_column, create_index, drop_index, drop_table). Never edit
  an applied migration: add a new version.

## Menus, settings, events, providers
- menus: [{ "id", "title", "operation", "where": "plugins"|"entity", "kinds": [...], "prefill": {"field": "{{entity.attributes.ip}}"}, "direct" }]
- settings: [fields]; secrets are encrypted and only reach http steps.
- events: [{ "on": ${PLUGIN_EVENTS.join("|")}, "operation", "when": "{{…}}", "input": {…} }]
- providers: [{ "id", "label", "baseUrl": "https://…/v1", "models": [...], "apiKey": "<secret setting>" }]
- reportSections: [{ "id", "title", "operation", "after": "<section id>", "modes": ["web"] }]: a section of
  the plugin's own in the OFFICIAL deliverable; the operation runs with no input and returns its
  markdown (a string or { markdown }). Empty → no section.
- exports: [{ "id", "title", "operation", "icon" }]: another format for the deliverable (a button in the
  Deliverable panel); the operation runs with no input and makes files (file or report steps).
- skills: [{ "id", "title", "text": "<markdown, up to 8000 chars>", "modes": ["web"] }]: knowledge for
  you (the Maestro) in projects where the plugin is enabled: a method, a checklist, a house style.
- proxy (code plugins, proxy permission): [{ "id", "on": "request|response", "handler", "modify": false,
  "hosts": ["*.acme.example"], "methods", "path": "<regex>", "contentTypes": ["text/html"], "timeoutMs" }]
  The handler gets { method, url, headers: [[k,v]], body, bodyEncoding } (a response: { request,
  status, headers, body }). A viewing hook (modify false) runs aside - a passive scanner that drafts
  findings. A modifying one returns the changes ({ headers, body, url } / { status, headers, body }).

## Code plugins (level: "code")
When steps are not enough (parsing a format, real logic, a document of its own, a panel), write
code. Manifest: "level": "code", "main": "main.mjs" (Node) or "main.py" with "runtime": "python";
each operation names its "handler" instead of "steps". Send the files with plugin_draft_write
(files: { "main.mjs": "…" }; later, only the files that change). Only Node's or Python's own
modules: there is no npm/pip install. Everything else goes through the penteos object:
Node:
  export async function activate(plugin) {
    plugin.operation("handler_name", async (input, penteos) => { …; return result; });
  }
Python:
  def activate(plugin):
      @plugin.operation("handler_name")
      def run(input, penteos): …; return result
penteos (Python uses snake_case: finding_draft, include_drafts…):
  http({url, method, headers, query, body}) → {status, ok, headers, body}   (net: permissions apply;
     secrets as "{{settings.key}}", filled in by the core)
  graph.query(kind, {text, limit}) · graph.get(id) · graph.put(type, attrs) · graph.annotate(id, data)
  store.insert/query/update/delete(table, …) · findingDraft({title, severity, …}) · notify(title, body)
  files.write(name, text | bytes | json) → {name, size, type}       (files:write)
  report({title, author, company, color, logo, sections, skip, extra, …}) → the official .docx
  settings() · log(…) · input · engagement {id, name, clientName, mode}
It is tested ISOLATED: no network or files of its own (penteos.http and files.write work; Python runs
contained by the system). Once approved, the operator decides whether it runs isolated or free.
Return values small and useful for the view (a summary, a table), not whole documents: files go
with files.write or report.

## How to build one (the method; the system enforces it)
0. research_search which service fits (free? a key? limits?) and research_fetch its docs.
1. plugin_probe the real service with the operator's own example BEFORE writing anything: its real
   status, body, redirects (another host needs its own net: permission), whether it needs a key,
   its rate limits. Never write an API's shape from memory.
2. Something only the operator has (a key, an account): declare it as a setting (secret: true) and
   ask with plugin_draft_request_setting. A choice only they can make: ask (task with question).
3. Test LIVE (plugin_draft_test live: true): real requests to the hosts the plugin declares, with
   the operator's settings, the operator's example as input, and expect = the acceptance criteria
   ({"fields": ["registrar","expires"], "contains": [...], "absent": ["error"]}). The test passes
   only if they hold. A plugin that talks to the internet cannot be proposed without a passing live
   test of its exact version.
4. Edge cases: another live test, or recorded answers taken from your probes
   ({"fromProbe": "<probeId>"}); a failure path with "expect": {"fails": true} must end with a TRUE,
   clear message. Recorded answers you write yourself prove nothing about the real service.
5. Read the result as the operator will (the view), answer the review list the test returns, fix,
   test again. Then plugin_draft_propose with evidence (what you tested, what came back, limits).
Recorded tests: "responses" ([{ "method", "url" (prefix or with *), "status", "body" }] or
{ "fromProbe" }) and "fixtures" (hosts, domains, webapps, findings in the lab project; reference
them in the input as "{{fixtures.hosts[0].id}}").

## Example (validates as is)
${JSON.stringify(GUIDE_EXAMPLE, null, 1)}
`;
}
