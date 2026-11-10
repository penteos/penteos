import { defineOperation, OperationError } from "../registry.js";
import { z } from "zod";
import { attackPaths } from "../../graph.js";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { exchangesToBatch, isBurpXml, isHar, parseBurpXml, parseHar } from "../../importers/web.js";
import { isBloodHound, parseBloodHound } from "@penteos/parser-bloodhound";
import { parseNmapXml } from "@penteos/parser-nmap";
import { engagementId } from "./shared.js";
import { INGEST_FORMAT, IngestBatch } from "@penteos/schema";

/** The largest file a plugin parser is given (it goes to an isolated process with a memory ceiling). */
const PLUGIN_PARSER_BYTES = 15 * 1024 * 1024;

// ---------------------------------------------------------------------------------------------
// import, tags, attack paths
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "ingest.import",
  title: "Import results",
  description: "Imports a results file produced elsewhere: nmap XML, a SharpHound/BloodHound collection (zip or JSON), Burp Suite saved items (XML) or a HAR proxy history (browsers, Caido, ZAP). The file is kept as raw evidence.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, filename: z.string().min(1), contentBase64: z.string().max(80_000_000) }),
  handler: async (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const bytes = Buffer.from(input.contentBase64, "base64");
    const files = [{ name: input.filename, content: new Uint8Array(bytes) }];
    const text = bytes.subarray(0, 4096).toString("utf8");
    if (text.includes("<nmaprun")) {
      const rawId = e.putRaw(bytes, { type: "import", mime: "application/xml", originalName: input.filename });
      return { format: "nmap", summary: e.ingest(parseNmapXml(bytes.toString("utf8"), { rawIds: [rawId] }), ctx.caller.actor) };
    }
    if (isBloodHound(files)) {
      const rawId = e.putRaw(bytes, { type: "import", mime: input.filename.endsWith(".zip") ? "application/zip" : "application/json", originalName: input.filename });
      return { format: "bloodhound", summary: e.ingest(parseBloodHound(files, { rawIds: [rawId] }), ctx.caller.actor) };
    }
    const full = bytes.toString("utf8");
    const web = isBurpXml(text) ? { format: "burp", list: parseBurpXml(full) } : isHar(text) ? { format: "har", list: parseHar(full) } : undefined;
    if (web) {
      const fileRaw = e.putRaw(bytes, { type: "import", mime: web.format === "har" ? "application/json" : "application/xml", originalName: input.filename });
      // Each exchange is kept on its own, so it can become evidence.
      const rawIds = web.list.slice(0, 5000).map((x) => e.putRaw(x.raw, { type: "http_exchange", mime: "message/http", originalName: `${x.method} ${x.url.href}`.slice(0, 200) }));
      const summary = e.ingest(exchangesToBatch(web.list, [fileRaw, ...rawIds], web.format), ctx.caller.actor);
      return { format: web.format, exchanges: web.list.length, summary };
    }
    // Formats taught by plugins enabled in this project (Nessus, …), after the built-in ones.
    const candidates = ctx.pluginRuntime?.parsersFor(e, input.filename, bytes.subarray(0, 8192).toString("utf8")) ?? [];
    for (const { pluginId, version, parser } of candidates) {
      if (bytes.length > PLUGIN_PARSER_BYTES) throw new OperationError("VALIDATION_ERROR", `the file is larger than ${PLUGIN_PARSER_BYTES / 1048576} MB, the most a plugin parser reads`);
      const out = (await ctx.pluginRuntime!.runParser(pluginId, parser, input.filename, full, ctx)) as { items?: unknown; tool?: unknown; toolVersion?: unknown } | null;
      const rawId = e.putRaw(bytes, { type: "import", mime: "application/octet-stream", originalName: input.filename });
      // The same validation as any official parser: an item that does not fit refuses the whole batch.
      const batch = IngestBatch.safeParse({
        format: INGEST_FORMAT,
        source: { parser: `plugin_${pluginId.replace(/[^a-z0-9-]/g, "_")}@${version}`, ...(typeof out?.tool === "string" ? { tool: out.tool } : {}), ...(typeof out?.toolVersion === "string" ? { toolVersion: out.toolVersion } : {}) },
        rawIds: [rawId],
        observedAt: new Date().toISOString(),
        items: Array.isArray(out?.items) ? out!.items : [],
      });
      if (!batch.success) throw new OperationError("VALIDATION_ERROR", `the ${pluginId} parser returned items that do not fit the ingest format: ${batch.error.issues.slice(0, 3).map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
      return { format: `${pluginId}:${parser.id}`, summary: e.ingest(batch.data, ctx.caller.actor) };
    }
    throw new OperationError("VALIDATION_ERROR", "unrecognized file: supported formats are nmap XML, SharpHound/BloodHound collections (zip or JSON), Burp Suite items (XML), HAR (browsers, Caido, ZAP) and those of the plugins enabled in this project");
  },
});

defineOperation({
  name: "entity.tag",
  title: "Tag entity",
  description: 'Adds or removes tags on an entity. Tag compromised identities as "owned" to compute attack paths from them.',
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, id: z.string(), add: z.array(z.string().min(1).max(40)).default([]), remove: z.array(z.string()).default([]) }),
  handler: (input, ctx) => ctx.engagement(input.engagementId).tag(input.id, input.add, input.remove, ctx.caller.actor),
});

defineOperation({
  name: "graph.paths",
  title: "Attack paths",
  description:
    'Shortest attack paths over identities (group membership, local admin rights, sessions): by default from principals tagged "owned" to privileged ones (Domain Admins and similar). Pass principal ids to choose sources or targets.',
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, from: z.array(z.string()).optional(), to: z.array(z.string()).optional(), maxPaths: z.number().int().min(1).max(200).default(20) }),
  handler: (input, ctx) =>
    attackPaths(ctx.engagement(input.engagementId), {
      ...(input.from ? { from: input.from } : {}),
      ...(input.to ? { to: input.to } : {}),
      maxPaths: input.maxPaths,
    }),
});
