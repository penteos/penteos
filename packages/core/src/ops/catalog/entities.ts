import { defineOperation, OperationError } from "../registry.js";
import { AnyEntityKind, ENTITY_KINDS } from "@penteos/schema";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { join } from "node:path";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// entities
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "entity.query",
  title: "Query entities",
  description: `Searches entities by kind and free text. Kinds: ${ENTITY_KINDS.join(", ")}, or a plugin's own (author.name:type).`,
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    kind: AnyEntityKind.optional(),
    text: z.string().optional(),
    limit: z.number().int().min(1).max(100_000).default(200),
    offset: z.number().int().min(0).default(0),
  }),
  handler: (input, ctx) => {
    const { engagementId: id, ...query } = input;
    return ctx.engagement(id).query(query);
  },
});

defineOperation({
  name: "entity.get",
  title: "Get entity",
  description: "Returns one entity with its relations and, optionally, its sightings (who said what and when).",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, id: z.string(), sightings: z.boolean().default(false) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const entity = e.get(input.id);
    if (!entity) throw new OperationError("NOT_FOUND", `entity not found: ${input.id}`);
    const edges = e.edgesOf(input.id).map((edge) => {
      const otherId = edge.from.id === input.id ? edge.to.id : edge.from.id;
      const other = e.get(otherId);
      return { ...edge, direction: edge.from.id === input.id ? "out" : "in", other: other ? { id: other.id, kind: other.kind, naturalKey: other.naturalKey } : null };
    });
    return { ...entity, edges, ...(input.sightings ? { sightings: e.sightingsOf(input.id) } : {}) };
  },
});

defineOperation({
  name: "entity.edit",
  title: "Edit entity",
  description: "Sets fields on an entity. Edited fields become authoritative over automatic sources.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, id: z.string(), fields: z.record(z.string(), z.unknown()) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    // A finding's workflow has its own operations, with their rules (only a human approves).
    if (ctx.caller.actor.type === "agent" && e.get(input.id)?.kind === "finding") {
      throw new OperationError("PERMISSION_DENIED", "edit findings with finding_update (text, severity, evidence), finding_set_instances (affected entities), finding_set_cvss and finding_set_status; entity_edit is not for findings");
    }
    return e.editEntity(input.id, input.fields, ctx.caller.actor);
  },
});
