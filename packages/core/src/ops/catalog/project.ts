import { defineOperation } from "../registry.js";
import { z } from "zod";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// Portability: a project as one self-contained .penteos file, to back up, move or share.
// Human-only on purpose - the agent must not export (exfiltrate) or import projects.

defineOperation({
  name: "project.export",
  title: "Export project (.penteos)",
  description: "Writes the whole project - its database and raw evidence - to one portable .penteos file, without the vault's secret values. For backups, moving or sharing.",
  kind: "read",
  actors: ["human"],
  input: z.object({ engagementId, dest: z.string().min(1) }),
  handler: (input, ctx) => ctx.workspace.exportEngagement(ctx.engagement(input.engagementId).info.id, input.dest),
});

defineOperation({
  name: "project.forget",
  title: "Remove from the list",
  description: "Removes a project from the recents/index without deleting its folder on disk. For projects whose folder is gone.",
  kind: "write",
  actors: ["human"],
  input: z.object({ id: z.string().min(1) }),
  handler: (input, ctx) => {
    ctx.workspace.forget(input.id);
    return { forgotten: input.id };
  },
});

defineOperation({
  name: "project.relocate",
  title: "Move project folder",
  description: "Moves this project's whole folder to a new parent folder (e.g. somewhere more visible) and points the index at the new place.",
  kind: "write",
  actors: ["human"],
  input: z.object({ engagementId, dir: z.string().min(1) }),
  handler: (input, ctx) => ({ dir: ctx.workspace.relocate(ctx.engagement(input.engagementId).info.id, input.dir) }),
});

defineOperation({
  name: "project.open",
  title: "Open project folder",
  description: "Opens a project folder the operator points at (reads its project.json) and registers it in the index if it is not there yet.",
  kind: "write",
  actors: ["human"],
  input: z.object({ dir: z.string().min(1) }),
  handler: (input, ctx) => ctx.workspace.openFolder(input.dir, ctx.caller.actor),
});

defineOperation({
  name: "project.import",
  title: "Import project (.penteos)",
  description: "Brings a .penteos file in as a new project. Its vault secrets were not exported, so they are re-entered afterwards.",
  kind: "write",
  actors: ["human"],
  input: z.object({ src: z.string().min(1) }),
  handler: (input, ctx) => ctx.workspace.importEngagement(input.src, ctx.caller.actor),
});

defineOperation({
  name: "project.dir",
  title: "Project folder",
  description: "Where a project's folder is on disk (to show it in the file manager).",
  kind: "read",
  actors: ["human"],
  input: z.object({ id: z.string().min(1) }),
  handler: (input, ctx) => ({ dir: ctx.workspace.dirOf(input.id) }),
});
