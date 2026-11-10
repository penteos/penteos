import type { Engagement, Entity } from "./engagement.js";

/**
 * Attack paths over identities: from what is owned to what is
 * privileged, following how control propagates in Active Directory:
 *
 *   member of a group      → you hold the group's rights
 *   admin to a computer    → you control the computer
 *   session on a computer  → whoever controls the computer can take that user
 */

export interface PathStep {
  id: string;
  label: string;
  /** How this step was reached from the previous one. */
  via?: "member_of" | "admin_to" | "session";
}

function label(e: Entity): string {
  return String(e.attributes.displayName ?? `${e.attributes.name}@${e.attributes.realm}`);
}

export function attackPaths(engagement: Engagement, options: { from?: string[]; to?: string[]; maxPaths?: number } = {}): PathStep[][] {
  const principals = engagement.query({ kind: "principal", limit: 100_000 });
  const byId = new Map(principals.map((p) => [p.id, p]));
  // Directed control graph: node → [next node, how]
  const next = new Map<string, Array<[string, PathStep["via"]]>>();
  const add = (a: string, b: string, via: PathStep["via"]) => {
    if (!next.has(a)) next.set(a, []);
    next.get(a)!.push([b, via]);
  };
  for (const p of principals) {
    for (const e of engagement.edgesOf(p.id)) {
      if (e.from.id !== p.id) continue;
      if (e.type === "member_of") add(e.from.id, e.to.id, "member_of");
      if (e.type === "admin_to") add(e.from.id, e.to.id, "admin_to");
      // A session of U on C: controlling C gives U.
      if (e.type === "has_session") add(e.to.id, e.from.id, "session");
    }
  }

  const sources = options.from?.length ? options.from : principals.filter((p) => p.tags.includes("owned")).map((p) => p.id);
  const targets = new Set(options.to?.length ? options.to : principals.filter((p) => p.attributes.privileged === true).map((p) => p.id));
  const paths: PathStep[][] = [];

  for (const source of sources) {
    if (!byId.has(source)) continue;
    // Breadth-first: the shortest path to each target.
    const prev = new Map<string, [string, PathStep["via"]] | null>([[source, null]]);
    const queue = [source];
    while (queue.length) {
      const node = queue.shift()!;
      if (targets.has(node) && node !== source) {
        const steps: PathStep[] = [];
        let cur: string | undefined = node;
        while (cur) {
          const link = prev.get(cur);
          steps.unshift({ id: cur, label: label(byId.get(cur)!), ...(link ? { via: link[1] } : {}) });
          cur = link ? link[0] : undefined;
        }
        paths.push(steps);
        if (paths.length >= (options.maxPaths ?? 50)) return paths;
        continue; // a privileged node is a destination, not a stepping stone
      }
      for (const [to, via] of next.get(node) ?? []) {
        if (prev.has(to) || !byId.has(to)) continue;
        prev.set(to, [node, via]);
        queue.push(to);
      }
    }
  }
  return paths.sort((a, b) => a.length - b.length);
}
