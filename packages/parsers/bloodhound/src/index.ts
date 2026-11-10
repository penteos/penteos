import { type IngestBatch, type IngestItem, INGEST_FORMAT } from "@penteos/schema";
import { strFromU8, unzipSync } from "fflate";

/**
 * SharpHound / BloodHound CE collections (users, groups, computers JSON files, usually zipped)
 * into the graph: principals with their SIDs, group memberships, sessions and local admin
 * rights. Enough to compute attack paths (who can reach Domain Admins from what you own).
 */

export const PARSER_ID = "bloodhound@0.1.0";

interface BHObject {
  ObjectIdentifier: string;
  Properties?: Record<string, unknown>;
  Members?: Array<{ ObjectIdentifier: string; ObjectType: string }>;
  Sessions?: { Results?: Array<{ UserSID: string; ComputerSID: string }> };
  PrivilegedSessions?: { Results?: Array<{ UserSID: string; ComputerSID: string }> };
  LocalAdmins?: { Results?: Array<{ ObjectIdentifier: string; ObjectType: string }> };
}

interface BHFile {
  meta?: { type?: string };
  data?: BHObject[];
}

type Kind = "user" | "group" | "computer";

/** Accepts a zip (as SharpHound produces) or individual JSON files. */
export function readCollection(files: Array<{ name: string; content: Uint8Array }>): Array<{ type: string; data: BHObject[] }> {
  const out: Array<{ type: string; data: BHObject[] }> = [];
  const take = (name: string, bytes: Uint8Array) => {
    if (!name.toLowerCase().endsWith(".json")) return;
    // SharpHound writes UTF-8 with a BOM.
    const json = JSON.parse(strFromU8(bytes).replace(/^﻿/, "")) as BHFile;
    const type = json.meta?.type?.toLowerCase();
    if (type && Array.isArray(json.data)) out.push({ type, data: json.data });
  };
  for (const f of files) {
    const isZip = f.content[0] === 0x50 && f.content[1] === 0x4b;
    if (isZip) {
      for (const [name, bytes] of Object.entries(unzipSync(f.content))) take(name, bytes);
    } else take(f.name, f.content);
  }
  return out;
}

export function isBloodHound(files: Array<{ name: string; content: Uint8Array }>): boolean {
  try {
    return readCollection(files).some((c) => ["users", "groups", "computers"].includes(c.type));
  } catch {
    return false;
  }
}

export function parseBloodHound(files: Array<{ name: string; content: Uint8Array }>, options: { rawIds: string[]; observedAt?: string }): IngestBatch {
  const collections = readCollection(files);
  const items: IngestItem[] = [];
  /** SID → the principal's natural key, so relations can refer to it. */
  const bySid = new Map<string, { realm: string; name: string; kind: Kind }>();

  const kindOf: Record<string, Kind> = { users: "user", groups: "group", computers: "computer" };
  for (const c of collections) {
    const kind = kindOf[c.type];
    if (!kind) continue;
    for (const o of c.data) {
      const p = o.Properties ?? {};
      const full = String(p.name ?? "");
      const realm = String(p.domain ?? full.split("@")[1] ?? "").toUpperCase();
      if (!full || !realm) continue;
      // users and groups are "NAME@DOMAIN"; computers are "HOST.DOMAIN"
      const name =
        kind === "computer"
          ? full.split(".")[0]!.toLowerCase()
          : kind === "user" && p.samaccountname
            ? String(p.samaccountname).toLowerCase()
            : full.split("@")[0]!.toLowerCase();
      bySid.set(o.ObjectIdentifier, { realm, name, kind });
      items.push({
        op: "upsert",
        kind: "principal",
        key: { realm, name },
        attributes: {
          principalType: kind,
          displayName: full,
          sid: o.ObjectIdentifier,
          ...(typeof p.enabled === "boolean" ? { enabled: p.enabled } : {}),
          ...(p.admincount === true || p.highvalue === true ? { privileged: true } : {}),
          ...(typeof p.email === "string" && p.email ? { email: p.email } : {}),
        },
        confidence: 1,
      });
    }
  }

  const ref = (sid: string) => {
    const p = bySid.get(sid);
    return p ? { kind: "principal" as const, key: { realm: p.realm, name: p.name } } : undefined;
  };
  const relate = (type: "member_of" | "admin_to" | "has_session", fromSid: string, toSid: string) => {
    const from = ref(fromSid);
    const to = ref(toSid);
    if (from && to) items.push({ op: "relate", type, from, to });
  };

  for (const c of collections) {
    for (const o of c.data) {
      for (const m of o.Members ?? []) relate("member_of", m.ObjectIdentifier, o.ObjectIdentifier);
      for (const s of [...(o.Sessions?.Results ?? []), ...(o.PrivilegedSessions?.Results ?? [])]) relate("has_session", s.UserSID, s.ComputerSID);
      for (const a of o.LocalAdmins?.Results ?? []) relate("admin_to", a.ObjectIdentifier, o.ObjectIdentifier);
    }
  }

  return {
    format: INGEST_FORMAT,
    source: { parser: PARSER_ID, tool: "bloodhound" },
    rawIds: options.rawIds,
    observedAt: options.observedAt ?? new Date().toISOString(),
    items,
  };
}
