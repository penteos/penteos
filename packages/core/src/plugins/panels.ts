import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { resolve, sep } from "node:path";

/**
 * Panels of code plugins: an HTML file of the plugin, served by the core
 * on its own origin to an <iframe sandbox="allow-scripts"> - so it can touch nothing of the app -,
 * with a policy that forbids every network request, and reached with a short-lived ticket (never
 * the operator's token). Its only way out is the bridge injected here: window.penteos.call(op,
 * input), which the app answers only for that plugin's own operations.
 */

/** Nothing leaves the frame: no fetch, no images from the network, no forms, no navigation of its own. */
export const PANEL_CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; font-src data:; media-src data: blob:; base-uri 'none'; form-action 'none'";

/** A free plugin's panel: it may load scripts and reach the network (Penteos still frames it). */
export const PANEL_CSP_FREE = "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; base-uri 'none'";

export const PANEL_LIMITS = { bytes: 1024 * 1024, ticketMs: 2 * 60_000, tickets: 200 } as const;

interface Ticket {
  free: boolean;
  pluginId: string;
  panelId: string;
  file: string;
  context: Record<string, unknown>;
  expires: number;
}

export class PanelTickets {
  private readonly tickets = new Map<string, Ticket>();

  /** A ticket for one panel file, checked to be a file inside the plugin's folder. */
  issue(pluginId: string, panelId: string, pluginDir: string, file: string, context: Record<string, unknown>, free = false): string {
    const dir = realpathSync(pluginDir);
    const full = resolve(dir, file);
    if (!full.startsWith(dir + sep) || !existsSync(full) || realpathSync(full) !== full) throw new Error(`panel file ${file} is not a file inside the plugin folder`);
    if (statSync(full).size > PANEL_LIMITS.bytes) throw new Error(`panel file ${file} is larger than ${PANEL_LIMITS.bytes / 1024} KB`);
    const now = Date.now();
    for (const [k, t] of this.tickets) if (t.expires < now) this.tickets.delete(k);
    if (this.tickets.size >= PANEL_LIMITS.tickets) this.tickets.delete(this.tickets.keys().next().value!);
    const ticket = randomBytes(24).toString("base64url");
    this.tickets.set(ticket, { free, pluginId, panelId, file: full, context, expires: now + PANEL_LIMITS.ticketMs });
    return ticket;
  }

  /** The page for a ticket: status, headers and body (the server writes them as they are). */
  serve(ticket: string): { status: number; headers: Record<string, string>; body: string } {
    const t = /^[A-Za-z0-9_-]{20,64}$/.test(ticket) ? this.tickets.get(ticket) : undefined;
    const headers = {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": t?.free ? PANEL_CSP_FREE : PANEL_CSP,
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "cross-origin-resource-policy": "cross-origin",
    };
    if (!t || t.expires < Date.now()) return { status: 404, headers, body: "<!doctype html><title>Expired</title>" };
    let html: string;
    try {
      html = readFileSync(t.file, "utf8");
    } catch {
      return { status: 404, headers, body: "<!doctype html><title>Missing</title>" };
    }
    return { status: 200, headers, body: panelDocument(html, { plugin: t.pluginId, panel: t.panelId, free: t.free, ...t.context }) };
  }
}

/**
 * The bridge, first thing in the page: window.penteos.call(op, input) → the app, which answers or
 * refuses; window.penteos.files.download|open|reveal(name) → one of the plugin's files in the project.
 */
export function panelDocument(html: string, context: Record<string, unknown>): string {
  const ctx = JSON.stringify(context).replace(/</g, "\\u003c");
  const bridge = `<script>(()=>{let n=0;const w=new Map();addEventListener("message",(e)=>{if(e.source!==parent)return;const m=e.data;if(!m||m.penteos!=="result"||!w.has(m.id))return;const p=w.get(m.id);w.delete(m.id);m.ok?p.resolve(m.value):p.reject(new Error(m.error));});const ask=(m)=>new Promise((resolve,reject)=>{const id=++n;w.set(id,{resolve,reject});parent.postMessage({...m,id},"*");});const file=(action)=>(name)=>ask({penteos:"file",action,name:String(name)});Object.defineProperty(window,"penteos",{value:Object.freeze({context:Object.freeze(${ctx}),call:(op,input)=>ask({penteos:"call",op:String(op),input:input??{}}),files:Object.freeze({download:file("download"),open:file("open"),reveal:file("reveal")})})});})();</script>`;
  const head = /<head[^>]*>/i.exec(html);
  if (head) return html.slice(0, head.index + head[0].length) + bridge + html.slice(head.index + head[0].length);
  return `<!doctype html><html><head><meta charset="utf-8">${bridge}</head><body>${html}</body></html>`;
}
