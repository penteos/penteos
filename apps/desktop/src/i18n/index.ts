/**
 * The interface in the operator's language.
 *
 * Every visible string lives in a catalog: `src/i18n/es/<ns>.ts` and `src/i18n/en/<ns>.ts`, one
 * namespace per area of the app, flat keys. Spanish is neutral and serious; English mirrors it.
 *
 *   t("board.answer")                       → "Responder" / "Reply"
 *   t("board.waiting", { n: 2 })            → "{n} tareas te esperan" with the value in place
 *   tn("board.tasksWaiting", 2)             → picks "board.tasksWaiting.one" or ".other", {n} = 2
 *
 * The language is the operator's (workspace prefs), cached in localStorage so the first paint is
 * already right. Changing it reloads the window: simpler and safer than re-rendering everything.
 */

import { CATALOGS } from "./catalogs";

export type Lang = "es" | "en";
export const LANGS: Array<{ id: Lang; name: string }> = [
  { id: "es", name: "Español" },
  { id: "en", name: "English" },
];

const KEY = "penteos.lang";

function initial(): Lang {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === "es" || saved === "en") return saved;
  } catch {
    /* storage unavailable */
  }
  // English until the operator picks another language: one predictable start for everyone,
  // instead of a mix of the system's language here and English elsewhere.
  return "en";
}

let current: Lang = initial();

export function lang(): Lang {
  return current;
}

/** BCP 47 tag for Intl (dates, numbers). */
export function locale(): string {
  return current === "es" ? "es" : "en-US";
}

/** Saves the choice locally and reloads so every screen comes back in that language. */
export function setLang(next: Lang, reload = true): void {
  try {
    localStorage.setItem(KEY, next);
  } catch {
    /* storage unavailable */
  }
  // The desktop app's start-up dialogs come before this window: they read it from there.
  void window.penteosDesktop?.setLanguage?.(next)?.catch(() => undefined);
  if (next !== current && reload) location.reload();
  current = next;
}

const warned = new Set<string>();

function lookup(key: string): string | undefined {
  const dot = key.indexOf(".");
  const ns = key.slice(0, dot);
  const rest = key.slice(dot + 1);
  return CATALOGS[current][ns]?.[rest] ?? CATALOGS.es[ns]?.[rest];
}

function fill(text: string, params?: Record<string, unknown>): string {
  if (!params) return text;
  return text.replace(/\{(\w+)\}/g, (m, name: string) => (name in params ? String(params[name] ?? "") : m));
}

/** The text for a key in the operator's language; the key itself (and a console warning) if missing. */
/** Running on a Mac (the desktop app, or a browser on one). */
export const isMac = typeof navigator !== "undefined" && /Mac/i.test(navigator.platform || navigator.userAgent);

/**
 * Shortcuts as each system writes them: on a Mac "Ctrl+K" is ⌘K. Ctrl+` stays ⌃` there, because
 * ⌘` belongs to macOS (it switches windows); the workbench accepts either key.
 */
export function keys(text: string): string {
  if (!isMac) return text;
  return text.replace(/Ctrl\+`/g, "⌃`").replace(/Ctrl\+Shift\+/g, "⇧⌘").replace(/Ctrl\+Enter/g, "⌘↩").replace(/Ctrl[+ ]/g, "⌘").replace(/Alt\+/g, "⌥");
}

export function t(key: string, params?: Record<string, unknown>): string {
  const text = lookup(key);
  if (text === undefined) {
    if (!warned.has(key)) {
      warned.add(key);
      console.warn(`[i18n] missing key: ${key}`);
    }
    return key;
  }
  return keys(fill(text, params));
}

/** Singular or plural: looks up `<key>.one` or `<key>.other`; `{n}` is the count. */
export function tn(key: string, n: number, params?: Record<string, unknown>): string {
  return t(`${key}.${n === 1 ? "one" : "other"}`, { n, ...params });
}

/** Relative time ("hace 5 min" / "5 min ago"). */
export function ago(iso: string | undefined, now = Date.now()): string {
  if (!iso) return "";
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (s < 5) return t("common.time.now");
  if (s < 60) return t("common.time.seconds", { n: s });
  const m = Math.round(s / 60);
  if (m < 60) return t("common.time.minutes", { n: m });
  const h = Math.round(m / 60);
  if (h < 24) return t("common.time.hours", { n: h });
  return new Date(iso).toLocaleDateString(locale(), { day: "2-digit", month: "short" });
}
