import { t } from "./i18n";
import type { BottomTab, EditorPanelId } from "./state";

/**
 * What each kind of engagement is for and what it shows. The mode shapes the workspace - the
 * sections in the activity bar, the start page, the default risk - but never locks anything
 * away: "View → Show all sections" shows everything, and the mode can be changed later.
 */

export type ModeId = "web" | "infra" | "custom";

export interface ModeInfo {
  id: ModeId;
  title: string;
  /** One line under the title. */
  tagline: string;
  /** What you do in this mode, for the person choosing it. */
  explain: string[];
  sections: EditorPanelId[];
  bottom: BottomTab[];
  risk: "passive" | "active" | "intrusive" | "exploitation";
}

const ALL: EditorPanelId[] = ["scope", "identities", "web", "coverage", "proxy", "services", "hosts", "domains", "findings", "secrets", "evolution", "board", "notes", "memory", "report", "tools"];
const BASE_BOTTOM: BottomTab[] = ["terminal", "runs", "activity"];

/** The explanation lines of a mode, in the operator's language. */
const lines = (id: ModeId, n: number): string[] => Array.from({ length: n }, (_, i) => t(`shell.mode.${id}.explain${i + 1}`));

export const MODES: Record<ModeId, ModeInfo> = {
  web: {
    id: "web",
    get title() {
      return t("shell.mode.web.title");
    },
    get tagline() {
      return t("shell.mode.web.tagline");
    },
    get explain() {
      return lines("web", 3);
    },
    sections: ["scope", "web", "coverage", "proxy", "domains", "services", "hosts", "findings", "secrets", "board", "notes", "memory", "report", "tools"],
    bottom: BASE_BOTTOM,
    risk: "intrusive",
  },
  infra: {
    id: "infra",
    get title() {
      return t("shell.mode.infra.title");
    },
    get tagline() {
      return t("shell.mode.infra.tagline");
    },
    get explain() {
      return lines("infra", 3);
    },
    sections: ["scope", "hosts", "services", "domains", "identities", "findings", "secrets", "board", "notes", "memory", "report", "tools"],
    bottom: BASE_BOTTOM,
    risk: "intrusive",
  },
  custom: {
    id: "custom",
    get title() {
      return t("shell.mode.custom.title");
    },
    get tagline() {
      return t("shell.mode.custom.tagline");
    },
    get explain() {
      return lines("custom", 1);
    },
    sections: ALL,
    bottom: ["terminal", "log", "runs", "activity"],
    risk: "intrusive",
  },
};

/** The target types offered when creating a project. */
export const MODE_ORDER: ModeId[] = ["web", "infra"];

export const modeOf = (id: string | undefined): ModeInfo => MODES[(id as ModeId) ?? "custom"] ?? MODES.custom;

export const ALL_SECTIONS = ALL;

const SHOW_ALL_KEY = "penteos.showAllSections";
export function loadShowAll(): boolean {
  try {
    return localStorage.getItem(SHOW_ALL_KEY) === "1";
  } catch {
    return false;
  }
}
export function saveShowAll(v: boolean): void {
  try {
    localStorage.setItem(SHOW_ALL_KEY, v ? "1" : "0");
  } catch {
    /* storage unavailable */
  }
}
