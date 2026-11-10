import esCommon from "./es/common";
import esLabels from "./es/labels";
import esShell from "./es/shell";
import esStart from "./es/start";
import esTeam from "./es/team";
import esAgent from "./es/agent";
import esOps from "./es/ops";
import esWeb from "./es/web";
import esWork from "./es/work";
import esData from "./es/data";
import esPlugins from "./es/plugins";
import enCommon from "./en/common";
import enLabels from "./en/labels";
import enShell from "./en/shell";
import enStart from "./en/start";
import enTeam from "./en/team";
import enAgent from "./en/agent";
import enOps from "./en/ops";
import enWeb from "./en/web";
import enWork from "./en/work";
import enData from "./en/data";
import enPlugins from "./en/plugins";

type Catalog = Record<string, Record<string, string>>;

/** One namespace per area of the app; Spanish is the source, English mirrors every key. */
export const CATALOGS: Record<"es" | "en", Catalog> = {
  es: { common: esCommon, labels: esLabels, shell: esShell, start: esStart, team: esTeam, agent: esAgent, ops: esOps, web: esWeb, work: esWork, data: esData, plugins: esPlugins },
  en: { common: enCommon, labels: enLabels, shell: enShell, start: enStart, team: enTeam, agent: enAgent, ops: enOps, web: enWeb, work: enWork, data: enData, plugins: enPlugins },
};
