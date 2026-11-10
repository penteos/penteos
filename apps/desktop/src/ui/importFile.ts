import { useApp } from "../state";
import { toast } from "./bits";
import { t } from "../i18n";

/** Reads a file chosen by the operator and sends it to the core to import. */
export async function importFile(client: ReturnType<typeof useApp>["client"]) {
  const input = document.createElement("input");
  input.type = "file";
  input.accept = ".xml,.zip,.json,.har,.nessus";
  input.onchange = async () => {
    const file = input.files?.[0];
    if (!file) return;
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    try {
      const r = await client.call<{ format: string; summary: { created: Record<string, number>; edges: number } }>("ingest.import", { filename: file.name, contentBase64: btoa(binary) });
      const created = Object.entries(r.summary.created).map(([k, n]) => `${n} ${k}`).join(", ") || t("ops.import.nothingNew");
      toast("ok", t("ops.import.done", { format: r.format }), t("ops.import.summary", { created, edges: r.summary.edges }));
    } catch (e) {
      toast("bad", t("ops.import.failed"), (e as Error).message);
    }
  };
  input.click();
}
