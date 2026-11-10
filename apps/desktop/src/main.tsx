import { createRoot } from "react-dom/client";
import { App } from "./App";
import { CoreClient } from "./client";
import "./styles.css";
import { ErrorBoundary } from "./ui/ErrorBoundary";
import { reportErrorsTo } from "./ui/reportError";

const params = new URLSearchParams(location.search);
const client = new CoreClient(params.get("url") ?? params.get("port") ?? "", params.get("token") ?? "");
reportErrorsTo(client);

// The last line of defence: a render error anywhere shows what failed and a way back, never an
// empty window (each panel also has its own boundary, so this one is only reached from the shell).
createRoot(document.getElementById("root")!).render(
  <ErrorBoundary area="window">
    <App client={client} />
  </ErrorBoundary>,
);

// In the desktop app the splash is its own small window (electron/splash): the page's copy is only
// for the browser. Either way the workbench says when it is connected to the core.
const desktop = window.penteosDesktop;
if (desktop) document.getElementById("splash")?.remove();
const shownAt = performance.now();
const hideSplash = () => {
  const el = document.getElementById("splash");
  if (!el) return;
  setTimeout(() => {
    el.classList.add("gone");
    setTimeout(() => el.remove(), 500);
  }, Math.max(0, 900 - (performance.now() - shownAt)));
};
// On first connection, warm the known-vulnerability feeds in the background if they were never
// downloaded, so a lookup later is instant and works offline. Never blocks; failures are ignored
// (the Tools panel shows the status and a manual "Actualizar").
function warmVulnFeeds() {
  void client
    .call<{ feeds: Array<{ asOf: string | null }> }>("vuln.sources", {})
    .then((r) => {
      if (r.feeds.length && r.feeds.every((f) => f.asOf === null)) void client.call("vuln.refresh", {}).catch(() => {});
    })
    .catch(() => {});
}
const offSplash = client.onStatus((connected) => {
  if (connected) {
    hideSplash();
    desktop?.appReady?.();
    warmVulnFeeds();
    offSplash();
  }
});
if (client.connected) {
  hideSplash();
  desktop?.appReady?.();
}
// If the core never answers, the workbench shows why: do not keep the splash over it.
setTimeout(hideSplash, 15000);
