// The band of a page the proxy refused: it only shows why and reports the operator's choice.
const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("block", {
  action: (a) => ipcRenderer.send("bk:action", a),
  onShow: (cb) => ipcRenderer.on("bk:show", (_e, b) => cb(b)),
  onError: (cb) => ipcRenderer.on("bk:error", (_e, text) => cb(text)),
});
