/**
 * The runner of Python plugins: the same line protocol and
 * the same API as a Node plugin (`penteos.http`, `penteos.graph`, `penteos.store`…), for whoever
 * prefers Python's ecosystem. Python plugins run free (a normal process), watched by Penteos.
 *
 * A plugin's main.py defines `activate(plugin)` and registers handlers:
 *
 *   def activate(plugin):
 *       @plugin.operation("scan")
 *       def scan(input, penteos):
 *           r = penteos.http({"url": "https://example.com"})
 *           return {"status": r["status"]}
 */

export const PYTHON_RUNNER_SOURCE = String.raw`# Penteos Python plugin runner (generated; do not edit)
import base64, importlib.util, json, os, sys, traceback

MARK = "\u0001P "
_out = sys.stdout
_seq = 0
_pending = []

def _send(msg):
    _out.write(MARK + json.dumps(msg, default=str) + "\n")
    _out.flush()

class _Log:
    def write(self, text):
        text = str(text)
        if text.strip():
            _send({"type": "log", "text": text.rstrip()[:2000]})
        return len(text)
    def flush(self):
        pass

sys.stdout = _Log()
sys.stderr = _Log()

def _read():
    line = sys.stdin.readline()
    if not line:
        os._exit(0)
    return json.loads(line)

def _ask(call_id, step):
    global _seq
    _seq += 1
    rid = _seq
    _send({"type": "rpc", "id": rid, "callId": call_id, "step": step})
    while True:
        m = _read()
        if m.get("type") == "rpc_result" and m.get("id") == rid:
            if m.get("ok"):
                return m.get("value")
            raise RuntimeError(m.get("error") or "the core refused")
        _pending.append(m)

class _Graph:
    def __init__(self, ask): self._ask = ask
    def query(self, kind, **opts): return self._ask(dict({"do": "graph_query", "kind": kind}, **opts))
    def get(self, entity): return self._ask({"do": "graph_get", "entity": entity})
    def put(self, type, attributes, **opts): return self._ask(dict({"do": "put", "type": type, "attributes": attributes}, **opts))
    def annotate(self, entity, data): return self._ask({"do": "annotate", "entity": entity, "data": data})
    def relate(self, frm, to): return self._ask({"do": "relate", "from": frm, "to": to})

class _Store:
    def __init__(self, ask): self._ask = ask
    def insert(self, table, row, **opts): return self._ask(dict({"do": "store_insert", "table": table, "row": row}, **opts))
    def insert_many(self, table, rows, **opts): return self._ask(dict({"do": "store_insert", "table": table, "rows": rows}, **opts))
    def query(self, table, **opts): return self._ask(dict({"do": "store_query", "table": table}, **opts))
    def update(self, table, where, set, **opts): return self._ask(dict({"do": "store_update", "table": table, "where": where, "set": set}, **opts))
    def delete(self, table, where, **opts): return self._ask(dict({"do": "store_delete", "table": table, "where": where}, **opts))

class _Files:
    """Files for the operator, in the project's folder: write(name, data) with str, bytes or JSON; dir for a free plugin to write there itself."""
    def __init__(self, ask, output): self._ask = ask; self.dir = output
    def write(self, name, data):
        if isinstance(data, str): raw = data.encode("utf-8")
        elif isinstance(data, (bytes, bytearray, memoryview)): raw = bytes(data)
        else: raw = json.dumps(data, indent=2, default=str).encode("utf-8")
        return self._ask({"do": "file", "name": name, "content": base64.b64encode(raw).decode("ascii"), "encoding": "base64"})

class _Penteos:
    def __init__(self, call_id, input, engagement, output):
        ask = lambda step: _ask(call_id, step)
        self._ask = ask
        self.input = input
        self.engagement = engagement
        self.output_dir = output
        self.graph = _Graph(ask)
        self.store = _Store(ask)
        self.files = _Files(ask, output)
    def http(self, request): return self._ask(dict({"do": "http"}, **request))
    def finding_draft(self, **finding): return self._ask(dict({"do": "finding_draft"}, **finding))
    def notify(self, title, body=None, level="info"): return self._ask({"do": "notify", "title": title, "level": level, **({"body": body} if body else {})})
    def settings(self): return self._ask({"do": "settings"})
    def report(self, **options):
        """The official deliverable with this plugin's choices (a .docx among its files): title, author, company, color, logo, sections, skip, min_severity, include_drafts, extra=[{title, markdown, after}], name, format."""
        camel = {"include_drafts": "includeDrafts", "min_severity": "minSeverity"}
        return self._ask(dict({"do": "report"}, **{camel.get(k, k): v for k, v in options.items()}))
    def log(self, *parts): _send({"type": "log", "text": " ".join(str(p) for p in parts)[:2000]})

class _Registrar:
    def __init__(self): self.handlers = {}
    def operation(self, name, fn=None):
        if fn is not None:
            self.handlers[str(name)] = fn
            return fn
        def deco(f):
            self.handlers[str(name)] = f
            return f
        return deco

def _handle(registrar, m):
    if m.get("type") != "call":
        return
    fn = registrar.handlers.get(m.get("handler"))
    try:
        if fn is None:
            raise RuntimeError("no handler " + str(m.get("handler")))
        value = fn(m.get("input") or {}, _Penteos(m.get("id"), m.get("input") or {}, m.get("engagement"), m.get("output")))
        _send({"type": "return", "id": m.get("id"), "ok": True, "value": json.loads(json.dumps(value, default=str))})
    except Exception as e:
        _send({"type": "return", "id": m.get("id"), "ok": False, "error": (str(e) or type(e).__name__)[:2000] + "\n" + traceback.format_exc()[-1500:]})

def main():
    path = sys.argv[1]
    sys.path.insert(0, os.path.dirname(path))
    spec = importlib.util.spec_from_file_location("penteos_plugin_main", path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        registrar = _Registrar()
        if not hasattr(module, "activate"):
            raise RuntimeError("main.py defines no activate(plugin)")
        module.activate(registrar)
    except Exception as e:
        _send({"type": "fatal", "error": "activation failed: " + str(e)[:1000]})
        sys.exit(78)
    _send({"type": "ready", "handlers": list(registrar.handlers.keys())})
    while True:
        m = _pending.pop(0) if _pending else _read()
        _handle(registrar, m)

main()
`;
