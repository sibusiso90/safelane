// In-browser backend for static hosting (GitHub Pages). Runs the real `safelane` package
// in Pyodide and answers the same /api/* calls the FastAPI app serves, so nothing a
// visitor types ever leaves their browser.
const PYODIDE = "https://cdn.jsdelivr.net/pyodide/v314.0.7/full/";
const FILES = ["safelane/__init__.py", "safelane/audit.py", "safelane/llm.py", "safelane/policy.py",
               "safelane/redactor.py", "safelane/service.py", "config/register.yaml"];

const HANDLER = `
import json, sys
sys.path.insert(0, ".")
from safelane.service import Gateway, GatewayError

gateway = Gateway("config/register.yaml", ":memory:")

def _need(data, key, max_len=None):
    v = data.get(key)
    if not isinstance(v, str) or not v.strip():
        raise GatewayError(422, f"{key} is required")
    if max_len and len(v) > max_len:
        raise GatewayError(422, f"{key} is longer than {max_len} characters")
    return v

def handle(method, path, body):
    data = json.loads(body) if body else {}
    try:
        if path == "/api/tools":
            out = {**gateway.tools(), "demo": True}
        elif path == "/api/ask":
            out = gateway.ask(_need(data, "user"), _need(data, "tool_id"), _need(data, "prompt", 20000),
                              data.get("data_class", "internal"))
        elif path == "/api/reviews":
            out = gateway.list_reviews()
        elif path.startswith("/api/reviews/") and method == "POST":
            out = gateway.decide(path.rsplit("/", 1)[1], _need(data, "reviewer"), _need(data, "action"),
                                 data.get("note", ""))
        elif path == "/api/audit":
            out = gateway.audit.entries(100)
        elif path == "/api/audit/verify":
            out = gateway.audit.verify()
        elif path == "/api/audit/tamper" and method == "POST":
            out = gateway.audit.simulate_tamper()
        elif path == "/api/audit/restore" and method == "POST":
            out = gateway.audit.restore()
        elif path == "/api/stats":
            out = gateway.audit.summary()
        else:
            return json.dumps([404, {"detail": "Not found"}])
        return json.dumps([200, out])
    except GatewayError as e:
        return json.dumps([e.status, {"detail": e.detail}])
`;

const handle = (async () => {
  const { loadPyodide } = await import(PYODIDE + "pyodide.mjs");
  const py = await loadPyodide({ indexURL: PYODIDE });
  await py.loadPackage("pyyaml");
  for (const f of FILES) {
    const r = await fetch(f, { cache: "no-cache" }); // revalidate, so a redeploy is picked up at once
    if (!r.ok) throw new Error(`Could not load ${f}`);
    py.FS.mkdirTree(f.slice(0, f.lastIndexOf("/")));
    py.FS.writeFile(f, await r.text());
  }
  py.runPython(HANDLER);
  return py.globals.get("handle");
})();

export async function call(url, opt = {}) {
  const [status, body] = JSON.parse((await handle)(opt.method || "GET", url, opt.body || ""));
  return { status, body };
}
