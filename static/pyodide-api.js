// In-browser backend for static hosting (GitHub Pages). Runs the real `safelane` package
// in Pyodide and answers the same /api/* calls the FastAPI app serves, so nothing a
// visitor types ever leaves their browser.
const PYODIDE = "https://cdn.jsdelivr.net/pyodide/v314.0.7/full/";
const FILES = ["safelane/__init__.py", "safelane/accounts.py", "safelane/audit.py", "safelane/llm.py",
               "safelane/policy.py", "safelane/redactor.py", "safelane/service.py",
               "config/register.yaml", "config/accounts.yaml"];

// Mirrors the routes and role checks in safelane/main.py; the checks themselves live in
// safelane/service.py, so both hosts enforce the same rules.
const HANDLER = `
import json, sys
sys.path.insert(0, ".")
from safelane.policy import CLASS_ORDER
from safelane.service import Gateway, GatewayError

gateway = Gateway("config/register.yaml", ":memory:", "config/accounts.yaml")

def _need(data, key, max_len=None):
    v = data.get(key)
    if not isinstance(v, str) or not v.strip():
        raise GatewayError(422, f"{key} is required")
    if max_len and len(v) > max_len:
        raise GatewayError(422, f"{key} is longer than {max_len} characters")
    return v

def handle(method, path, body, token):
    data = json.loads(body) if body else {}
    try:
        if path == "/api/tools":
            out = {**gateway.tools(), "demo": True, "demo_accounts": gateway.demo_accounts(),
                   "demo_password": gateway.accounts.demo_password}
        elif path == "/api/login" and method == "POST":
            out = gateway.login(_need(data, "username", 64), _need(data, "password", 256), "browser")
        elif path == "/api/logout" and method == "POST":
            out = gateway.logout(token)
        else:
            me = gateway.session(token)
            if path == "/api/me":
                out = me.view()
            elif path == "/api/ask" and method == "POST":
                if data.get("data_class", "internal") not in CLASS_ORDER:
                    raise GatewayError(422, f"data_class must be one of {CLASS_ORDER}")
                out = gateway.ask(me, _need(data, "tool_id", 100), _need(data, "prompt", 20000),
                                  data.get("data_class", "internal"))
            elif path == "/api/reviews":
                out = gateway.list_reviews(me)
            elif path.startswith("/api/reviews/") and method == "POST":
                out = gateway.decide(path.rsplit("/", 1)[1], me, _need(data, "action"),
                                     str(data.get("note", ""))[:1000])
            elif path == "/api/audit":
                out = gateway.audit_entries(me, 100)
            elif path == "/api/audit/verify":
                out = gateway.audit_verify(me)
            elif path == "/api/audit/tamper" and method == "POST":
                out = gateway.simulate_tamper(me)
            elif path == "/api/audit/restore" and method == "POST":
                out = gateway.restore(me)
            elif path == "/api/stats":
                out = gateway.stats(me)
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
  const auth = opt.headers?.Authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  const [status, body] = JSON.parse((await handle)(opt.method || "GET", url.split("?")[0], opt.body || "", token));
  return { status, body };
}
