"""A fake APC NMC classic web UI, faithful to the page shapes the console's
parsers expect, so the whole console can be tested without a real card.
State is inspectable/manipulable via /__ endpoints (not part of the NMC UI)."""
import json, re, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOGON = """<html><head><title>APC | Log On</title></head><body>
<form method="post" action="/Forms/login1">
<input type="text" name="login_username">
<input type="password" name="login_password">
<input type="hidden" name="login_token" value="t1">
<input type="submit" name="submit" value="Log On">
</form></body></html>"""

def home_page(state):
    return ("<html><body><div>Device Status</div>"
            f"<div>Total Load: {state['total']:.1f} Amps</div>"
            f"<div>Bank B1 Load: {state['b1']:.1f} Amps</div>"
            f"<div>Bank B2 Load: {state['b2']:.1f} Amps</div>"
            "<div>No Alarms</div></body></html>")

def status_page(state):
    rows = []
    for n in range(1, 25):
        o = state["outlets"][n]
        bank = 1 if n <= 12 else 2
        rows.append(f'<tr><td>[B{bank}]</td><td>{o["state"]}</td>'
                    f'<td><a href="olnamcfg.htm?outlet={n}">{o["name"]}</a></td></tr>')
    return "<html><body><table>" + "".join(rows) + "</table></body></html>"

def control_page():
    cbs = []
    for col in (1, 2, 3):
        for row in range(2, 10):
            cbs.append(f'<input type="checkbox" name="OL_Cntrl_Col{col}_Btn" value="?{row},2">')
    return ("<html><body><form method=\"post\" action=\"/Forms/outlctrl1\">"
            '<select name="rPDUOutletCtrl">'
            '<option value=1>On Immediate</option><option value=2>Off Immediate</option>'
            '<option value=3>Reboot Immediate</option></select>'
            + "".join(cbs) +
            '<input type="submit" name="submit" value="Next >>"></form></body></html>')

CONFIRM_PAGE = ("<html><body><form method=\"post\" action=\"/Forms/outlctrl2\">"
                '<input type="hidden" name="confirm_token" value="x">'
                '<input type="submit" name="submit" value="Apply"></form></body></html>')

def config_page(state, n):
    o = state["outlets"][n]
    return ("<html><body><form method=\"post\" action=\"/Forms/olnamcfg1\">"
            f'<input type="hidden" name="cfgLink" value="link-{n}">'
            f'<input type="text" name="rPDUOLCfgName" value="{o["name"]}">'
            '<input type="text" name="rPDUOLCfgOnDelay" value="5">'
            '<input type="text" name="rPDUOLCfgOffDelay" value="7">'
            '<input type="radio" name="rPDUOLCfgRebootMode" value="immediate" checked>'
            '<input type="radio" name="rPDUOLCfgRebootMode" value="delayed">'
            '<input type="submit" name="submit" value="Apply"></form></body></html>')

def make_state(username="apc", password="apc"):
    return {"username": username, "password": password, "session": False,
            "logins": 0, "login_attempts": 0, "refuse_403": False,
            "ignore_next_control": False, "total": 1.5, "b1": 0.5, "b2": 1.0,
            "pending": None, "last_config_post": {},
            "outlets": {n: {"name": f"Outlet {n}", "state": "On" if n == 6 else "Off"} for n in range(1, 25)}}

class FakeNmc(BaseHTTPRequestHandler):
    state = None
    def log_message(self, *a): pass
    def _send(self, code, body, ctype="text/html", extra=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)
    def _form(self):
        n = int(self.headers.get("Content-Length") or 0)
        return urllib.parse.parse_qs(self.rfile.read(n).decode())
    def _authed(self): return self.state["session"] and "sess=xyz" in (self.headers.get("Cookie") or "")
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        st = self.state
        if path == "/__state":
            return self._send(200, json.dumps({"logins": st["logins"], "login_attempts": st["login_attempts"],
                                               "outlets": {str(k): v for k, v in st["outlets"].items()},
                                               "last_config_post": st["last_config_post"]}), "application/json")
        if path == "/logon.htm": return self._send(200, LOGON)
        if path == "/logout.htm":
            st["session"] = False
            return self._send(200, LOGON)
        if not self._authed(): return self._send(200, LOGON)
        if path in ("/home.htm", "/"): return self._send(200, home_page(st))
        if path == "/olstatus.htm": return self._send(200, status_page(st))
        if path == "/outlctrl.htm": return self._send(200, control_page())
        if path == "/olnamcfg.htm":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            st["config_outlet"] = int(q["outlet"][0])
            return self._send(200, config_page(st, st["config_outlet"]))
        return self._send(404, "nope", "text/plain")
    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        st = self.state
        if path == "/__set":
            n = int(self.headers.get("Content-Length") or 0)
            cfg = json.loads(self.rfile.read(n) or b"{}")
            for k in ("refuse_403", "ignore_next_control"):
                if k in cfg: st[k] = bool(cfg[k])
            return self._send(200, "{}", "application/json")
        if path == "/__expire":
            st["session"] = False
            return self._send(200, "{}", "application/json")
        if path == "/Forms/login1":
            st["login_attempts"] += 1
            if st["refuse_403"]:
                return self._send(403, "<html><body>APC | Application Error</body></html>")
            f = self._form()
            if (f.get("login_username", [""])[0] == st["username"] and
                    f.get("login_password", [""])[0] == st["password"]):
                st["session"] = True; st["logins"] += 1
                return self._send(200, home_page(st), extra={"Set-Cookie": "sess=xyz; Path=/"})
            return self._send(200, LOGON)
        if not self._authed(): return self._send(200, LOGON)
        if path == "/Forms/outlctrl1":
            f = self._form()
            action = {"1": "on", "2": "off", "3": "reboot"}.get(f.get("rPDUOutletCtrl", [""])[0])
            outlet = None
            for name, vals in f.items():
                m = re.fullmatch(r"OL_Cntrl_Col(\d)_Btn", name)
                if m:
                    row = int(vals[0].split(",")[0].lstrip("?"))
                    outlet = (int(m.group(1)) - 1) * 8 + (row - 2) + 1
            st["pending"] = (outlet, action)
            return self._send(200, CONFIRM_PAGE)
        if path == "/Forms/outlctrl2":
            self._form()
            if st["pending"] and not st["ignore_next_control"]:
                outlet, action = st["pending"]
                st["outlets"][outlet]["state"] = "Off" if action == "off" else "On"
            st["ignore_next_control"] = False
            st["pending"] = None
            return self._send(200, "<html><body>Done</body></html>")
        if path == "/Forms/olnamcfg1":
            f = {k: v[0] for k, v in self._form().items()}
            st["last_config_post"] = f
            n = st.get("config_outlet")
            if n and "rPDUOLCfgName" in f: st["outlets"][n]["name"] = f["rPDUOLCfgName"]
            return self._send(200, "<html><body>Saved</body></html>")
        return self._send(404, "nope", "text/plain")

def serve(port=0, username="apc", password="apc"):
    handler = type("BoundFake", (FakeNmc,), {"state": make_state(username, password)})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1], handler.state
