"""Integration tests for the PDU Console: the real server, driven over HTTP,
against fake NMC cards. No real PDU is touched. Run: python3 tests/run_tests.py"""
import http.cookiejar, json, os, subprocess, sys, tempfile, time, urllib.request, urllib.error
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
import fake_nmc

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAILURES, COUNT = [], 0
def check(name, cond, extra=""):
    global COUNT; COUNT += 1
    print(("PASS" if cond else "FAIL"), "-", name, extra if not cond else "")
    if not cond: FAILURES.append(name)

class Client:
    def __init__(self, base):
        self.base = base
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def call(self, method, path, data=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(data).encode() if data is not None else None,
                                     headers={"Content-Type": "application/json"})
        try:
            with self.op.open(req, timeout=30) as r: return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try: return e.code, json.loads(e.read() or b"{}")
            except Exception: return e.code, {}
    def get(self, p): return self.call("GET", p)
    def post(self, p, d=None): return self.call("POST", p, d if d is not None else {})

def fake_get(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as r:
        return json.loads(r.read())
def fake_post(port, path, data):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r: return json.loads(r.read() or b"{}")

def start_console(data_dir, port):
    env = dict(os.environ, PORT=str(port), PDU_DATA_DIR=data_dir)
    proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "app", "server.py")],
                            cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            with urllib.request.urlopen(base + "/api/health", timeout=2) as r:
                if r.status == 200: return proc, Client(base)
        except Exception: time.sleep(0.25)
    raise RuntimeError("console did not start")

def free_port():
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def main():
    fake1, fp1, fs1 = fake_nmc.serve()
    fake2, fp2, fs2 = fake_nmc.serve()
    tmp = tempfile.mkdtemp(prefix="pdu-test-")
    proc, c = start_console(tmp, free_port())
    try:
        # ---- auth ----
        s, b = c.get("/api/auth/state")
        check("auth state: not configured at first", s == 200 and b["configured"] is False and b["authed"] is False)
        s, b = c.post("/api/auth/setup", {"password": "short7"})
        check("setup rejects <8 char password", s == 400)
        s, b = c.post("/api/auth/setup", {"password": "console-pw-1"})
        check("setup accepts 8+ char password", s == 200)
        s, b = c.post("/api/auth/login", {"password": "wrong"})
        check("login rejects wrong password", s == 401)
        s, b = Client(c.base).get("/api/pdus")
        check("overview requires sign-in", s == 401)
        s, b = c.post("/api/auth/login", {"password": "console-pw-1"})
        check("login accepts the password", s == 200)
        # ---- add PDU validation ----
        s, b = c.post("/api/pdus", {"ip": "bad ip!", "name": "X", "username": "apc", "password": "apc"})
        check("add rejects malformed address", s == 400)
        s, b = c.post("/api/pdus", {"ip": f"127.0.0.1:{fp1}", "name": "Rack One", "username": "apc", "password": "nope"})
        check("add rejects wrong card password", s == 400 and "could not connect" in b.get("error", ""))
        s, b = c.post("/api/pdus", {"ip": f"127.0.0.1:{fp1}", "name": "Rack One", "username": "apc", "password": "apc"})
        check("add PDU 1 succeeds (host:port address)", s == 200 and b.get("id") == "rack-one", str(b))
        s, b = c.post("/api/pdus", {"ip": f"127.0.0.1:{fp1}", "name": "Again", "username": "apc", "password": "apc"})
        check("add rejects duplicate address", s == 400 and "already added" in b.get("error", ""))
        time.sleep(1.2)   # let the new PDU's poller establish its session
        # ---- overview + status ----
        s, b = c.get("/api/pdus")
        check("overview lists PDU 1 with live data", s == 200 and len(b["pdus"]) == 1 and b["pdus"][0]["ok"] is True
              and b["pdus"][0]["outlets_total"] == 24 and b["pdus"][0]["outlets_on"] == 1 and b["pdus"][0]["total_load"] == 1.5)
        s, b = c.get("/api/pdus/rack-one/status")
        outs = {o["n"]: o for o in b["status"]["outlets"]}
        check("status: 24 outlets, #6 on, banks split 1/2", len(outs) == 24 and outs[6]["state"] == "On"
              and outs[1]["bank"] == 1 and outs[24]["bank"] == 2 and b["status"]["loads"]["banks"] == {"1": 0.5, "2": 1.0})
        logins_after_add = fake_get(fp1, "/__state")["logins"]
        check("card logins so far: verify + one session", logins_after_add == 2, f"got {logins_after_add}")
        # ---- control, with state verification ----
        s, b = c.post("/api/pdus/rack-one/control", {"outlet": 22, "action": "on"})
        check("control without confirm is refused", s == 400)
        s, b = c.post("/api/pdus/rack-one/control", {"outlet": 22, "action": "on", "confirm": True})
        check("control ON outlet 22", s == 200 and "is now On" in b.get("message", ""), str(b))
        check("fake card shows outlet 22 On", fake_get(fp1, "/__state")["outlets"]["22"]["state"] == "On")
        fake_post(fp1, "/__set", {"ignore_next_control": True})
        s, b = c.post("/api/pdus/rack-one/control", {"outlet": 22, "action": "off", "confirm": True})
        check("verification catches a command the card ignored", s == 400 and "do not read Off" in b.get("error", ""), str(b))
        s, b = c.post("/api/pdus/rack-one/control", {"outlet": 22, "action": "off", "confirm": True})
        check("control OFF outlet 22", s == 200 and fake_get(fp1, "/__state")["outlets"]["22"]["state"] == "Off")
        # ---- session discipline ----
        s, b = c.post("/api/pdus/rack-one/refresh")
        check("session reused across polls/controls (still 2 logins)", fake_get(fp1, "/__state")["logins"] == 2,
              f"got {fake_get(fp1, '/__state')['logins']}")
        fake_post(fp1, "/__expire", {})
        s, b = c.post("/api/pdus/rack-one/refresh")
        check("expired session recovers with one re-login", s == 200 and b["status"] is not None
              and fake_get(fp1, "/__state")["logins"] == 3)
        # ---- rename preserves the other config fields ----
        s, b = c.post("/api/pdus/rack-one/rename", {"outlet": 7, "name": "Pump"})
        post = fake_get(fp1, "/__state")["last_config_post"]
        check("rename outlet 7", s == 200 and fake_get(fp1, "/__state")["outlets"]["7"]["name"] == "Pump")
        check("rename preserves delays/link/radio", post.get("rPDUOLCfgOnDelay") == "5" and post.get("rPDUOLCfgOffDelay") == "7"
              and post.get("cfgLink") == "link-7" and post.get("rPDUOLCfgRebootMode") == "immediate", str(post))
        s, b = c.post("/api/pdus/rack-one/rename", {"outlet": 7, "name": "bad<name"})
        check("rename rejects HTML characters", s == 400)
        s, b = c.post("/api/pdus/rack-one/rename", {"outlet": 7, "name": "x" * 24})
        check("rename rejects >23 chars", s == 400)
        # ---- groups ----
        s, b = c.post("/api/pdus/rack-one/groups", {"name": "Servers", "outlets": [9, 10]})
        check("create group", s == 200 and len(b["groups"]) == 1)
        s, b = c.post("/api/pdus/rack-one/groups", {"name": "Clash", "outlets": [10, 11]})
        check("group rejects an outlet already grouped", s == 400)
        s, b = c.post("/api/pdus/rack-one/groups", {"name": "Solo", "outlets": [11]})
        check("group requires at least 2 outlets", s == 400)
        s, b = c.post("/api/pdus/rack-one/group-control", {"group": "Servers", "action": "on", "confirm": True})
        st = fake_get(fp1, "/__state")["outlets"]
        check("group control switches all members", s == 200 and st["9"]["state"] == "On" and st["10"]["state"] == "On", str(b))
        # ---- locks ----
        s, b = c.post("/api/pdus/rack-one/lock", {"outlet": 5, "locked": True})
        check("lock outlet 5", s == 200 and b["locked"] == [5])
        s, b = c.post("/api/pdus/rack-one/control", {"outlet": 5, "action": "on", "confirm": True})
        check("locked outlet demands the console password (428)", s == 428)
        s, b = c.post("/api/pdus/rack-one/control", {"outlet": 5, "action": "on", "confirm": True, "password": "nope"})
        check("locked outlet rejects wrong password", s == 400 and "wrong console password" in b.get("error", ""))
        s, b = c.post("/api/pdus/rack-one/control", {"outlet": 5, "action": "on", "confirm": True, "password": "console-pw-1"})
        check("locked outlet accepts the console password", s == 200)
        s, b = c.post("/api/pdus/rack-one/lock", {"outlet": 5, "locked": False, "password": "nope"})
        check("unlock rejects wrong password", s == 403)
        s, b = c.post("/api/pdus/rack-one/lock", {"outlet": 5, "locked": False, "password": "console-pw-1"})
        check("unlock with the password", s == 200 and b["locked"] == [])
        s, b = c.post("/api/pdus/rack-one/grouplock", {"group": "Servers", "locked": True})
        check("lock the group", s == 200 and b["groups"][0]["locked"] is True)
        s, b = c.post("/api/pdus/rack-one/group-control", {"group": "Servers", "action": "off", "confirm": True})
        check("locked group demands the password (428)", s == 428)
        s, b = c.post("/api/pdus/rack-one/group-control", {"group": "Servers", "action": "off", "confirm": True, "password": "console-pw-1"})
        check("locked group accepts the password", s == 200)
        s, b = c.post("/api/pdus/rack-one/grouplock", {"group": "Servers", "locked": False, "password": "console-pw-1"})
        check("unlock the group", s == 200 and b["groups"][0]["locked"] is False)
        # ---- second PDU: isolation ----
        s, b = c.post("/api/pdus", {"ip": f"127.0.0.1:{fp2}", "name": "Rack One", "username": "apc", "password": "apc"})
        check("second PDU with same display name gets its own id", s == 200 and b.get("id") == "rack-one-2", str(b))
        time.sleep(1.2)
        s, b = c.get("/api/pdus/rack-one-2/status")
        check("PDU 2 has no groups/locks from PDU 1", b["groups"] == [] and b["locked"] == [])
        s, b = c.post("/api/pdus/rack-one/settings/poll", {"poll_seconds": 10})
        check("set PDU 1 poll interval", s == 200 and b["poll_seconds"] == 10)
        s, b = c.get("/api/pdus/rack-one-2/settings")
        check("PDU 2 poll interval untouched (30)", b["poll_seconds"] == 30)
        s, b = c.post("/api/pdus/rack-one/settings/poll", {"poll_seconds": 7})
        check("unsupported poll interval rejected", s == 400)
        s, b = c.post("/api/pdus/rack-one/settings/connection",
                      {"ip": f"127.0.0.1:{fp1}", "name": "Rack One", "username": "apc", "password": "bad"})
        check("connection change with bad password saves nothing", s == 400)
        s, b = c.get("/api/pdus/rack-one/status")
        check("PDU 1 still healthy after refused connection change", b["status"] is not None)
        # ---- blocked list ----
        s, b = c.post("/api/console/blocked", {"blocked_ips": "192.0.2.55"})
        check("blocked list saved", s == 200 and b["blocked_ips"] == ["192.0.2.55"])
        s, b = c.post("/api/pdus", {"ip": "192.0.2.55", "name": "Prod", "username": "x", "password": "y"})
        check("add to a blocked address refused pre-connect", s == 400 and "blocked list" in b.get("error", ""))
        # ---- 403 backoff (on PDU 2) ----
        fake_post(fp2, "/__set", {"refuse_403": True})
        fake_post(fp2, "/__expire", {})
        s, b = c.post("/api/pdus/rack-one-2/refresh")
        check("403 from the card surfaces a backing-off error", b.get("error") and "backing off" in b["error"], str(b.get("error")))
        attempts = fake_get(fp2, "/__state")["login_attempts"]
        s, b = c.post("/api/pdus/rack-one-2/refresh")
        check("during backoff no further login is attempted", fake_get(fp2, "/__state")["login_attempts"] == attempts)
        fake_post(fp2, "/__set", {"refuse_403": False})
        # ---- remove PDU 2 ----
        s, b = c.post("/api/pdus/rack-one-2/remove", {})
        check("remove PDU 2", s == 200)
        s, b = c.get("/api/pdus")
        check("overview back to one PDU", len(b["pdus"]) == 1 and b["pdus"][0]["id"] == "rack-one")
        check("removed PDU archived", os.path.isdir(os.path.join(tmp, "pdus-removed"))
              and any(d.startswith("rack-one-2-") for d in os.listdir(os.path.join(tmp, "pdus-removed"))))
        # ---- console password change ----
        s, b = c.post("/api/console/password", {"current": "bad", "new": "console-pw-2"})
        check("password change rejects wrong current", s == 403)
        s, b = c.post("/api/console/password", {"current": "console-pw-1", "new": "console-pw-2"})
        check("password change works", s == 200)
        c2 = Client(c.base)
        s, b = c2.post("/api/auth/login", {"password": "console-pw-1"})
        check("old password no longer signs in", s == 401)
        s, b = c2.post("/api/auth/login", {"password": "console-pw-2"})
        check("new password signs in", s == 200)
    finally:
        proc.terminate()
        try: proc.wait(timeout=10)
        except Exception: proc.kill()
        fake1.shutdown(); fake2.shutdown()
    print(f"\nmain suite: {COUNT - len(FAILURES)}/{COUNT} checks passed so far")

def migration_test():
    """A legacy (pre-v3) data folder must fold into the per-PDU layout."""
    fake, fp, fs = fake_nmc.serve()
    tmp = tempfile.mkdtemp(prefix="pdu-mig-")
    gen = subprocess.run([sys.executable, "-c", f'''
import os, sys, json
sys.path.insert(0, {os.path.join(ROOT, "app")!r})
os.environ["PDU_DATA_DIR"] = {tmp!r}
import server
server._key()
rec = {{"ip": "127.0.0.1:{fp}", "name": "Legacy", "username": "apc", "password": server.enc("apc")}}
json.dump(rec, open(os.path.join({tmp!r}, "device.json"), "w"))
json.dump([{{"id": "abc123", "name": "OldGroup", "outlets": [3, 4], "locked": False}}], open(os.path.join({tmp!r}, "groups.json"), "w"))
json.dump({{"locked": [3]}}, open(os.path.join({tmp!r}, "locks.json"), "w"))
json.dump({{"blocked_ips": ["192.0.2.1"], "poll_seconds": 10}}, open(os.path.join({tmp!r}, "settings.json"), "w"))
'''], capture_output=True, text=True)
    check("legacy fixture generated", gen.returncode == 0, gen.stderr[-300:])
    proc, c = start_console(tmp, free_port())
    try:
        c.post("/api/auth/setup", {"password": "console-pw-1"})
        s, b = c.get("/api/pdus")
        check("migration: legacy PDU appears", s == 200 and len(b["pdus"]) == 1 and b["pdus"][0]["name"] == "Legacy", str(b))
        time.sleep(1.2)
        s, b = c.get("/api/pdus/legacy/status")
        check("migration: group + lock + id carried over", len(b["groups"]) == 1 and b["groups"][0]["name"] == "OldGroup"
              and b["groups"][0].get("id") == "abc123" and b["locked"] == [3], str(b))
        s, b = c.get("/api/pdus/legacy/settings")
        check("migration: legacy poll interval became per-PDU", b["poll_seconds"] == 10)
        s, b = c.get("/api/console/settings")
        check("migration: blocked list became console-wide", b["blocked_ips"] == ["192.0.2.1"])
    finally:
        proc.terminate()
        try: proc.wait(timeout=10)
        except Exception: proc.kill()
        fake.shutdown()

if __name__ == "__main__":
    main()
    migration_test()
    print(f"\nTOTAL: {COUNT - len(FAILURES)}/{COUNT} checks passed")
    if FAILURES: sys.exit(1)
