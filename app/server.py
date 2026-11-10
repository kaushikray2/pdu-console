"""PDU Console v3 - a modern web console for APC Switched Rack PDUs that expose
the classic NMC web UI. Multi-PDU: one console manages any number of PDUs,
each with its own isolated data folder (connection, groups, locks, poll
interval) under data/pdus/<id>/. The landing page is an overview of all PDUs;
each PDU has its own detail page and settings page. Console-level concerns
(login password, blocked-address list) are shared. Python stdlib only."""
import base64, hashlib, hmac, html as htmlmod, http.cookiejar, json, os, re, secrets, signal, threading, time, urllib.error, urllib.parse, urllib.request, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8080"))
DATA_DIR = os.environ.get("PDU_DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
PDUS_DIR = os.path.join(DATA_DIR, "pdus")
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
GSETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")   # console-wide settings (blocked list)
AUDIT_FILE = os.path.join(DATA_DIR, "audit.log")
KEY_FILE = os.path.join(DATA_DIR, ".key")
POLL_CHOICES = [5, 10, 15, 30, 60, 120, 300]
DEFAULT_POLL = 30
SESSION_TTL = 12 * 3600
LOGIN_WINDOW, LOGIN_MAX = 600, 8
PROTECTED_OUTLETS = set()          # outlets that can never be switched (empty by default)
_STORE_LOCK = threading.RLock()

def _read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f: return json.load(f)
    except Exception: return default
def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(data, f, indent=1)
    os.replace(tmp, path)
def audit(event):
    try:
        with _STORE_LOCK:
            with open(AUDIT_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps({"ts": int(time.time()), **event}) + "\n")
    except Exception: pass
def recent_audit(limit=50, pdu_id=None):
    try:
        with open(AUDIT_FILE, encoding="utf-8") as f: lines = f.read().splitlines()
    except Exception: return []
    out = []
    for line in reversed(lines):
        try: ev = json.loads(line)
        except Exception: continue
        if pdu_id and ev.get("pdu") != pdu_id: continue
        out.append(ev)
        if len(out) >= limit: break
    return out

def _key():
    try:
        with open(KEY_FILE, "rb") as f:
            k = f.read()
            if len(k) == 32: return k
    except Exception: pass
    k = secrets.token_bytes(32)
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(KEY_FILE, "wb") as f: f.write(k)
    os.chmod(KEY_FILE, 0o600)
    return k
def _stream(key, nonce, n):
    out = b""; ctr = 0
    while len(out) < n:
        out += hmac.new(key, nonce + ctr.to_bytes(4, "big"), hashlib.sha256).digest(); ctr += 1
    return out[:n]
def enc(plain: str) -> str:
    key = _key(); nonce = secrets.token_bytes(16); data = plain.encode()
    ct = bytes(a ^ b for a, b in zip(data, _stream(key, nonce, len(data))))
    tag = hmac.new(key, b"tag" + nonce + ct, hashlib.sha256).digest()[:16]
    return base64.b64encode(nonce + tag + ct).decode()
def dec(token: str) -> str:
    raw = base64.b64decode(token); nonce, tag, ct = raw[:16], raw[16:32], raw[32:]
    key = _key()
    want = hmac.new(key, b"tag" + nonce + ct, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, want): raise ValueError("secret integrity check failed")
    return bytes(a ^ b for a, b in zip(ct, _stream(key, nonce, len(ct)))).decode()

def load_gsettings(): return _read_json(GSETTINGS_FILE, {})
def blocked_ips():
    try: return [str(x).strip() for x in load_gsettings().get("blocked_ips", []) if str(x).strip()]
    except Exception: return []
def set_blocked_ips(values):
    s = load_gsettings(); s["blocked_ips"] = values
    with _STORE_LOCK: _write_json(GSETTINGS_FILE, s)

# ---- console auth (shared across all PDUs) ----
_SESSIONS, _LOGIN_FAILS = {}, {}   # sessions; per-IP failed-login timestamps
def auth_configured(): return os.path.exists(AUTH_FILE)
def set_console_password(pw):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200000)
    _write_json(AUTH_FILE, {"algo": "pbkdf2-sha256", "iter": 200000,
                            "salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(dk).decode()})
    os.chmod(AUTH_FILE, 0o600)
def check_console_password(pw) -> bool:
    if not pw: return False
    rec = _read_json(AUTH_FILE, None)
    if not rec: return False
    try:
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(rec["salt"]), int(rec["iter"]))
        return hmac.compare_digest(base64.b64encode(dk).decode(), rec["hash"])
    except Exception: return False
def new_session():
    tok = secrets.token_urlsafe(32); _SESSIONS[tok] = time.time() + SESSION_TTL; return tok
def session_ok(tok):
    exp = _SESSIONS.get(tok or "")
    return bool(exp and exp > time.time())
def drop_session(tok): _SESSIONS.pop(tok, None)
def login_throttled(ip):
    now = time.time()
    fails = [t for t in _LOGIN_FAILS.get(ip, []) if now - t < LOGIN_WINDOW]
    _LOGIN_FAILS[ip] = fails
    return len(fails) >= LOGIN_MAX
def note_login_fail(ip):
    _LOGIN_FAILS.setdefault(ip, []).append(time.time())

# ---- APC NMC classic-UI client ----
class NmcError(Exception): pass
_ACTIVE_NMCS = set()
_BANK_RE = re.compile(r"Bank\s+B(\d)\s+Load:\s*([0-9.]+)\s*A", re.I)
_TOTAL_RE = re.compile(r"Total\s+Load:\s*([0-9.]+)\s*A", re.I)
_OUTLET_RE = re.compile(r'olnamcfg\.htm\?outlet=(\d+)"[^>]*>(.*?)</a>\s*:\s*(On|Off)', re.I | re.S)
_BANKTAG_RE = re.compile(r"\[B(\d)\]")
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
_SELECT_RE = re.compile(r"(<select\b[^>]*>)(.*?)</select>", re.I | re.S)
_FORM_RE = re.compile(r"<form\b[^>]*>", re.I)
def _tag_attr(tag, name):
    m = re.search(name + r'\s*=\s*"?([^"\s>]+)"?', tag, re.I)
    return m.group(1) if m else None
def _form_action(page, marker):
    for m in _FORM_RE.finditer(page):
        if marker in m.group(0): return _tag_attr(m.group(0), "action")
    return None

class Nmc:
    def __init__(self, ip, username, password):
        self.base = f"http://{ip}/"
        self.username, self.password = username, password
        cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    def _req(self, url, data=None):
        req = urllib.request.Request(url, data=data, headers={"User-Agent": "pdu-console"})
        with self.opener.open(req, timeout=20) as r: return r.read().decode("utf-8", "replace")
    def _get(self, path): return self._req(urllib.parse.urljoin(self.base, path.lstrip("/")))
    def login(self):
        page = self._get("/logon.htm")
        inputs = [(t, _tag_attr(t, "name"), _tag_attr(t, "type"), _tag_attr(t, "value")) for t in _INPUT_RE.findall(page)]
        users = [n for _, n, ty, _ in inputs if n and (ty or "").lower() == "text"]
        passes = [n for _, n, ty, _ in inputs if n and (ty or "").lower() == "password"]
        if not users or not passes: raise NmcError("login form not recognised")
        fields = {}
        for _, n, ty, v in inputs:
            if n and (ty or "").lower() == "hidden": fields[n] = v or ""
        fields[users[0]] = self.username
        fields[passes[0]] = self.password
        action = _form_action(page, "logon") or "/Forms/login1"
        home = self._req(urllib.parse.urljoin(self.base, action), urllib.parse.urlencode(fields).encode())
        if "logon.htm" in home and "Log On" in home: raise NmcError("login rejected")
        _ACTIVE_NMCS.add(self)
        return home
    @staticmethod
    def _clean(h): return h.replace("&nbsp;", " ").replace("&#160;", " ")
    def logout(self):
        _ACTIVE_NMCS.discard(self)
        try: self._get("/logout.htm")
        except Exception: pass
    def fetch_status(self):
        home = self.login()
        try:
            return self._read_status(home)
        finally:
            self.logout()
    def _read_status(self, home=None):
        if home is None: home = self._get("/home.htm")
        if "Total Load" not in home and "Log On" in home: raise NmcError("session expired")
        h = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", self._clean(home)))
        def load(label):
            m = re.search(label + r"[^0-9]*([0-9]+(?:\.[0-9]+)?)\s*Amps", h, re.I)
            return float(m.group(1)) if m else None
        bank1, bank2, total = load(r"Bank B1 Load:"), load(r"Bank B2 Load:"), load(r"Total Load:")
        banks = {b: v for b, v in ((1, bank1), (2, bank2)) if v is not None}
        alarms_ok = "No Alarms" in h
        ols = self._clean(self._get("/olstatus.htm"))
        outlets = []
        matches = list(re.finditer(r'olnamcfg\.htm\?outlet=(\d+)"[^>]*>([^<]+)</a>', ols))
        prev_end = 0
        for m in matches:
            seg = ols[prev_end:m.start()]; prev_end = m.end()
            n = int(m.group(1)); name = htmlmod.unescape(m.group(2)).strip()
            states = re.findall(r"\b(On|Off)\b", seg)
            btags = re.findall(r"\[B([12])\]", seg)
            outlets.append({"n": n, "name": name,
                            "state": states[-1] if states else "Unknown",
                            "bank": int(btags[-1]) if btags else (1 if n <= 12 else 2)})
        outlets.sort(key=lambda o: o["n"])
        if not outlets: raise NmcError("no outlets could be parsed from the status page")
        return {"kind": "APC Switched Rack PDU", "alarms": not alarms_ok,
                "loads": {"total": total, "banks": banks},
                "outlets": outlets, "fetched_at": int(time.time())}

ACTION_LABELS = {"on": "On Immediate", "off": "Off Immediate", "reboot": "Reboot Immediate"}
def drive_control(nmc, outlets, action):
    """One login -> control -> logout cycle driving the NMC control forms the
    proven way: checkbox values and the confirmation form are read from the
    pages the card actually serves. Several outlets (a group) are driven one
    confirmation round each inside the same session."""
    try:
        for outlet in outlets:
            pg = nmc._get("/outlctrl.htm")
            fm = re.search(r'<form[^>]*action="([^"]*)"[^>]*>', pg, re.I)
            if not fm: raise NmcError("control form not found")
            sel = re.search(r'<select[^>]*name="rPDUOutletCtrl"[^>]*>(.*?)</select>', pg, re.I | re.S)
            if not sel: raise NmcError("control action select not found")
            want = ACTION_LABELS[action]
            chosen = None
            for om in re.finditer(r'<option(?:[^>]*?value="?([^"\s>]+)"?)?[^>]*>([^<]*)</option>', sel.group(1), re.I):
                label = htmlmod.unescape(om.group(2)).strip()
                if label.lower() == want.lower(): chosen = om.group(1) if om.group(1) is not None else label
            if chosen is None: raise NmcError(f"action '{want}' not offered by NMC")
            col = (outlet - 1) // 8 + 1; row = (outlet - 1) % 8 + 2
            cb_name = f"OL_Cntrl_Col{col}_Btn"; cb_val = None
            for inp in re.findall(r"<input[^>]*>", pg, re.I):
                nm = re.search(r'name="([^"]*)"', inp, re.I); vv = re.search(r'value="([^"]*)"', inp, re.I)
                if nm and vv and nm.group(1) == cb_name and vv.group(1).startswith(f"?{row},"): cb_val = vv.group(1)
            if cb_val is None: raise NmcError(f"checkbox for outlet {outlet} not found")
            sub = re.search(r'<input[^>]*type="?submit"?[^>]*name="submit"[^>]*value="([^"]*)"', pg, re.I)
            fields = {"rPDUOutletCtrl": chosen, cb_name: cb_val, "submit": htmlmod.unescape(sub.group(1)) if sub else "Next >>"}
            conf = nmc._req(urllib.parse.urljoin(nmc.base, fm.group(1)), urllib.parse.urlencode(fields).encode())
            fm2 = re.search(r'<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>', conf, re.I | re.S)
            if not fm2: raise NmcError("confirmation form not found")
            body2 = fm2.group(2); fields2 = {}
            apply_val = None; submit_name = "submit"
            for inp in re.findall(r"<input[^>]*>", body2, re.I):
                nm = re.search(r'name="([^"]*)"', inp, re.I)
                if not nm: continue
                name = nm.group(1)
                ty = (re.search(r'type="([^"]*)"', inp, re.I) or [None, "text"])[1].lower()
                val = (re.search(r'value="([^"]*)"', inp, re.I) or [None, ""])[1]
                if ty == "hidden": fields2[name] = htmlmod.unescape(val)
                elif ty == "submit" and re.search(r"apply", val, re.I): apply_val = htmlmod.unescape(val); submit_name = name
            if apply_val is None: raise NmcError("confirmation Apply button not found")
            fields2[submit_name] = apply_val
            nmc._req(urllib.parse.urljoin(nmc.base, fm2.group(1)), urllib.parse.urlencode(fields2).encode())
    except Exception:
        raise

def drive_rename(nmc, outlet, new_name):
    """Rename one outlet via its config form, re-submitting every other field
    (power-on/off delays, reboot duration) at its current value."""
    try:
        pg = nmc._get(f"/olnamcfg.htm?outlet={outlet}")
        fm = re.search(r'<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>', pg, re.I | re.S)
        if not fm: raise NmcError("outlet config form not found")
        body = fm.group(2); fields = {}
        for inp in re.findall(r"<input[^>]*>", body, re.I):
            nm = re.search(r'name="([^"]*)"', inp, re.I)
            if not nm: continue
            name = nm.group(1)
            ty = (re.search(r'type="([^"]*)"', inp, re.I) or [None, "text"])[1].lower()
            val = (re.search(r'value="([^"]*)"', inp, re.I) or [None, ""])[1]
            if ty in ("hidden", "text"): fields[name] = htmlmod.unescape(val)
            elif ty == "radio" and "checked" in inp.lower(): fields[name] = htmlmod.unescape(val)
            elif ty == "submit": fields[name] = htmlmod.unescape(val)
        if "rPDUOLCfgName" not in fields: raise NmcError("name field not found on config form")
        fields["rPDUOLCfgName"] = new_name
        nmc._req(urllib.parse.urljoin(nmc.base, fm.group(1)), urllib.parse.urlencode(fields).encode())
    except Exception:
        raise

# ---- one managed PDU: isolated config, cache, poller ----
class Pdu:
    def __init__(self, pid):
        self.id = pid
        self.dir = os.path.join(PDUS_DIR, pid)
        self.nmc_lock = threading.Lock()          # serialise this PDU's card access
        self.cache = {"data": None, "error": None, "updated": None}
        self._stop = False
        self._nmc = None               # persistent card session (login once, reuse)
        self._backoff_until = 0        # 403 backoff: do not attempt logins before this time
        self._fail_streak = 0
        self._device = None
        rec = self.device()
        if rec:
            try:
                rec = dict(rec); rec["password"] = dec(rec["password"])
                self._device = rec
            except Exception:
                self._device = {"ip": rec.get("ip", ""), "name": rec.get("name", pid),
                                "username": rec.get("username", ""), "password": None}
                self.cache["error"] = "stored credential could not be read - re-enter it in this PDU's Settings"
    def _p(self, name): return os.path.join(self.dir, name)
    def device(self):
        return _read_json(self._p("device.json"), None)
    def save_device(self, ip, name, username, password):
        rec = {"ip": ip, "name": name, "username": username, "password": enc(password)}
        with _STORE_LOCK: _write_json(self._p("device.json"), rec)
        self._device = {"ip": ip, "name": name, "username": username, "password": password}
    def nmc(self):
        d = self._device
        return Nmc(d["ip"], d["username"], d["password"]) if d and d.get("password") else None
    # per-PDU groups / locks / settings
    def groups(self):
        out = []
        for g in _read_json(self._p("groups.json"), []):
            try:
                rec = {"name": str(g["name"]), "outlets": sorted(int(n) for n in g["outlets"]), "locked": bool(g.get("locked", False))}
                if g.get("id"): rec["id"] = g["id"]
                out.append(rec)
            except Exception: pass
        return out
    def save_groups(self, groups):
        with _STORE_LOCK: _write_json(self._p("groups.json"), groups)
    def locks(self):
        raw = _read_json(self._p("locks.json"), [])
        if isinstance(raw, dict): raw = raw.get("locked", [])   # the on-disk shape is {"locked": [...]}
        return sorted(int(n) for n in raw if str(n).isdigit())
    def save_locks(self, locks):
        with _STORE_LOCK: _write_json(self._p("locks.json"), {"locked": sorted(set(locks))})
        audit({"event": "locks_changed", "pdu": self.id, "locked": sorted(set(locks))})
    def poll_seconds(self):
        try:
            v = int(_read_json(self._p("settings.json"), {}).get("poll_seconds", DEFAULT_POLL))
            return v if v in POLL_CHOICES else DEFAULT_POLL
        except Exception: return DEFAULT_POLL
    def set_poll_seconds(self, v):
        s = _read_json(self._p("settings.json"), {}); s["poll_seconds"] = v
        with _STORE_LOCK: _write_json(self._p("settings.json"), s)
    # card operations (all serialised per PDU)
    def _session(self):
        if self._nmc is None:
            nmc = self.nmc()
            if nmc is None: raise NmcError("device credential not configured")
            nmc.login()
            self._nmc = nmc
        return self._nmc
    def _drop_session(self):
        nmc, self._nmc = self._nmc, None
        if nmc is not None:
            try: nmc.logout()
            except Exception: pass
    def _note_failure(self, e):
        msg = str(e)
        if "403" in msg:
            self._fail_streak += 1
            delay = min(300, 60 * (2 ** min(self._fail_streak - 1, 3)))
            self._backoff_until = time.time() + delay
            msg = ("the PDU management card refused the login (403) - it allows only one web "
                   "session at a time and rate-limits logins; the console is backing off and "
                   "will retry on its own")
        self.cache["error"] = msg
    def poll_once(self):
        if time.time() < self._backoff_until: return False
        with self.nmc_lock:
            try:
                data = self._session()._read_status()
            except Exception:
                self._drop_session()
                try:
                    data = self._session()._read_status()
                except Exception as e:
                    self._note_failure(e)
                    return False
            self._fail_streak = 0
            self.cache["data"] = data
            self.cache["error"] = None
            self.cache["updated"] = int(time.time())
            return True
    def poller(self):
        while not self._stop:
            self.poll_once()
            for _ in range(self.poll_seconds() * 2):
                if self._stop: return
                time.sleep(0.5)
    def outlet_names(self):
        data = self.cache["data"]
        return {o["n"]: o["name"] for o in data["outlets"]} if data else {}
    def check_action(self, targets, password):
        """None if the action may proceed, else an error string."""
        for t in targets:
            if t in PROTECTED_OUTLETS: return f"outlet {t} is protected and can never be switched"
        locked = set(self.locks())
        groups = {g["name"]: g for g in self.groups()}
        hit = [t for t in targets if t in locked]
        for g in groups.values():
            if g["locked"] and any(t in g["outlets"] for t in targets): hit.append("group:" + g["name"])
        if hit:
            if not password: return "password_required"
            if not check_console_password(password): return "wrong console password"
        return None
    def do_control(self, outlets, action, password, source):
        err = self.check_action(outlets, password)
        if err:
            audit({"event": "control_refused", "pdu": self.id, "action": action, "outlets": outlets, "reason": err})
            return False, err
        with self.nmc_lock:
            try:
                nmc = self._session()
                drive_control(nmc, outlets, action)
                data = nmc._read_status()
            except Exception as e:
                self._drop_session()
                return False, f"card error: {e}"
            self.cache["data"] = data; self.cache["error"] = None; self.cache["updated"] = int(time.time())
        audit({"event": "control", "pdu": self.id, "action": action, "outlets": outlets, "via": source})
        expect = "On" if action in ("on", "reboot") else "Off"
        names = {o["n"]: o["name"] for o in data["outlets"]}
        states = {o["n"]: o["state"] for o in data["outlets"]}
        wrong = [n for n in outlets if states.get(n) not in (expect, None)]
        if wrong:
            return False, f"command sent but outlet(s) {', '.join('#' + str(n) for n in wrong)} do not read {expect}"
        return True, ", ".join(f"#{n} {names.get(n, '?')} is now {states.get(n, '?')}" for n in outlets)
    def do_rename(self, outlet, new_name):
        with self.nmc_lock:
            try:
                nmc = self._session()
                drive_rename(nmc, outlet, new_name)
                data = nmc._read_status()
            except Exception as e:
                self._drop_session()
                return False, f"card error: {e}"
            self.cache["data"] = data; self.cache["error"] = None; self.cache["updated"] = int(time.time())
        audit({"event": "rename", "pdu": self.id, "outlet": outlet, "name": new_name})
        names = {o["n"]: o["name"] for o in data["outlets"]}
        if names.get(outlet) != new_name:
            return False, f"the card still shows '{names.get(outlet)}' for outlet {outlet} - the rename did not take"
        return True, f"outlet {outlet} renamed to '{new_name}'"

# ---- registry, migration, add/remove ----
PDUS = {}
PDUS_LOCK = threading.Lock()
def slugify(name, taken):
    base = re.sub(r"[^a-z0-9]+", "-", (name or "pdu").lower()).strip("-") or "pdu"
    cand, i = base, 2
    while cand in taken: cand = f"{base}-{i}"; i += 1
    return cand
def migrate_legacy():
    """One-time: fold the pre-v3 single-PDU files (data/device.json etc.) into
    data/pdus/<id>/ and carry the blocked list into console settings."""
    legacy = os.path.join(DATA_DIR, "device.json")
    os.makedirs(PDUS_DIR, exist_ok=True)
    if os.path.exists(legacy) and not os.listdir(PDUS_DIR):
        rec = _read_json(legacy, {})
        pid = slugify(rec.get("name", "pdu"), set())
        dest = os.path.join(PDUS_DIR, pid)
        os.makedirs(dest, exist_ok=True)
        for fname in ("device.json", "groups.json", "locks.json"):
            srcp = os.path.join(DATA_DIR, fname)
            if os.path.exists(srcp): os.replace(srcp, os.path.join(dest, fname))
        old = _read_json(GSETTINGS_FILE, {})  # legacy settings.json held poll + blocked
        blocked = old.get("blocked_ips")
        if blocked is not None:
            s = load_gsettings(); s["blocked_ips"] = blocked; _write_json(GSETTINGS_FILE, s)
        if old.get("poll_seconds"):
            _write_json(os.path.join(dest, "settings.json"), {"poll_seconds": old["poll_seconds"]})
            s = load_gsettings(); s.pop("poll_seconds", None); _write_json(GSETTINGS_FILE, s)
        audit({"event": "migrated_legacy_layout", "pdu": pid})
def load_registry():
    migrate_legacy()
    if not os.path.isdir(PDUS_DIR): return
    for pid in sorted(os.listdir(PDUS_DIR)):
        if os.path.isdir(os.path.join(PDUS_DIR, pid)):
            pdu = Pdu(pid)
            if pdu.device(): PDUS[pid] = pdu
def start_pollers():
    for pdu in PDUS.values():
        threading.Thread(target=pdu.poller, daemon=True).start()
ADDR_RE = r"[A-Za-z0-9.\-]{1,63}(:\d{1,5})?"
def is_blocked(addr):
    b = blocked_ips()
    return addr in b or addr.split(":")[0] in b
def verify_connection(ip, username, password):
    """Full status fetch against candidate settings; raises on failure."""
    return Nmc(ip, username, password).fetch_status()
def add_pdu(ip, name, username, password):
    if is_blocked(ip): return None, f"{ip} is on this console's blocked list - refusing to connect to it"
    if any(p._device and p._device["ip"] == ip for p in PDUS.values()):
        return None, f"{ip} is already added to this console"
    try: verify_connection(ip, username, password)
    except Exception as e: return None, f"could not connect to {ip} with those credentials: {e}"
    pid = slugify(name, set(PDUS))
    pdu = Pdu.__new__(Pdu)
    pdu.id, pdu.dir = pid, os.path.join(PDUS_DIR, pid)
    pdu.nmc_lock, pdu.cache, pdu._stop, pdu._device = threading.Lock(), {"data": None, "error": None, "updated": None}, False, None
    pdu._nmc = None; pdu._backoff_until = 0; pdu._fail_streak = 0
    os.makedirs(pdu.dir, exist_ok=True)
    pdu.save_device(ip, name, username, password)
    with PDUS_LOCK: PDUS[pid] = pdu
    threading.Thread(target=pdu.poller, daemon=True).start()
    audit({"event": "pdu_added", "pdu": pid, "ip": ip, "name": name})
    return pid, "connected and added"
def remove_pdu(pid):
    pdu = PDUS.pop(pid, None)
    if not pdu: return False
    pdu._stop = True
    trash = os.path.join(DATA_DIR, "pdus-removed")
    os.makedirs(trash, exist_ok=True)
    dest = os.path.join(trash, f"{pid}-{int(time.time())}")
    try: os.replace(pdu.dir, dest)
    except Exception: pass
    audit({"event": "pdu_removed", "pdu": pid})
    return True
def validate_group(pdu, name, outlets, exclude=None):
    name = (name or "").strip()
    if not name: return None, "group needs a name"
    if len(name) > 40: return None, "group name too long (max 40)"
    try: wants = sorted({int(n) for n in outlets})
    except Exception: return None, "outlets must be numbers"
    if len(wants) < 2: return None, "a group needs at least 2 outlets"
    names = pdu.outlet_names()
    if names and any(n not in names for n in wants): return None, "one of those outlets does not exist on this PDU"
    if any(n in PROTECTED_OUTLETS for n in wants): return None, "protected outlets can never be grouped or switched"
    for g in pdu.groups():
        if g["name"] == exclude: continue
        if g["name"].lower() == name.lower(): return None, f"a group named '{g['name']}' already exists"
        clash = [n for n in wants if n in g["outlets"]]
        if clash: return None, f"outlet(s) {', '.join('#' + str(n) for n in clash)} already belong to group '{g['name']}'"
    return {"name": name, "outlets": wants, "locked": False}, None
def status_body(pdu):
    d = pdu._device or {}
    return {"device": {"ip": d.get("ip", ""), "name": d.get("name", pdu.id)},
            "status": pdu.cache["data"], "error": pdu.cache["error"], "updated": pdu.cache["updated"],
            "groups": pdu.groups(), "locked": pdu.locks(), "protected": sorted(PROTECTED_OUTLETS)}
def overview_entry(pdu):
    d = pdu._device or {}
    s = pdu.cache["data"]
    return {"id": pdu.id, "name": d.get("name", pdu.id), "ip": d.get("ip", ""),
            "ok": bool(s), "error": pdu.cache["error"], "updated": pdu.cache["updated"],
            "alarms": s["alarms"] if s else None,
            "total_load": s["loads"]["total"] if s else None,
            "bank_loads": s["loads"]["banks"] if s else {},
            "outlets_on": sum(1 for o in s["outlets"] if o["state"] == "On") if s else None,
            "outlets_total": len(s["outlets"]) if s else None,
            "groups": len(pdu.groups()), "locked": len(pdu.locks())}

# ---- HTTP layer ----
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def _send(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, (bytes, str)) else json.dumps(obj)
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
    def _cookie(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            if part.strip().startswith("pdu3sess="): return part.strip()[9:]
        return ""
    def _set_cookie(self, tok):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        body = b'{"ok": true}'
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", f"pdu3sess={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}")
        self.send_header("Cache-Control", "no-store")
        self.end_headers(); self.wfile.write(body)
    def _json_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception: return {}
    def _authed(self): return session_ok(self._cookie())
    def _require_auth(self):
        if self._authed(): return True
        self._send(401, {"error": "not signed in"}); return False
    def _pdu(self, pid):
        pdu = PDUS.get(pid)
        if not pdu: self._send(404, {"error": "unknown PDU"})
        return pdu
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/health": return self._send(200, {"ok": True})
        if path == "/api/auth/state":
            return self._send(200, {"configured": auth_configured(), "authed": self._authed(),
                                    "pdus": len(PDUS)})
        if path.startswith("/api/"):
            if not self._require_auth(): return
            if path == "/api/pdus":
                return self._send(200, {"pdus": [overview_entry(p) for p in PDUS.values()]})
            m = re.fullmatch(r"/api/pdus/([^/]+)/status", path)
            if m:
                pdu = self._pdu(m.group(1))
                if pdu: return self._send(200, status_body(pdu))
                return
            m = re.fullmatch(r"/api/pdus/([^/]+)/settings", path)
            if m:
                pdu = self._pdu(m.group(1))
                if not pdu: return
                d = pdu._device or {}
                return self._send(200, {"device": {"ip": d.get("ip", ""), "name": d.get("name", pdu.id),
                                                  "username": d.get("username", "")},
                                        "poll_seconds": pdu.poll_seconds(), "poll_choices": POLL_CHOICES,
                                        "recent": recent_audit(50, pdu.id)})
            if path == "/api/console/settings":
                return self._send(200, {"blocked_ips": blocked_ips(), "recent": recent_audit(50)})
            return self._send(404, {"error": "not found"})
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        full = os.path.normpath(os.path.join(STATIC_DIR, rel))
        if not full.startswith(STATIC_DIR) or not os.path.isfile(full):
            return self._send(404, "not found", "text/plain")
        ctype = {"html": "text/html", "css": "text/css", "js": "text/javascript"}.get(rel.rsplit(".", 1)[-1], "text/plain")
        with open(full, "rb") as f: return self._send(200, f.read(), ctype)
    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/auth/setup":
            if auth_configured(): return self._send(400, {"error": "password already set"})
            pw = (self._json_body().get("password") or "")
            if len(pw) < 8: return self._send(400, {"error": "use at least 8 characters"})
            set_console_password(pw); audit({"event": "console_password_created"})
            return self._set_cookie(new_session())
        if path == "/api/auth/login":
            if login_throttled(self.client_address[0]): return self._send(429, {"error": "too many failed attempts - wait a few minutes"})
            pw = (self._json_body().get("password") or "")
            if not check_console_password(pw):
                note_login_fail(self.client_address[0]); audit({"event": "login_failed"})
                return self._send(401, {"error": "wrong password"})
            audit({"event": "login"})
            return self._set_cookie(new_session())
        if path == "/api/auth/logout":
            drop_session(self._cookie()); audit({"event": "logout"})
            return self._send(200, {"ok": True})
        if not path.startswith("/api/"): return self._send(404, {"error": "not found"})
        if not self._require_auth(): return
        return self._post_api(path)
    def _post_api(self, path):
        body = self._json_body()
        if path == "/api/pdus":
            ip = (body.get("ip") or "").strip()
            name = (body.get("name") or "").strip()
            user = (body.get("username") or "").strip()
            pw = body.get("password") or ""
            if not re.fullmatch(ADDR_RE, ip): return self._send(400, {"error": "invalid IP address or hostname"})
            if not name: return self._send(400, {"error": "give the PDU a display name"})
            if not user or not pw: return self._send(400, {"error": "the PDU username and password are required"})
            pid, msg = add_pdu(ip, name, user, pw)
            if not pid: return self._send(400, {"error": msg})
            return self._send(200, {"ok": True, "id": pid, "message": msg})
        if path == "/api/console/blocked":
            raw = body.get("blocked_ips")
            if isinstance(raw, str): raw = [p for p in re.split(r"[,\s]+", raw) if p]
            values = []
            for v in (raw or []):
                v = str(v).strip()
                if not re.fullmatch(r"[A-Za-z0-9.\-]{1,63}", v):
                    return self._send(400, {"error": f"invalid address in blocked list: {v}"})
                if v not in values: values.append(v)
            set_blocked_ips(values)
            audit({"event": "blocked_list_changed", "count": len(values)})
            return self._send(200, {"ok": True, "blocked_ips": blocked_ips()})
        if path == "/api/console/password":
            if not check_console_password(body.get("current") or ""):
                return self._send(403, {"error": "current password is wrong"})
            new = body.get("new") or ""
            if len(new) < 8: return self._send(400, {"error": "use at least 8 characters"})
            set_console_password(new)
            me = self._cookie()
            for tok in list(_SESSIONS):
                if tok != me: _SESSIONS.pop(tok, None)
            audit({"event": "console_password_changed"})
            return self._send(200, {"ok": True})
        m = re.fullmatch(r"/api/pdus/([^/]+)/(refresh|control|group-control|groups|groups/delete|lock|grouplock|rename|remove|settings/connection|settings/poll)", path)
        if not m: return self._send(404, {"error": "not found"})
        pdu = self._pdu(m.group(1))
        if not pdu: return
        route = m.group(2)
        if route == "refresh":
            pdu.poll_once()
            return self._send(200, status_body(pdu))
        if route == "remove":
            remove_pdu(pdu.id)
            return self._send(200, {"ok": True})
        if route == "settings/poll":
            try: v = int(body.get("poll_seconds"))
            except Exception: return self._send(400, {"error": "invalid interval"})
            if v not in POLL_CHOICES: return self._send(400, {"error": "unsupported interval"})
            pdu.set_poll_seconds(v)
            audit({"event": "poll_interval_changed", "pdu": pdu.id, "seconds": v})
            return self._send(200, {"ok": True, "poll_seconds": pdu.poll_seconds()})
        if route == "settings/connection":
            ip = (body.get("ip") or "").strip()
            name = (body.get("name") or "").strip()
            user = (body.get("username") or "").strip()
            pw = body.get("password") or (pdu._device or {}).get("password", "")
            if not re.fullmatch(ADDR_RE, ip): return self._send(400, {"error": "invalid IP address or hostname"})
            if not name: return self._send(400, {"error": "display name cannot be empty"})
            if not user: return self._send(400, {"error": "username cannot be empty"})
            if not pw: return self._send(400, {"error": "password is required"})
            if is_blocked(ip): return self._send(400, {"error": f"{ip} is on this console's blocked list - refusing to connect to it"})
            if any(o is not pdu and o._device and o._device["ip"] == ip for o in PDUS.values()):
                return self._send(400, {"error": f"{ip} already belongs to another PDU in this console"})
            try: verify_connection(ip, user, pw)
            except Exception as e: return self._send(400, {"error": f"could not connect with those settings (nothing was changed): {e}"})
            pdu.save_device(ip, name, user, pw if body.get("password") else (pdu._device or {}).get("password", pw))
            audit({"event": "connection_settings_changed", "pdu": pdu.id, "ip": ip, "name": name, "username": user})
            pdu.poll_once()
            return self._send(200, {"ok": True, "message": f"connected to {ip} and saved"})
        if route in ("control", "group-control"):
            action = body.get("action")
            if action not in ACTION_LABELS: return self._send(400, {"error": "invalid action"})
            if route == "control":
                outlet = body.get("outlet")
                if outlet in PROTECTED_OUTLETS:
                    return self._send(403, {"error": f"outlet {outlet} is protected and can never be switched"})
                targets = [outlet]
            else:
                g = next((g for g in pdu.groups() if g["name"] == body.get("group")), None)
                if not g: return self._send(404, {"error": "group not found"})
                targets = g["outlets"]
            if not body.get("confirm"):
                return self._send(400, {"error": "confirmation required - no command was sent"})
            ok, msg = pdu.do_control(targets, action, body.get("password"), "group" if route == "group-control" else "outlet")
            if msg == "password_required": return self._send(428, {"error": "password_required"})
            if not ok: return self._send(400, {"error": msg})
            return self._send(200, {"ok": True, "message": msg})
        if route == "groups":
            existing = next((g for g in pdu.groups() if g["name"] == body.get("original")), None) if body.get("original") else None
            rec, err = validate_group(pdu, body.get("name"), body.get("outlets"), exclude=body.get("original"))
            if err: return self._send(400, {"error": err})
            rec["locked"] = existing["locked"] if existing else False
            if existing and existing.get("id"): rec["id"] = existing["id"]
            groups = [g for g in pdu.groups() if g["name"] != body.get("original")]
            groups.append(rec); groups.sort(key=lambda g: g["name"].lower())
            pdu.save_groups(groups)
            audit({"event": "group_saved", "pdu": pdu.id, "group": rec["name"], "outlets": rec["outlets"]})
            return self._send(200, {"ok": True, "groups": pdu.groups()})
        if route == "groups/delete":
            name = body.get("name")
            groups = [g for g in pdu.groups() if g["name"] != name]
            if len(groups) == len(pdu.groups()): return self._send(404, {"error": "group not found"})
            pdu.save_groups(groups)
            audit({"event": "group_deleted", "pdu": pdu.id, "group": name})
            return self._send(200, {"ok": True, "groups": pdu.groups()})
        if route == "lock":
            outlet = body.get("outlet")
            if outlet in PROTECTED_OUTLETS:
                return self._send(403, {"error": f"outlet {outlet} is permanently protected; its lock state cannot change"})
            names = pdu.outlet_names()
            if names and outlet not in names: return self._send(404, {"error": "unknown outlet"})
            locked = pdu.locks()
            if body.get("locked"):
                if outlet not in locked: locked.append(outlet)
            else:
                if not check_console_password(body.get("password") or ""):
                    return self._send(403, {"error": "unlocking needs the correct console password"})
                locked = [n for n in locked if n != outlet]
            pdu.save_locks(locked)
            return self._send(200, {"ok": True, "locked": pdu.locks()})
        if route == "grouplock":
            g = next((g for g in pdu.groups() if g["name"] == body.get("group")), None)
            if not g: return self._send(404, {"error": "group not found"})
            if not body.get("locked") and not check_console_password(body.get("password") or ""):
                return self._send(403, {"error": "unlocking needs the correct console password"})
            groups = pdu.groups()
            for gg in groups:
                if gg["name"] == g["name"]: gg["locked"] = bool(body.get("locked"))
            pdu.save_groups(groups)
            audit({"event": "group_lock_changed", "pdu": pdu.id, "group": g["name"], "locked": bool(body.get("locked"))})
            return self._send(200, {"ok": True, "groups": pdu.groups()})
        if route == "rename":
            outlet, new_name = body.get("outlet"), (body.get("name") or "").strip()
            if not new_name: return self._send(400, {"error": "name cannot be empty"})
            if len(new_name) > 23: return self._send(400, {"error": "the PDU caps outlet names at 23 characters"})
            if any(c in new_name for c in '<>&"') or any(ord(c) < 32 for c in new_name):
                return self._send(400, {"error": "name contains characters the PDU page cannot use"})
            names = pdu.outlet_names()
            if names and outlet not in names: return self._send(404, {"error": "unknown outlet"})
            ok, msg = pdu.do_rename(outlet, new_name)
            if not ok: return self._send(400, {"error": msg})
            return self._send(200, {"ok": True, "message": msg})
        return self._send(404, {"error": "not found"})

def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    _key()
    load_registry()
    start_pollers()
    audit({"event": "startup", "pdus": sorted(PDUS), "protected": sorted(PROTECTED_OUTLETS)})
    def _shutdown(signum, frame):
        # Never leave a web session dangling on a card when the container stops:
        # a stranded session makes the card refuse all new logins (HTTP 403).
        for nmc in list(_ACTIVE_NMCS):
            try: nmc.logout()
            except Exception: pass
        os._exit(0)
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
if __name__ == "__main__":
    main()
