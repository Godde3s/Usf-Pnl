import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import base64
import socket
from datetime import datetime, timezone, timedelta
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Usf-Pnl")

# ── App Setup ──────────────────────────────────────────────────────────────────
app = FastAPI(title="Usf-Pnl", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CONFIG = {
    "port": int(os.environ.get("PORT", 7860)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
}

# ── State ──────────────────────────────────────────────────────────────────────
connections: dict = {}
connections_lock = asyncio.Lock()
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
daily_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

SESSION_COOKIE = "usf_session"
SESSION_TTL = 60 * 60 * 24 * 7
UNLIMITED_QUOTA_BYTES = 53687091200000
DEFAULT_PORT = 443
RELAY_BUF = 256 * 1024

DB_FILE = "panel_db.json"

# ── Database Storage ───────────────────────────────────────────────────────────
def save_db():
    data = {
        "auth_hash": AUTH["password_hash"],
        "links": LINKS,
    }
    try:
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error saving DB: {e}")

def load_db():
    global LINKS
    if not os.path.exists(DB_FILE):
        return
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        AUTH["password_hash"] = data.get("auth_hash", AUTH["password_hash"])
        LINKS.clear()
        LINKS.update(data.get("links", {}))
    except Exception as e:
        logger.error(f"Error loading DB: {e}")

# ── Auth ───────────────────────────────────────────────────────────────────────
def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("PANEL_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

# ── Keep-alive ─────────────────────────────────────────────────────────────────
async def keep_alive():
    while True:
        await asyncio.sleep(300)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
        except Exception:
            pass

# ── Startup / Shutdown ─────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global http_client
    load_db()
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    asyncio.create_task(keep_alive())
    await ensure_default_link()

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()

# ── Helpers ────────────────────────────────────────────────────────────────────
def get_domain() -> str:
    return (
        os.environ.get("SPACE_HOST", "localhost")
        .replace("https://", "").replace("http://", "")
        .split("/")[0]
    )

def generate_vless_link(uuid: str, remark: str = "Usf", address: str = None, port: int = None) -> str:
    domain = get_domain()
    addr = address if address else domain
    use_port = port if port else DEFAULT_PORT
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:{use_port}?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB":
        return int(value * 1024 * 1024 * 1024)
    if unit == "MB":
        return int(value * 1024 * 1024)
    if unit == "KB":
        return int(value * 1024)
    return int(value)

def parse_expires_at(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        normalised = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalised)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def seconds_until_expiry(expires_at_str: str | None) -> int | None:
    exp = parse_expires_at(expires_at_str)
    if exp is None:
        return None
    remaining = (exp - datetime.now(timezone.utc)).total_seconds()
    return max(0, int(remaining))

def _fmt_bytes(b: int) -> str:
    if b >= 1_073_741_824:
        return f"{b / 1_073_741_824:.1f}GB"
    if b >= 1_048_576:
        return f"{b / 1_048_576:.1f}MB"
    return f"{b / 1024:.1f}KB"

def fmt_exp_py(ea: str | None) -> str:
    if not ea:
        return "\u221e"
    exp = parse_expires_at(ea)
    if not exp:
        return "\u221e"
    diff = exp - datetime.now(timezone.utc)
    seconds = diff.total_seconds()
    if seconds <= 0:
        return "Expired"
    days = int(seconds // 86400)
    if days > 0:
        return f"{days}d"
    hours = int(seconds // 3600)
    if hours > 0:
        return f"{hours}h"
    minutes = int(seconds // 60)
    return f"{minutes}m"

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            LINKS["Default"] = {
                "label": "Default",
                "limit_bytes": 0,
                "used_bytes": 0,
                "max_connections": 0,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "active": True,
                "expires_at": None,
            }

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

async def count_connections_for_link(uid: str) -> int:
    async with connections_lock:
        return sum(1 for info in connections.values() if info.get("uuid") == uid)

async def close_connections_for_link(uid: str):
    async with connections_lock:
        to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        async with connections_lock:
            connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    async with connections_lock:
        link_ip_map.pop(uid, None)

async def get_internal_stats():
    async with connections_lock:
        conn_count = len(connections)
    cpu_p = 0.0
    mem_p = 0.0
    if HAS_PSUTIL:
        try:
            cpu_p = psutil.cpu_percent(interval=0.1)
            mem_p = psutil.virtual_memory().percent
        except Exception:
            pass
    return {
        "active_connections": conn_count,
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": cpu_p,
        "memory_percent": mem_p,
        "hourly_traffic": dict(hourly_traffic),
        "daily_traffic": dict(daily_traffic),
    }

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return Response(content="OK", media_type="text/plain")

@app.get("/health")
async def health():
    async with connections_lock:
        conn_count = len(connections)
    return {"status": "ok", "connections": conn_count, "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/change-password")
async def api_change_password(request: Request, token: str = Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current") or "")
    new_pw = str(body.get("new") or "")
    if not current or not new_pw:
        raise HTTPException(status_code=400, detail="Both fields required")
    if len(new_pw) < 4:
        raise HTTPException(status_code=400, detail="Password too short (min 4)")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Current password is wrong")
    AUTH["password_hash"] = hash_password(new_pw)
    save_db()
    return {"ok": True}

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/dashboard")
async def api_dashboard(_=Depends(require_auth)):
    return await get_internal_stats()

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        items = list(LINKS.items())
    for uid, data in items:
        result.append({
            "uuid": uid,
            "label": data["label"],
            "limit_bytes": data["limit_bytes"],
            "used_bytes": data["used_bytes"],
            "max_connections": data.get("max_connections", 0),
            "active": data["active"],
            "created_at": data["created_at"],
            "expires_at": data.get("expires_at"),
            "current_connections": await count_connections_for_link(uid),
            "vless_link": generate_vless_link(uid, remark=f"Usf-{data['label']}", port=DEFAULT_PORT),
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Inbound name must contain only English letters, numbers, and characters: - _ . space")
    if not label:
        raise HTTPException(status_code=400, detail="Inbound name is required")
    async with LINKS_LOCK:
        if label in LINKS:
            raise HTTPException(status_code=400, detail="An inbound with this name already exists")
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = int(body.get("max_connections") or 0)
    if max_conn < 0:
        max_conn = 0
    days_valid = body.get("days_valid")
    expires_at: str | None = None
    if days_valid is not None:
        try:
            days_valid = int(days_valid)
            if days_valid > 0:
                expires_at = (datetime.now(timezone.utc) + timedelta(days=days_valid)).isoformat()
        except (ValueError, TypeError):
            pass
    uid = label
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label,
            "limit_bytes": limit_bytes,
            "used_bytes": 0,
            "max_connections": max_conn,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "active": True,
            "expires_at": expires_at,
        }
    save_db()
    return {
        "uuid": uid,
        "label": label,
        "limit_bytes": limit_bytes,
        "used_bytes": 0,
        "max_connections": max_conn,
        "active": True,
        "created_at": LINKS[uid]["created_at"],
        "expires_at": expires_at,
        "vless_link": generate_vless_link(uid, remark=f"Usf-{label}", port=DEFAULT_PORT),
    }

@app.put("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "max_connections" in body:
            mc = int(body.get("max_connections") or 0)
            LINKS[uid]["max_connections"] = mc if mc >= 0 else 0
        if "days_valid" in body:
            try:
                dv = int(body["days_valid"])
                if dv > 0:
                    LINKS[uid]["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=dv)).isoformat()
                else:
                    LINKS[uid]["expires_at"] = None
            except (ValueError, TypeError):
                pass
    save_db()
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    save_db()
    await close_connections_for_link(uid)
    return {"ok": True}

@app.post("/api/links/{uid}/reset")
async def reset_usage(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        LINKS[uid]["used_bytes"] = 0
    save_db()
    return {"ok": True}

@app.post("/api/links/{uid}/toggle")
async def toggle_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        LINKS[uid]["active"] = not LINKS[uid]["active"]
        new_state = LINKS[uid]["active"]
    save_db()
    if not new_state:
        await close_connections_for_link(uid)
    return {"ok": True, "active": new_state}

@app.get("/api/links/{uid}/sub")
async def get_sub_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
    sub_url = f"https://{get_domain()}/sub/{uid}"
    return {"sub_url": sub_url}

# ── Subscription Page Generator ────────────────────────────────────────────────

def generate_sub_landing_page(link: dict, uid: str) -> str:
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    expires_at_str = link.get("expires_at")

    usage_str = "{0} / Unlimited".format(_fmt_bytes(used)) if limit == 0 else "{0} / {1}".format(_fmt_bytes(used), _fmt_bytes(limit))
    pct = round((used / limit) * 100, 1) if limit > 0 else 0
    rem = limit - used if limit > 0 else -1
    rem_str = _fmt_bytes(rem) if rem >= 0 else "Unlimited"

    secs_left = seconds_until_expiry(expires_at_str)
    if secs_left is None:
        expiry_str = "Unlimited"
    elif secs_left == 0:
        expiry_str = "Expired"
    else:
        days = secs_left // 86400
        hours = (secs_left % 86400) // 3600
        mins = (secs_left % 3600) // 60
        if days > 0:
            expiry_str = "{0}d {1}h remaining".format(days, hours)
        elif hours > 0:
            expiry_str = "{0}h {1}m remaining".format(hours, mins)
        else:
            expiry_str = "{0}m remaining".format(mins)

    is_active = link["active"]
    if is_active and expires_at_str:
        exp_dt = parse_expires_at(expires_at_str)
        if exp_dt and exp_dt < datetime.now(timezone.utc):
            is_active = False

    config = generate_vless_link(uid, remark="Usf-{0}".format(link['label']), port=DEFAULT_PORT)
    config_json = json.dumps(config)
    status_badge_class = 'badge-on' if is_active else 'badge-off'
    status_text = 'Active' if is_active else 'Inactive'

    html = """<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Usf-Pnl | Connection Status</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #0b1120;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            color: #e2e8f0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .bg-layer {
            position: fixed; inset: 0; z-index: 0; pointer-events: none;
            background: radial-gradient(ellipse 80% 60% at 50% 0%, rgba(6,182,212,0.08), transparent 60%),
                        radial-gradient(ellipse 60% 40% at 80% 100%, rgba(14,165,233,0.06), transparent 50%);
        }
        .card {
            width: 100%; max-width: 440px;
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid rgba(6,182,212,0.12);
            border-radius: 16px; padding: 28px 24px;
            position: relative; z-index: 1;
            backdrop-filter: blur(20px);
        }
        .header {
            text-align: center; margin-bottom: 24px;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(148,163,184,0.1);
        }
        .header h1 { font-size: 20px; font-weight: 800; color: #22d3ee; letter-spacing: 1px; }
        .header p { font-size: 12px; color: #64748b; margin-top: 4px; }
        .info-row {
            display: flex; justify-content: space-between;
            align-items: center; padding: 10px 0;
        }
        .info-label { font-size: 13px; color: #94a3b8; }
        .info-value { font-size: 14px; font-weight: 600; color: #e2e8f0; }
        .badge { padding: 3px 12px; border-radius: 20px; font-size: 11px; font-weight: 700; }
        .badge-on { background: rgba(52,211,153,0.12); color: #34d399; border: 1px solid rgba(52,211,153,0.25); }
        .badge-off { background: rgba(251,113,133,0.12); color: #fb7185; border: 1px solid rgba(251,113,133,0.25); }
        .progress-outer {
            height: 8px; background: rgba(148,163,184,0.08);
            border-radius: 4px; overflow: hidden; margin: 8px 0 4px;
        }
        .progress-inner {
            height: 100%; border-radius: 4px;
            background: linear-gradient(90deg, #06b6d4, #22d3ee);
            transition: width 0.6s ease;
        }
        .section-title {
            font-size: 11px; font-weight: 700; color: #475569;
            text-transform: uppercase; letter-spacing: 1.5px;
            margin: 20px 0 12px;
        }
        .node-card {
            display: flex; align-items: center; justify-content: space-between;
            background: rgba(30, 41, 59, 0.7);
            border: 1px solid rgba(148,163,184,0.08);
            border-radius: 10px; padding: 12px 14px; margin-bottom: 8px;
        }
        .node-name { font-size: 13px; font-weight: 600; color: #cbd5e1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 55%; }
        .btn {
            font-family: inherit; font-size: 12px; font-weight: 600;
            border-radius: 8px; padding: 6px 14px; cursor: pointer;
            border: none; transition: all 0.2s;
        }
        .btn-primary { background: #06b6d4; color: #0b1120; }
        .btn-primary:hover { background: #22d3ee; }
        .btn-outline { background: transparent; color: #94a3b8; border: 1px solid rgba(148,163,184,0.2); }
        .btn-outline:hover { border-color: #06b6d4; color: #22d3ee; }
        .overlay {
            position: fixed; inset: 0; background: rgba(0,0,0,0.75);
            z-index: 200; display: none; align-items: center;
            justify-content: center; backdrop-filter: blur(6px);
        }
        .overlay.show { display: flex; }
        .overlay-box {
            background: #0f172a; border: 1px solid rgba(6,182,212,0.15);
            border-radius: 16px; padding: 24px; width: 90%;
            max-width: 300px; text-align: center; position: relative;
        }
        .overlay-box img {
            max-width: 100%; border-radius: 8px;
            border: 2px solid rgba(6,182,212,0.1); margin-top: 14px;
        }
        .overlay-close {
            position: absolute; top: 10px; right: 10px; font-size: 18px;
            cursor: pointer; color: #64748b; background: none; border: none;
        }
        .toast {
            position: fixed; bottom: 24px; left: 50%;
            transform: translateX(-50%) translateY(20px);
            background: #0f172a; color: #22d3ee;
            border: 1px solid rgba(6,182,212,0.2);
            border-radius: 10px; padding: 10px 20px;
            font-size: 13px; font-weight: 600; opacity: 0;
            transition: all 0.3s; z-index: 999;
        }
        .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
        @media (max-width: 480px) {
            .card { padding: 20px 16px; }
            .node-card { padding: 10px 12px; }
            .node-name { max-width: 45%; }
        }
    </style>
</head>
<body>
    <div class="bg-layer"></div>
    <div class="toast" id="toast">Copied!</div>
    <div class="card">
        <div class="header">
            <h1>USF-PNL</h1>
            <p>Connection Status</p>
        </div>
        <div class="info-row">
            <span class="info-label">Username</span>
            <div style="display:flex;align-items:center;gap:8px">
                <span class="info-value">""" + link['label'] + """</span>
                <span class="badge """ + status_badge_class + """">
                    """ + status_text + """
                </span>
            </div>
        </div>
        <div class="progress-outer">
            <div class="progress-inner" style="width: """ + str(pct) + """%"></div>
        </div>
        <div style="display:flex; justify-content: space-between; margin-top: 2px;">
            <div class="info-label" style="font-size:11px">Used: """ + usage_str + """</div>
            <div class="info-label" style="font-size:11px">Remaining: """ + rem_str + """</div>
        </div>
        <div class="info-row" style="margin-top:14px; padding-top:14px; border-top: 1px solid rgba(148,163,184,0.08);">
            <span class="info-label">Time Left</span>
            <span class="info-value" style="color:#22d3ee; font-size:15px">""" + expiry_str + """</span>
        </div>
        <div class="section-title">Available Nodes</div>
        <div id="node-list"></div>
    </div>
    <div class="overlay" id="qr-overlay" onclick="if(event.target===this)this.classList.remove('show')">
        <div class="overlay-box">
            <button class="overlay-close" onclick="document.getElementById('qr-overlay').classList.remove('show')">&#10005;</button>
            <h3 style="color:#22d3ee; font-size:14px; font-weight:700">QR Code</h3>
            <img id="qr-img" src="" alt="QR">
        </div>
    </div>
    <script>
        const config = """ + config_json + """;
        const listEl = document.getElementById('node-list');
        function showToast(txt) {
            const t = document.getElementById('toast');
            t.textContent = txt; t.className = 'toast show';
            clearTimeout(t.timer);
            t.timer = setTimeout(function() { t.className = 'toast'; }, 2500);
        }
        function copyTxt(text) {
            navigator.clipboard.writeText(text)
                .then(function() { showToast('Copied!'); })
                .catch(function() { showToast('Copy failed'); });
        }
        function showQR(text) {
            document.getElementById('qr-img').src = 'https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=' + encodeURIComponent(text);
            document.getElementById('qr-overlay').classList.add('show');
        }
        var parts = config.split('#');
        var remark = parts[1] ? decodeURIComponent(parts[1]) : 'Node 1';
        listEl.innerHTML =
            '<div class="node-card">' +
                '<span class="node-name">' + remark + '</span>' +
                '<div style="display:flex; gap: 6px;">' +
                    '<button class="btn btn-outline" onclick="copyTxt(config)">Copy</button>' +
                    '<button class="btn btn-primary" onclick="showQR(config)">QR</button>' +
                '</div>' +
            '</div>';
    </script>
</body>
</html>"""
    return html


def generate_subscription_content(link: dict, uid: str) -> str:
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    expires_at_str = link.get("expires_at")
    usage_str = f"{_fmt_bytes(used)} / \u221e" if limit == 0 else f"{_fmt_bytes(used)} / {_fmt_bytes(limit)}"
    secs_left = seconds_until_expiry(expires_at_str)
    if secs_left is None:
        expiry_str = "\u221e"
    elif secs_left == 0:
        expiry_str = "Expired"
    else:
        expiry_str = f"{secs_left // 86400} Days Left"
    status_node = generate_vless_link(uid, remark=f"\U0001f4ca {usage_str} | \u23f3 {expiry_str}", address="0.0.0.0", port=DEFAULT_PORT)
    links_out = [status_node]
    links_out.append(generate_vless_link(uid, remark=f"Usf-{link['label']}", port=DEFAULT_PORT))
    return "\n".join(links_out)

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
        link = dict(link)
    if not link["active"]:
        raise HTTPException(status_code=403, detail="link disabled")
    expires_at = parse_expires_at(link.get("expires_at"))
    if expires_at is not None and expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="link expired")
    ua = request.headers.get("user-agent", "").lower()
    accept = request.headers.get("accept", "").lower()
    is_browser = any(x in ua for x in ["mozilla", "chrome", "safari", "opera", "edge"]) and "text/html" in accept
    if is_browser:
        return HTMLResponse(content=generate_sub_landing_page(link, uid))
    sub_content = generate_subscription_content(link, uid)
    encoded = base64.b64encode(sub_content.encode()).decode()
    total_bytes = link["limit_bytes"] if link["limit_bytes"] > 0 else UNLIMITED_QUOTA_BYTES
    expire_ts = 0
    if expires_at is not None:
        expire_ts = int(expires_at.timestamp())
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": 'attachment; filename="sub.txt"',
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']};download=0;total={total_bytes};expire={expire_ts}",
    }
    return Response(content=encoded, headers=headers)

# ── WebSocket VLESS Tunnel ─────────────────────────────────────────────────────
async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 1 + 16
    addon_len = first_chunk[pos]
    pos += 1 + addon_len
    command = first_chunk[pos]
    pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big")
    pos += 2
    addr_type = first_chunk[pos]
    pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]
        pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]
        pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]
        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None or not link["active"]:
            return False
        expires_at = parse_expires_at(link.get("expires_at"))
        if expires_at is not None and expires_at < datetime.now(timezone.utc):
            return False
        if link["limit_bytes"] == 0:
            return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket, writer, conn_id, link_uid):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break
            stats["total_bytes"] += size
            stats["total_requests"] += 1
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now(timezone.utc).strftime("%H:00")] += size
            daily_traffic[datetime.now(timezone.utc).strftime("%Y-%m-%d")] += size
            await add_usage(link_uid, size)
            try:
                writer.write(data)
                await writer.drain()
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        try:
            if not writer.is_closing():
                writer.write_eof()
        except Exception:
            pass

async def tcp_to_ws(websocket, reader, conn_id, link_uid):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break
            stats["total_bytes"] += size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now(timezone.utc).strftime("%H:00")] += size
            daily_traffic[datetime.now(timezone.utc).strftime("%Y-%m-%d")] += size
            await add_usage(link_uid, size)
            try:
                await websocket.send_bytes((b"\x00\x00" + data) if first else data)
                first = False
            except Exception:
                break
    except Exception:
        pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()

    # IMPORTANT: all validation that doesn't require reading client data
    # happens BEFORE accept(). Calling websocket.close() before accept()
    # makes the ASGI server reply with a plain HTTP 403 instead of
    # completing the WebSocket upgrade (101) and then dropping the
    # connection. The latter is a strong, easily-scriptable fingerprint
    # for active-probing systems: "this server fully completes a WS
    # handshake for literally any /ws/<uuid> path, then closes it" is
    # exactly the kind of behavior DPI/censor probes look for. Rejecting
    # pre-handshake makes invalid requests look like a normal closed/
    # forbidden endpoint instead of a live VLESS server.
    async with LINKS_LOCK:
        link_data = LINKS.get(uuid)
        if link_data is None or not link_data["active"]:
            await websocket.close(code=1008)
            return
        max_conn = link_data.get("max_connections", 0)
        link_data_copy = dict(link_data)

    expires_at = parse_expires_at(link_data_copy.get("expires_at"))
    if expires_at is not None and expires_at < datetime.now(timezone.utc):
        await websocket.close(code=1008)
        return

    if max_conn > 0:
        current_conns = await count_connections_for_link(uuid)
        if current_conns >= max_conn:
            await websocket.close(code=1008)
            return

    await websocket.accept()
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
    try:
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        try:
            command, address, port, initial_payload = await parse_vless_header(first_chunk)
        except ValueError as e:
            logger.warning(f"Invalid VLESS header: {e}")
            await websocket.close(code=1008, reason="invalid header")
            return

        conn_id = secrets.token_urlsafe(8)
        async with connections_lock:
            connections[conn_id] = {
                "uuid": uuid,
                "ip": client_ip,
                "connected_at": datetime.now(timezone.utc).isoformat(),
                "bytes": 0,
            }
            connection_sockets[conn_id] = websocket
            link_ip_map[uuid].add(client_ip)

        size = len(first_chunk)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
        async with connections_lock:
            if conn_id in connections:
                connections[conn_id]["bytes"] += size
        hourly_traffic[datetime.now(timezone.utc).strftime("%H:00")] += size
        daily_traffic[datetime.now(timezone.utc).strftime("%Y-%m-%d")] += size
        await add_usage(uuid, size)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )

        # Speed optimization: enable TCP_NODELAY
        try:
            sock = writer.get_extra_info('socket')
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            async with connections_lock:
                if conn_id in connections:
                    connections[conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now(timezone.utc).strftime("%H:00")] += p_size
            daily_traffic[datetime.now(timezone.utc).strftime("%Y-%m-%d")] += p_size
            await add_usage(uuid, p_size)
            try:
                writer.write(initial_payload)
                await writer.drain()
            except Exception:
                pass

        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now(timezone.utc).isoformat()})
        logger.exception("WebSocket error")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        if conn_id:
            async with connections_lock:
                info = connections.pop(conn_id, None)
                connection_sockets.pop(conn_id, None)
                if info:
                    uid = info.get("uuid")
                    ip = info.get("ip")
                    if uid and ip:
                        has_other = any(
                            c.get("uuid") == uid and c.get("ip") == ip
                            for c in connections.values()
                        )
                        if not has_other:
                            if uid in link_ip_map:
                                link_ip_map[uid].discard(ip)
                                if not link_ip_map[uid]:
                                    link_ip_map.pop(uid, None)


PANEL_HTML = r"""<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Usf-Pnl</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --pri:#0b1120;--pri2:#111827;--pri3:#1e293b;
  --surface:rgba(15,23,42,0.92);--surface2:rgba(30,41,59,0.7);--surface3:rgba(51,65,85,0.5);
  --border:rgba(148,163,184,0.08);--border2:rgba(6,182,212,0.2);
  --accent:#06b6d4;--accent2:#22d3ee;--accent3:#0891b2;
  --accent-dim:rgba(6,182,212,0.08);--accent-glow:0 0 20px rgba(6,182,212,0.15);
  --txt:#e2e8f0;--txt2:#94a3b8;--txt3:#64748b;
  --green:#34d399;--red:#fb7185;--yellow:#fbbf24;
  --top-h:56px;
  --radius:12px;
}
body.light-mode{
  --pri:#f1f5f9;--pri2:#ffffff;--pri3:#e2e8f0;
  --surface:rgba(255,255,255,0.95);--surface2:rgba(241,245,249,0.8);--surface3:rgba(226,232,240,0.6);
  --border:rgba(15,23,42,0.08);--border2:rgba(6,182,212,0.25);
  --accent-dim:rgba(6,182,212,0.1);--accent-glow:0 4px 12px rgba(0,0,0,0.06);
  --txt:#0f172a;--txt2:#475569;--txt3:#94a3b8;
}
html,body{height:100%}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--pri);color:var(--txt);display:flex;flex-direction:column;min-height:100vh;transition:background .3s,color .3s}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-thumb{background:rgba(6,182,212,0.2);border-radius:4px}
.bg-glow{position:fixed;inset:0;z-index:0;pointer-events:none;background:radial-gradient(ellipse 80% 50% at 50% -5%,rgba(6,182,212,0.06),transparent 60%)}

/* Top Bar */
.topbar{height:var(--top-h);background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 20px;position:sticky;top:0;z-index:100;backdrop-filter:blur(16px)}
.topbar-right{display:flex;align-items:center;gap:10px}
.topbar-logo{width:28px;height:28px;color:var(--accent2)}
.topbar-logo svg{width:100%;height:100%}
.topbar-brand{font-size:15px;font-weight:800;color:var(--accent2);letter-spacing:.5px}
.topbar-nav{display:flex;align-items:center;gap:2px}
.nav-btn{font-family:inherit;font-size:12.5px;font-weight:600;padding:8px 16px;border-radius:8px;cursor:pointer;border:none;background:transparent;color:var(--txt3);transition:all .2s;white-space:nowrap}
.nav-btn:hover{background:var(--accent-dim);color:var(--txt)}
.nav-btn.active{background:var(--accent-dim);color:var(--accent2)}
.topbar-left{display:flex;align-items:center;gap:6px}
.topbar-icon{width:34px;height:34px;display:flex;align-items:center;justify-content:center;border-radius:8px;cursor:pointer;color:var(--txt3);background:none;border:none;transition:all .2s}
.topbar-icon:hover{background:var(--accent-dim);color:var(--txt)}
.topbar-icon svg{width:18px;height:18px}

/* Main Content */
.main{flex:1;padding:24px;max-width:1100px;width:100%;margin:0 auto;position:relative;z-index:1}
.page{display:none;animation:fadeUp .25s ease}.page.active{display:block}
@keyframes fadeUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.page-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:10px}
.page-title{font-size:18px;font-weight:800;color:var(--txt)}
.page-sub{font-size:12px;color:var(--txt3);margin-top:2px}

/* Stat Cards */
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.st-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;transition:all .25s}
.st-card:hover{border-color:var(--border2);transform:translateY(-1px);box-shadow:var(--accent-glow)}
.st-card-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;margin-bottom:10px}
.st-card-icon svg{width:16px;height:16px}
.st-card-icon.c1{background:rgba(6,182,212,0.1);color:var(--accent2)}
.st-card-icon.c2{background:rgba(52,211,153,0.1);color:var(--green)}
.st-card-icon.c3{background:rgba(251,191,36,0.1);color:var(--yellow)}
.st-card-icon.c4{background:rgba(251,113,133,0.1);color:var(--red)}
.st-label{font-size:11px;color:var(--txt3);margin-bottom:4px}
.st-val{font-size:20px;font-weight:800;font-variant-numeric:tabular-nums}
.st-unit{font-size:11px;font-weight:500;color:var(--txt3)}

/* Cards */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;transition:border-color .2s}
.card:hover{border-color:var(--border2)}
.card-title{font-size:12px;font-weight:700;color:var(--txt2);margin-bottom:12px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:12px}

/* System Bars */
.sys-item{display:flex;align-items:center;justify-content:space-between;padding:5px 0}
.sys-k{font-size:12px;color:var(--txt3)}
.sys-v{font-size:13px;font-weight:700;font-variant-numeric:tabular-nums}
.bar-bg{height:5px;background:rgba(148,163,184,0.06);border-radius:3px;overflow:hidden;margin-top:6px}
.bar-fg{height:100%;border-radius:3px;transition:width .5s,background .5s;background:var(--accent2)}

/* Chart */
.chart-box{height:190px;position:relative}

/* Table */
.toolbar{display:flex;align-items:center;gap:6px;margin-bottom:12px;flex-wrap:wrap}
.chip{padding:5px 14px;border-radius:20px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid var(--border);background:transparent;color:var(--txt3);transition:all .2s}
.chip.active{background:var(--accent-dim);color:var(--accent2);border-color:var(--border2)}
.chip:hover{border-color:var(--border2)}
.search{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:7px 12px;color:var(--txt);font-size:12px;font-family:inherit;outline:none;min-width:160px;transition:border .2s}
.search:focus{border-color:var(--accent)}
.tbl{width:100%;border-collapse:collapse;font-size:12px}
.tbl thead th{text-align:left;padding:9px 10px;font-size:11px;font-weight:700;color:var(--txt3);border-bottom:1px solid var(--border)}
.tbl tbody td{padding:9px 10px;border-bottom:1px solid rgba(148,163,184,0.04);vertical-align:middle}
.tbl tbody tr:hover{background:rgba(6,182,212,0.02)}

/* Tags & Pills */
.tag{display:inline-block;padding:2px 8px;border-radius:6px;font-size:10px;font-weight:800;letter-spacing:.3px}
.tag-v{background:var(--accent-dim);color:var(--accent2);border:1px solid rgba(6,182,212,0.15)}
.tag-on{background:rgba(52,211,153,0.08);color:var(--green);border:1px solid rgba(52,211,153,0.2)}
.tag-off{background:rgba(251,113,133,0.08);color:var(--red);border:1px solid rgba(251,113,133,0.2)}
.pill{display:flex;align-items:center;gap:6px;font-size:11px}
.pill-used{color:var(--txt2);font-weight:600;min-width:55px}
.pill-bar{flex:1;height:4px;background:rgba(148,163,184,0.06);border-radius:2px;overflow:hidden;min-width:40px}
.pill-fill{height:100%;border-radius:2px;transition:width .5s}
.pill-lim{color:var(--txt3);font-size:10px;min-width:45px}

/* Toggle */
.toggle{width:34px;height:18px;border-radius:9px;background:rgba(148,163,184,0.15);border:none;cursor:pointer;position:relative;transition:background .2s}
.toggle::after{content:'';position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:#fff;transition:transform .2s}
.toggle.on{background:var(--accent)}
.toggle.on::after{transform:translateX(16px)}

/* Action Buttons */
.abtn{font-family:inherit;font-size:10px;font-weight:700;border-radius:6px;padding:4px 8px;cursor:pointer;border:1px solid var(--border);background:transparent;color:var(--txt3);transition:all .15s}
.abtn:hover{border-color:var(--border2);color:var(--txt)}
.abtn.ae:hover{color:var(--accent2);border-color:rgba(6,182,212,0.3)}
.abtn.ac:hover{color:var(--green);border-color:rgba(52,211,153,0.3)}
.abtn.as:hover{color:var(--yellow);border-color:rgba(251,191,36,0.3)}
.abtn.aq:hover{color:var(--accent2);border-color:rgba(6,182,212,0.3)}
.abtn.ad:hover{color:var(--red);border-color:rgba(251,113,133,0.3)}

/* Mobile Cards */
.m-cards{display:none}
.m-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px;margin-bottom:10px}
.m-card-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.m-card-acts{display:flex;gap:4px;margin-top:10px;flex-wrap:wrap}

/* Alerts */
.alerts{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:12px;margin-bottom:16px}
.alert-row{display:flex;align-items:center;justify-content:space-between;padding:7px 10px;border-radius:8px;background:var(--surface2);margin-bottom:5px;font-size:12px}
.alert-row:last-child{margin-bottom:0}

/* Buttons */
.btn{font-family:inherit;font-size:12px;font-weight:700;border-radius:8px;padding:9px 18px;cursor:pointer;border:none;transition:all .2s;display:inline-flex;align-items:center;gap:5px}
.btn-p{background:var(--accent);color:#0b1120}.btn-p:hover{background:var(--accent3)}
.btn-d{background:rgba(251,113,133,0.08);color:var(--red);border:1px solid rgba(251,113,133,0.2)}.btn-d:hover{background:rgba(251,113,133,0.15)}
.btn-g{background:rgba(148,163,184,0.06);color:var(--txt);border:1px solid var(--border)}.btn-g:hover{background:rgba(148,163,184,0.1)}
.btn-sm{font-size:10.5px;padding:6px 10px;border-radius:6px}

/* Modals */
.mo{position:fixed;inset:0;background:rgba(0,0,0,0.65);z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(6px)}
.mo.show{display:flex}
.mo-box{background:var(--pri2);border:1px solid var(--border2);border-radius:16px;padding:24px;width:90%;max-width:400px;position:relative;animation:moIn .2s ease}
@keyframes moIn{from{opacity:0;transform:scale(.96) translateY(8px)}to{opacity:1;transform:scale(1) translateY(0)}}
.mo-close{position:absolute;top:12px;right:12px;width:26px;height:26px;display:flex;align-items:center;justify-content:center;border-radius:6px;cursor:pointer;color:var(--txt3);background:none;border:none;font-size:14px;transition:all .2s}
.mo-close:hover{background:var(--accent-dim);color:var(--txt)}
.mo-title{font-size:14px;font-weight:800;color:var(--accent2);margin-bottom:18px;text-align:center}
.qr-box{background:var(--surface3);border-radius:10px;padding:14px;display:flex;justify-content:center}
.qr-box img{max-width:100%;border-radius:6px}
.fg{margin-bottom:12px}
.fl{display:block;font-size:11px;font-weight:700;color:var(--txt3);margin-bottom:4px;letter-spacing:.3px}
.fi{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;color:var(--txt);font-size:13px;font-family:inherit;outline:none;transition:border .2s}
.fi:focus{border-color:var(--accent)}
.fr{display:flex;gap:10px}
.fs{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;color:var(--txt);font-size:13px;font-family:inherit;outline:none;cursor:pointer}
.fs:focus{border-color:var(--accent)}

/* Toast */
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(16px);background:var(--pri2);color:var(--accent2);border:1px solid var(--border2);border-radius:8px;padding:9px 18px;font-size:12.5px;font-weight:600;opacity:0;transition:all .3s;z-index:999;pointer-events:none}
.toast.err{color:var(--red);border-color:rgba(251,113,133,0.3)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}

/* Empty */
.empty{text-align:center;padding:36px 20px;color:var(--txt3);font-size:13px}

/* Responsive */
@media(max-width:900px){
  .stats-row{grid-template-columns:repeat(2,1fr)}
}
@media(max-width:768px){
  .main{padding:16px 12px 80px}
  .topbar-nav{display:none}
  .mob-nav{display:flex!important}
  .d-table{display:none!important}
  .m-cards{display:block!important}
  .grid-2{grid-template-columns:1fr}
  .page-title{font-size:16px}
  .page-hd{margin-bottom:14px}
  .stats-row{grid-template-columns:1fr 1fr;gap:8px}
  .st-card{padding:12px}
  .st-val{font-size:16px}
}
@media(max-width:480px){
  .stats-row{grid-template-columns:1fr 1fr;gap:8px}
  .m-card-acts{gap:3px}
  .abtn{padding:4px 6px;font-size:9px}
  .mo-box{padding:20px 16px}
}
.mob-nav{display:none;position:fixed;bottom:0;left:0;right:0;background:var(--surface);border-top:1px solid var(--border);z-index:50;padding:6px 0 env(safe-area-inset-bottom,6px)}
.mob-nav-inner{display:flex;justify-content:space-around;align-items:center}
.mob-btn{display:flex;flex-direction:column;align-items:center;gap:2px;padding:6px 10px;cursor:pointer;color:var(--txt3);transition:color .2s;font-size:9px;font-weight:600;background:none;border:none;font-family:inherit}
.mob-btn.active{color:var(--accent2)}
.mob-btn svg{width:18px;height:18px}
</style>
</head>
<body>
<div class="bg-glow"></div>

<!-- Login -->
<div style="position:fixed;inset:0;display:flex;align-items:center;justify-content:center;z-index:100;background:var(--pri)" id="login-page">
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:36px 28px;width:90%;max-width:360px;text-align:center">
    <div style="margin-bottom:16px">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color:var(--accent2);margin:0 auto"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
    </div>
    <div style="font-size:20px;font-weight:800;color:var(--accent2);margin-bottom:4px">USF-PNL</div>
    <div style="font-size:12px;color:var(--txt3);margin-bottom:24px">Proxy Management Panel</div>
    <div id="login-err" style="display:none;background:rgba(251,113,133,0.08);border:1px solid rgba(251,113,133,0.2);color:var(--red);border-radius:8px;padding:8px 12px;font-size:12px;font-weight:600;margin-bottom:12px">Incorrect password</div>
    <div class="fg" style="text-align:left">
      <label class="fl">Password</label>
      <input class="fi" type="password" id="login-pw" placeholder="Enter your password" onkeydown="if(event.key==='Enter')doLogin()">
    </div>
    <button class="btn btn-p" style="width:100%;justify-content:center;padding:12px;font-size:13px" onclick="doLogin()">Sign In</button>
  </div>
</div>

<!-- Dashboard Shell -->
<div id="dashboard-page" style="display:none;width:100%">
  <!-- Top Bar -->
  <header class="topbar">
    <div class="topbar-right">
      <div class="topbar-logo"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
      <span class="topbar-brand">USF-PNL</span>
    </div>
    <nav class="topbar-nav">
      <button class="nav-btn active" data-page="dashboard">Dashboard</button>
      <button class="nav-btn" data-page="inbounds">Inbounds</button>
      <button class="nav-btn" data-page="traffic">Traffic</button>
      <button class="nav-btn" data-page="settings">Settings</button>
    </nav>
    <div class="topbar-left">
      <button class="topbar-icon" id="theme-btn" onclick="toggleTheme()" title="Theme">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
      </button>
      <button class="topbar-icon" onclick="doLogout()" title="Logout">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      </button>
    </div>
  </header>

  <main class="main">
    <!-- Dashboard -->
    <section class="page active" id="page-dashboard">
      <div class="page-hd">
        <div><div class="page-title">Dashboard</div><div class="page-sub">System overview &amp; statistics</div></div>
        <span style="font-size:11px;color:var(--txt3)" id="last-up"></span>
      </div>
      <div class="alerts" id="alerts-box" style="display:none"><div id="alerts-list"></div></div>
      <div class="stats-row">
        <div class="st-card">
          <div class="st-card-icon c1"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div>
          <div class="st-label">Total Traffic</div>
          <div class="st-val"><span id="sv-traffic">0</span> <span class="st-unit">MB</span></div>
        </div>
        <div class="st-card">
          <div class="st-card-icon c2"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg></div>
          <div class="st-label">Inbounds</div>
          <div class="st-val" id="sv-links">0</div>
        </div>
        <div class="st-card">
          <div class="st-card-icon c3"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div>
          <div class="st-label">Uptime</div>
          <div class="st-val" id="sv-uptime">--:--:--</div>
        </div>
        <div class="st-card">
          <div class="st-card-icon c4"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg></div>
          <div class="st-label">Domain</div>
          <div class="st-val" id="sv-domain" style="font-size:13px;word-break:break-all">--</div>
        </div>
      </div>
      <div class="grid-2" style="margin-bottom:20px">
        <div class="card">
          <div class="card-title">System Resources</div>
          <div class="sys-item"><span class="sys-k">CPU</span><span class="sys-v" id="cpu-v">--</span></div>
          <div class="bar-bg"><div class="bar-fg" id="cpu-b" style="width:0%"></div></div>
          <div class="sys-item" style="margin-top:8px"><span class="sys-k">Memory</span><span class="sys-v" id="mem-v">--</span></div>
          <div class="bar-bg"><div class="bar-fg" id="mem-b" style="width:0%"></div></div>
        </div>
        <div class="card">
          <div class="card-title">Hourly Traffic</div>
          <div class="chart-box"><canvas id="tc"></canvas></div>
        </div>
      </div>
    </section>

    <!-- Inbounds -->
    <section class="page" id="page-inbounds">
      <div class="page-hd">
        <div><div class="page-title">Inbounds</div><div class="page-sub">Manage VLESS connections</div></div>
        <button class="btn btn-p" onclick="showAddMo()">+ Add</button>
      </div>
      <div class="toolbar">
        <div class="chip active" data-f="all" onclick="setFilter('all',this)">All</div>
        <div class="chip" data-f="active" onclick="setFilter('active',this)">Active</div>
        <div class="chip" data-f="off" onclick="setFilter('off',this)">Inactive</div>
        <input class="search" id="srch" placeholder="Search..." oninput="filterLinks()">
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="d-table" style="overflow-x:auto">
          <table class="tbl">
            <thead><tr>
              <th>#</th><th>Name</th><th>Type</th><th>Usage</th><th>Conn</th><th>Expiry</th><th>Status</th><th>Actions</th>
            </tr></thead>
            <tbody id="ltb"></tbody>
          </table>
        </div>
        <div class="m-cards" id="mcards"></div>
        <div class="empty" id="lempty" style="display:none">No inbounds found</div>
      </div>
    </section>

    <!-- Traffic -->
    <section class="page" id="page-traffic">
      <div class="page-hd"><div><div class="page-title">Traffic</div><div class="page-sub">Usage statistics &amp; analytics</div></div></div>
      <div class="grid-2" style="margin-bottom:12px">
        <div class="card">
          <div class="sys-item"><span class="sys-k">Total Traffic</span><span class="sys-v" id="t-tr">--</span></div>
          <div class="sys-item"><span class="sys-k">Total Requests</span><span class="sys-v" id="t-rq">--</span></div>
          <div class="sys-item"><span class="sys-k">Uptime</span><span class="sys-v" id="t-up">--</span></div>
        </div>
        <div class="card">
          <div class="card-title">User Traffic Share</div>
          <div class="chart-box"><canvas id="inbound-chart"></canvas></div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">Daily Traffic</div>
        <div class="chart-box" style="height:220px"><canvas id="daily-chart"></canvas></div>
      </div>
    </section>

    <!-- Settings -->
    <section class="page" id="page-settings">
      <div class="page-hd"><div><div class="page-title">Settings</div><div class="page-sub">Change panel password</div></div></div>
      <div class="card" style="max-width:440px">
        <div class="card-title">Change Password</div>
        <div class="fg"><label class="fl">Current Password</label><input class="fi" type="password" id="pw-current" placeholder="********"></div>
        <div class="fg"><label class="fl">New Password</label><input class="fi" type="password" id="pw-new" placeholder="********"></div>
        <div class="fg"><label class="fl">Confirm New Password</label><input class="fi" type="password" id="pw-confirm" placeholder="********" onkeydown="if(event.key==='Enter')doChangePw()"></div>
        <button class="btn btn-p" onclick="doChangePw()" style="margin-top:4px">Update Password</button>
        <div id="pw-err" style="color:var(--red);font-size:12px;margin-top:10px;display:none"></div>
        <div id="pw-ok" style="color:var(--green);font-size:12px;margin-top:10px;display:none">Password changed successfully</div>
      </div>
    </section>
  </main>

  <!-- Mobile Nav -->
  <div class="mob-nav">
    <div class="mob-nav-inner">
      <button class="mob-btn active" data-page="dashboard" onclick="switchPage('dashboard')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
        <span>Home</span>
      </button>
      <button class="mob-btn" data-page="inbounds" onclick="switchPage('inbounds')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>
        <span>Inbounds</span>
      </button>
      <button class="mob-btn" data-page="traffic" onclick="switchPage('traffic')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        <span>Traffic</span>
      </button>
      <button class="mob-btn" data-page="settings" onclick="switchPage('settings')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
        <span>Settings</span>
      </button>
      <button class="mob-btn" onclick="doLogout()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        <span>Logout</span>
      </button>
    </div>
  </div>
</div>

<!-- Modals -->
<div class="mo" id="mo-add" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-add').classList.remove('show')">&#10005;</button>
    <div class="mo-title">Add Inbound</div>
    <div class="fg"><label class="fl">Label</label><input class="fi" id="nl" placeholder="e.g. User 1"></div>
    <div class="fr">
      <div class="fg"><label class="fl">Traffic Limit</label><input class="fi" id="nv" type="number" min="0" step=".1" placeholder="0 = Unlimited"></div>
      <div class="fg" style="max-width:90px"><label class="fl">Unit</label><select class="fs" id="nu"><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl">Max Connections</label><input class="fi" id="nc" type="number" min="0" placeholder="0 = Unlimited"></div>
    <div class="fg"><label class="fl">Days Valid</label><input class="fi" id="nd" type="number" min="0" placeholder="0 = No expiry"></div>
    <button class="btn btn-p" onclick="createLink()" style="width:100%;justify-content:center;margin-top:10px;padding:11px">Create</button>
  </div>
</div>

<div class="mo" id="mo-edit" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-edit').classList.remove('show')">&#10005;</button>
    <div class="mo-title" id="et">Edit Inbound</div>
    <input type="hidden" id="eu">
    <div class="fg"><label class="fl">Name</label><input class="fi" id="en2" readonly style="opacity:.5;cursor:not-allowed"></div>
    <div class="fr">
      <div class="fg"><label class="fl">Traffic Limit</label><input class="fi" id="el" type="number" min="0" step=".1" placeholder="0 = Unlimited"></div>
      <div class="fg" style="max-width:90px"><label class="fl">Unit</label><select class="fs" id="eu2"><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl">Max Connections</label><input class="fi" id="ec" type="number" min="0" placeholder="0 = Unlimited"></div>
    <div class="fg"><label class="fl">Add Days</label><input class="fi" id="ed" type="number" min="0" placeholder="0 = No change"></div>
    <div style="display:flex;gap:10px;margin-top:14px">
      <button class="btn btn-p" onclick="saveEdit()" style="flex:1;justify-content:center;padding:11px">Save</button>
      <button class="btn btn-d" onclick="resetTraf()" style="padding:11px">Reset</button>
    </div>
  </div>
</div>

<div class="mo" id="mo-qr" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box" style="max-width:320px">
    <button class="mo-close" onclick="document.getElementById('mo-qr').classList.remove('show')">&#10005;</button>
    <div class="mo-title">QR Code</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR"></div>
    <div style="display:flex;gap:10px;margin-top:14px;justify-content:center">
      <button class="btn btn-p btn-sm" onclick="dlQR()" style="padding:9px 14px">Download</button>
      <button class="btn btn-g btn-sm" onclick="document.getElementById('mo-qr').classList.remove('show')" style="padding:9px 14px">Close</button>
    </div>
  </div>
</div>

<script>
function $m(id){return document.getElementById(id);}
function esc(s){return String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

var theme=localStorage.getItem('usf_theme')||'dark';
var allLinks=[];var cf='all';var sData={};
var tChart=null,iChart=null,dChart=null;
var isAuthenticated=false;

// Theme
function setTheme(t){
  theme=t;
  if(t==='light')document.body.classList.add('light-mode');
  else document.body.classList.remove('light-mode');
  localStorage.setItem('usf_theme',t);
  var btn=$m('theme-btn');
  if(btn)btn.innerHTML=t==='light'
    ?'<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>'
    :'<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
  updChartColors();
}
function toggleTheme(){setTheme(theme==='dark'?'light':'dark');}

// Auth
async function checkAuth(){try{var r=await fetch('/api/dashboard');if(r.ok){showDashboard();}else{showLogin();}}catch(e){showLogin();}}
function showLogin(){isAuthenticated=false;$m('login-page').style.display='';$m('dashboard-page').style.display='none';}
function showDashboard(){isAuthenticated=true;$m('login-page').style.display='none';$m('dashboard-page').style.display='block';initChart();loadStats();loadLinks();}
async function doLogin(){var pw=$m('login-pw').value;$m('login-err').style.display='none';try{var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});if(r.ok){$m('login-pw').value='';showDashboard();}else{$m('login-err').style.display='block';}}catch(e){$m('login-err').style.display='block';}}
async function doLogout(){await fetch('/api/logout',{method:'POST'});showLogin();}
async function doChangePw(){
  var cur=$m('pw-current').value,nw=$m('pw-new').value,cnf=$m('pw-confirm').value;
  $m('pw-err').style.display='none';$m('pw-ok').style.display='none';
  if(!cur||!nw||!cnf){$m('pw-err').textContent='Please fill all fields';$m('pw-err').style.display='block';return;}
  if(nw.length<4){$m('pw-err').textContent='Password too short (min 4)';$m('pw-err').style.display='block';return;}
  if(nw!==cnf){$m('pw-err').textContent='Passwords do not match';$m('pw-err').style.display='block';return;}
  try{
    var r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current:cur,new:nw})});
    if(r.ok){$m('pw-current').value='';$m('pw-new').value='';$m('pw-confirm').value='';$m('pw-ok').style.display='block';}
    else{var d=await r.json();$m('pw-err').textContent=d.detail||'Error';$m('pw-err').style.display='block';}
  }catch(e){$m('pw-err').textContent='Error';$m('pw-err').style.display='block';}
}

// Navigation
document.querySelectorAll('[data-page]').forEach(function(el){el.addEventListener('click',function(){switchPage(el.dataset.page);});});
function switchPage(id){
  document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active');});
  var t=$m('page-'+id);if(t)t.classList.add('active');
  document.querySelectorAll('.nav-btn[data-page]').forEach(function(n){n.classList.toggle('active',n.dataset.page===id);});
  document.querySelectorAll('.mob-btn[data-page]').forEach(function(n){n.classList.toggle('active',n.dataset.page===id);});
}

// Toast
function toast(msg,err){var t=$m('toast');t.textContent=msg;t.className='toast'+(err?' err':'')+' show';clearTimeout(t._h);t._h=setTimeout(function(){t.classList.remove('show');},3000);}

// Format
function fmtB(b){if(!b||b===0)return'0 B';return b>=1073741824?(b/1073741824).toFixed(2)+' GB':b>=1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB';}
function fmtLim(b){if(!b||b===0)return '\u221e';var g=b/1073741824;return(g%1===0?g.toFixed(0):g.toFixed(1))+' GB';}
function fmtExp(ea){if(!ea||ea===0)return '\u221e';var d=new Date(ea)-new Date();if(d<=0)return'Expired';var days=Math.floor(d/86400000);if(days>0)return days+'d';var hours=Math.floor(d/3600000);if(hours>0)return hours+'h';return Math.floor(d/60000)+'m';}

// Links
function setFilter(f,el){cf=f;document.querySelectorAll('.chip').forEach(function(c){c.classList.remove('active');});if(el)el.classList.add('active');filterLinks();}
function filterLinks(){
  var q=($m('srch')?($m('srch').value||''):'').toLowerCase();var r=allLinks;
  if(cf==='active')r=r.filter(function(l){return l.active;});else if(cf==='off')r=r.filter(function(l){return !l.active;});
  if(q)r=r.filter(function(l){return l.label.toLowerCase().indexOf(q)!==-1||l.uuid.toLowerCase().indexOf(q)!==-1;});
  renderLinks(r);
}

function processAlerts(){
  var al=$m('alerts-list');var ab=$m('alerts-box');al.innerHTML='';var c=0;
  allLinks.forEach(function(l){
    var u=l.used_bytes||0;var lim=l.limit_bytes||0;var pct=lim>0?(u/lim)*100:0;
    if(lim>0&&pct>=90){c++;al.innerHTML+='<div class="alert-row"><span style="font-weight:600">\ud83d\udd34 Near limit: &apos;'+esc(l.label)+'&apos;</span><span>'+pct.toFixed(1)+'%</span></div>';}
    if(l.expires_at){var diff=new Date(l.expires_at)-new Date();var days=diff/86400000;if(days>0&&days<=3){c++;al.innerHTML+='<div class="alert-row"><span style="font-weight:600">\ud83d\udfe1 Expiring soon: &apos;'+esc(l.label)+'&apos;</span><span>'+days.toFixed(1)+' days</span></div>';}}
  });
  ab.style.display=c>0?'block':'none';
  if(iChart){
    var sorted=allLinks.slice().sort(function(a,b){return(b.used_bytes||0)-(a.used_bytes||0);}).slice(0,8);
    iChart.data.labels=sorted.map(function(x){return x.label;});
    iChart.data.datasets[0].data=sorted.map(function(x){return Math.round((x.used_bytes||0)/(1024*1024));});
    iChart.update();
  }
}

function renderLinks(links){
  var tb=$m('ltb');var em=$m('lempty');var mc=$m('mcards');
  if(!links||!links.length){tb.innerHTML='';mc.innerHTML='';em.style.display='block';processAlerts();return;}
  em.style.display='none';var idx=links.length;
  var rows=links.map(function(l){
    var u=l.used_bytes||0;var lim=l.limit_bytes||0;var pct=lim>0?Math.min(100,(u/lim)*100):0;
    var col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--accent2)';var ex=fmtExp(l.expires_at);
    var ec=ex==='Expired'?'var(--red)':ex==='\u221e'?'var(--txt3)':'var(--txt2)';var i=idx--;
    var cc=l.current_connections||0;var mc2=l.max_connections||0;
    return{l:l,pct:pct,col:col,ex:ex,ec:ec,i:i,cc:cc,mc2:mc2,u:u,lim:lim};
  });
  tb.innerHTML=rows.map(function(r){
    return '<tr><td style="color:var(--txt3);font-size:10px">'+r.i+'</td><td style="font-weight:600">'+esc(r.l.label)+'</td><td><span class="tag tag-v">VLESS</span></td><td><div class="pill"><span class="pill-used">'+fmtB(r.u)+'</span><div class="pill-bar"><div class="pill-fill" style="width:'+r.pct+'%;background:'+r.col+'"></div></div><span class="pill-lim">'+fmtLim(r.lim)+'</span></div></td><td style="font-size:11px;font-weight:600;color:'+(r.mc2>0&&r.cc>=r.mc2?'var(--red)':'var(--txt2)')+'">'+r.cc+'/'+(r.mc2||'\u221e')+'</td><td style="font-size:10px;font-weight:700;color:'+r.ec+'">'+r.ex+'</td><td><span class="tag '+(r.l.active?'tag-on':'tag-off')+'">'+(r.l.active?'Active':'Inactive')+'</span></td><td><div style="display:flex;gap:3px;align-items:center;flex-wrap:wrap"><button class="toggle '+(r.l.active?'on':'')+'" data-uid="'+r.l.uuid+'" onclick="togLink(this)"></button><button class="abtn ae" onclick="showEditMo(\''+r.l.uuid+'\')">Edit</button><button class="abtn ac" onclick="cpLink(\''+esc(r.l.vless_link||'')+'\')">Copy</button><button class="abtn as" onclick="cpSub(\''+r.l.uuid+'\')">Sub</button><button class="abtn aq" onclick="showQR(\''+esc(r.l.vless_link||'')+'\')">QR</button><button class="abtn ad" onclick="delLink(\''+r.l.uuid+'\')">Delete</button></div></td></tr>';
  }).join('');
  mc.innerHTML=rows.map(function(r){
    return '<div class="m-card"><div class="m-card-hd"><div style="display:flex;align-items:center;gap:6px"><span style="font-size:10px;color:var(--txt3)">#'+r.i+'</span><span style="font-weight:600;font-size:13px">'+esc(r.l.label)+'</span><span class="tag tag-v">VLESS</span></div><button class="toggle '+(r.l.active?'on':'')+'" data-uid="'+r.l.uuid+'" onclick="togLink(this)"></button></div><div class="pill"><span class="pill-used">'+fmtB(r.u)+'</span><div class="pill-bar"><div class="pill-fill" style="width:'+r.pct+'%;background:'+r.col+'"></div></div><span class="pill-lim">'+fmtLim(r.lim)+'</span></div><div style="font-size:11px;color:'+r.ec+';margin-top:5px;font-weight:600">\u23f3 '+r.ex+' \u00b7 '+r.cc+'/'+(r.mc2||'\u221e')+' connections</div><div class="m-card-acts"><button class="abtn ae" onclick="showEditMo(\''+r.l.uuid+'\')">Edit</button><button class="abtn ac" onclick="cpLink(\''+esc(r.l.vless_link||'')+'\')">Copy</button><button class="abtn as" onclick="cpSub(\''+r.l.uuid+'\')">Sub</button><button class="abtn aq" onclick="showQR(\''+esc(r.l.vless_link||'')+'\')">QR</button><button class="abtn ad" onclick="delLink(\''+r.l.uuid+'\')">Delete</button></div></div>';
  }).join('');
  processAlerts();
}

async function togLink(el){var uid=el.dataset.uid;try{var r=await fetch('/api/links/'+uid+'/toggle',{method:'POST'});if(!r.ok)throw new Error();var d=await r.json();var l=allLinks.find(function(x){return x.uuid===uid;});if(l)l.active=d.active;filterLinks();loadStats();}catch(e){toast('Error',true);}}
function showAddMo(){$m('mo-add').classList.add('show');}

async function createLink(){
  var label=$m('nl').value.trim()||'New Link';
  if(!/^[a-zA-Z0-9\-_. ]+$/.test(label)){toast('Only English characters allowed',true);return;}
  var v=parseFloat($m('nv').value)||0;var mc=parseInt($m('nc').value)||0;var days=parseInt($m('nd').value)||0;
  try{
    var r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:label,limit_value:v,limit_unit:'GB',max_connections:mc,days_valid:days})});
    if(!r.ok){var d=await r.json().catch(function(){return {};});throw new Error(d.detail||'Error');}
    toast('Created');$m('nl').value='';$m('nv').value='';$m('nc').value='';$m('nd').value='';$m('mo-add').classList.remove('show');await loadLinks();await loadStats();
  }catch(e){toast(e.message||'Error',true);}
}

function showEditMo(uid){
  var l=allLinks.find(function(x){return x.uuid===uid;});if(!l)return;
  $m('eu').value=uid;$m('en2').value=l.label;$m('el').value=l.limit_bytes>0?(l.limit_bytes/1073741824):'';
  $m('ec').value=l.max_connections>0?l.max_connections:'';$m('ed').value='';
  $m('et').textContent='Edit: '+l.label;$m('mo-edit').classList.add('show');
}

async function saveEdit(){
  var uid=$m('eu').value;var v=parseFloat($m('el').value)||0;var mc=parseInt($m('ec').value)||0;var days=parseInt($m('ed').value)||0;
  var body={limit_value:v,limit_unit:'GB',max_connections:mc};if(days>0)body.days_valid=days;
  try{var r=await fetch('/api/links/'+uid,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(!r.ok)throw new Error();toast('Updated');$m('mo-edit').classList.remove('show');await loadLinks();}catch(e){toast('Error',true);}
}

async function resetTraf(){
  var uid=$m('eu').value;if(!confirm('Reset traffic for this inbound?'))return;
  try{var r=await fetch('/api/links/'+uid+'/reset',{method:'POST'});if(!r.ok)throw new Error();toast('Traffic reset');await loadLinks();}catch(e){toast('Error',true);}
}

async function delLink(uid){if(!confirm('Delete this inbound?'))return;try{var r=await fetch('/api/links/'+uid,{method:'DELETE'});if(!r.ok)throw new Error();toast('Deleted');await loadLinks();await loadStats();}catch(e){toast('Error',true);}}
function cpLink(txt){if(!txt){toast('No link available',true);return;}navigator.clipboard.writeText(txt).then(function(){toast('Copied!');}).catch(function(){toast('Copy failed',true);});}
async function cpSub(uid){try{var r=await fetch('/api/links/'+uid+'/sub');if(!r.ok)throw new Error();var d=await r.json();await navigator.clipboard.writeText(d.sub_url);toast('Subscription link copied!');}catch(e){toast('Error',true);}}
function showQR(txt){if(!txt){toast('No data available',true);return;}$m('qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(txt);$m('mo-qr').classList.add('show');}
function dlQR(){var a=document.createElement('a');a.href=$m('qr-img').src;a.download='usf-qr.png';a.click();}

// Stats
async function loadStats(){
  try{
    var r=await fetch('/api/dashboard');if(r.status===401){showLogin();return;}if(!r.ok)throw new Error();sData=await r.json();
    $m('sv-traffic').innerHTML=(sData.total_traffic_mb||0)+' <span class="st-unit">MB</span>';
    $m('sv-links').textContent=sData.links_count||0;$m('sv-uptime').textContent=sData.uptime||'--:--:--';
    $m('sv-domain').textContent=sData.domain||'--';$m('last-up').textContent='Updated '+new Date().toLocaleTimeString();
    if($m('t-tr'))$m('t-tr').textContent=(sData.total_traffic_mb||0)+' MB';
    if($m('t-rq'))$m('t-rq').textContent=(sData.total_requests||0).toLocaleString();
    if($m('t-up'))$m('t-up').textContent=sData.uptime||'--:--:--';
    if(sData.cpu_percent!==undefined&&sData.cpu_percent>0){
      var c=sData.cpu_percent;var cc=c>80?'var(--red)':c>50?'var(--yellow)':'var(--accent2)';
      $m('cpu-v').textContent=c.toFixed(1)+'%';$m('cpu-v').style.color=cc;$m('cpu-b').style.width=c+'%';$m('cpu-b').style.background=cc;
    }else{$m('cpu-v').textContent='N/A';}
    if(sData.memory_percent!==undefined&&sData.memory_percent>0){
      var m=sData.memory_percent;var mc2=m>80?'var(--red)':m>50?'var(--yellow)':'var(--green)';
      $m('mem-v').textContent=m.toFixed(1)+'%';$m('mem-v').style.color=mc2;$m('mem-b').style.width=m+'%';$m('mem-b').style.background=mc2;
    }else{$m('mem-v').textContent='N/A';}
    updChart();updDailyChart();
  }catch(e){}
}

async function loadLinks(){try{var r=await fetch('/api/links');if(r.status===401){showLogin();return;}if(!r.ok)throw new Error();var d=await r.json();allLinks=d.links||[];filterLinks();}catch(e){}}

// Charts
function initChart(){
  var ctx=$m('tc');if(!ctx||tChart)return;
  var accentCol='rgba(6,182,212,0.6)';var borderCol='#06b6d4';
  tChart=new Chart(ctx,{type:'bar',data:{labels:[],datasets:[{label:'MB',data:[],backgroundColor:accentCol,borderColor:borderCol,borderWidth:1,borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:'rgba(6,182,212,0.3)',font:{size:10}}},y:{grid:{color:'rgba(148,163,184,0.04)'},ticks:{color:'rgba(6,182,212,0.3)',font:{size:10},callback:function(v){return v+' MB';}},beginAtZero:true}}}});
  var ctx2=$m('inbound-chart');if(ctx2&&!iChart){iChart=new Chart(ctx2,{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:['#06b6d4','#34d399','#fbbf24','#fb7185','#38bdf8','#ec4899','#f43f5e','#22d3ee'],borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:true,position:'right',labels:{color:'rgba(226,232,240,0.6)',font:{size:10}}}}}});}
  var ctx3=$m('daily-chart');if(ctx3&&!dChart){dChart=new Chart(ctx3,{type:'line',data:{labels:[],datasets:[{label:'MB',data:[],borderColor:'#06b6d4',backgroundColor:'rgba(6,182,212,0.08)',fill:true,tension:0.4,pointRadius:3,pointBackgroundColor:'#06b6d4',borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:'rgba(6,182,212,0.3)',font:{size:10}}},y:{grid:{color:'rgba(148,163,184,0.04)'},ticks:{color:'rgba(6,182,212,0.3)',font:{size:10},callback:function(v){return v+' MB';}},beginAtZero:true}}}});}
  updChartColors();
}
function updChartColors(){
  if(!tChart)return;var col=theme==='light'?'rgba(0,0,0,0.4)':'rgba(6,182,212,0.3)';var gridCol=theme==='light'?'rgba(0,0,0,0.06)':'rgba(148,163,184,0.04)';
  tChart.options.scales.x.ticks.color=col;tChart.options.scales.y.ticks.color=col;tChart.options.scales.y.grid.color=gridCol;tChart.update();
  if(dChart){dChart.options.scales.x.ticks.color=col;dChart.options.scales.y.ticks.color=col;dChart.options.scales.y.grid.color=gridCol;dChart.update();}
}
function updChart(){if(!tChart||!sData.hourly_traffic)return;var e=Object.entries(sData.hourly_traffic).sort(function(a,b){return a[0].localeCompare(b[0]);}).slice(-12);tChart.data.labels=e.map(function(x){return x[0];});tChart.data.datasets[0].data=e.map(function(x){return Math.round(x[1]/1048576);});tChart.update();}
function updDailyChart(){if(!dChart||!sData.daily_traffic)return;var e=Object.entries(sData.daily_traffic).sort(function(a,b){return a[0].localeCompare(b[0]);}).slice(-14);dChart.data.labels=e.map(function(x){return x[0];});dChart.data.datasets[0].data=e.map(function(x){return Math.round(x[1]/1048576);});dChart.update();}

// Init
setTheme(theme);checkAuth();
var _si=null;function startPoll(){if(_si)clearInterval(_si);_si=setInterval(function(){if(isAuthenticated){loadStats();loadLinks();}},12000);}startPoll();
</script>
</body>
</html>"""


# ── Page Routes ───────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(content=PANEL_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    return HTMLResponse(content=PANEL_HTML)

@app.get("/panel", response_class=HTMLResponse)
async def panel_page():
    return HTMLResponse(content=PANEL_HTML)

# ── Uvicorn ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])