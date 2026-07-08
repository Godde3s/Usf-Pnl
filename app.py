import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import base64
import socket
import uuid as uuid_lib
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
logger = logging.getLogger("panel")

# ── App Setup ──────────────────────────────────────────────────────────────────
app = FastAPI(title="WebApp", docs_url=None, redoc_url=None)

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

SESSION_COOKIE = "sid"
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
    """Detect domain from platform env vars (order: HF > Render > Railway > Fly > Koyeb > request host)."""
    # HuggingFace Spaces
    d = os.environ.get("SPACE_HOST", "")
    if d:
        return d.replace("https://", "").replace("http://", "").split("/")[0]
    # Render
    d = os.environ.get("RENDER_EXTERNAL_URL", "")
    if d:
        return d.replace("https://", "").replace("http://", "").split("/")[0]
    # Railway
    d = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "")
    if d:
        return d.replace("https://", "").replace("http://", "").split("/")[0]
    # Fly.io
    d = os.environ.get("FLY_APP_NAME", "")
    if d:
        return f"{d}.fly.dev"
    # Koyeb
    d = os.environ.get("KOYEB_SERVICE_NAME", "")
    if d:
        return f"{d}-koyeb.apps.koyeb.com"
    return "localhost"

def generate_vless_link(uuid: str, remark: str = "Node", address: str = None, port: int = None) -> str:
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
            LINKS[str(uuid_lib.uuid4())] = {
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
            "vless_link": generate_vless_link(uid, remark=f"{data['label']}", port=DEFAULT_PORT),
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
    uid = str(uuid_lib.uuid4())
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
        "vless_link": generate_vless_link(uid, remark=f"{label}", port=DEFAULT_PORT),
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

    usage_str = f"{_fmt_bytes(used)} / Unlimited" if limit == 0 else f"{_fmt_bytes(used)} / {_fmt_bytes(limit)}"
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
            expiry_str = f"{days} Days, {hours} Hours Left"
        elif hours > 0:
            expiry_str = f"{hours} Hours, {mins} Minutes Left"
        else:
            expiry_str = f"{mins} Minutes Left"

    is_active = link["active"]
    if is_active and expires_at_str:
        exp_dt = parse_expires_at(expires_at_str)
        if exp_dt and exp_dt < datetime.now(timezone.utc):
            is_active = False

    config = generate_vless_link(uid, remark=f"{link['label']}", port=DEFAULT_PORT)
    config_json = json.dumps(config)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connection Status</title>
    <link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@700;900&family=Inter:wght@300;400;500;600;700&family=Vazirmatn:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            background: #060608;
            font-family: 'Inter', 'Vazirmatn', sans-serif;
            color: rgba(255,255,255,0.92);
            padding: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }}
        .bg-glow {{
            position: fixed; inset: 0; z-index: 0; pointer-events: none;
            background: radial-gradient(ellipse 70% 50% at 50% -10%, rgba(139,92,246,0.12), transparent 60%);
        }}
        .container {{
            width: 100%; max-width: 500px;
            background: rgba(12,12,18,0.97);
            border: 1px solid rgba(139,92,246,0.15);
            border-radius: 20px; padding: 24px;
            box-shadow: 0 0 24px rgba(139,92,246,0.1);
            position: relative; z-index: 1;
        }}
        .brand {{ text-align: center; margin-bottom: 20px; }}
        .brand svg {{ width: 40px; height: 40px; margin-bottom: 8px; }}
        .brand h1 {{
            font-family: 'Cinzel', serif; font-size: 22px;
            color: #A78BFA; letter-spacing: 2px;
        }}
        .brand p {{ font-size: 12px; color: rgba(255,255,255,0.35); margin-top: 4px; }}
        .card {{
            background: rgba(20,20,28,0.9);
            border: 1px solid rgba(139,92,246,0.08);
            border-radius: 14px; padding: 16px; margin-bottom: 14px;
        }}
        .user-header {{
            display: flex; align-items: center;
            justify-content: space-between; margin-bottom: 12px;
        }}
        .username {{ font-size: 18px; font-weight: 700; color: #fff; }}
        .status-badge {{
            padding: 3px 8px; border-radius: 6px;
            font-size: 10px; font-weight: 800; text-transform: uppercase;
        }}
        .status-active {{ background: rgba(74,222,128,0.15); color: #4ade80; border: 1px solid rgba(74,222,128,0.3); }}
        .status-expired {{ background: rgba(248,113,113,0.15); color: #f87171; border: 1px solid rgba(248,113,113,0.3); }}
        .label {{ font-size: 11px; color: rgba(255,255,255,0.4); text-transform: uppercase; letter-spacing: 1px; }}
        .val {{ font-size: 16px; font-weight: 600; color: #fff; margin-top: 2px; }}
        .progress-bar {{
            height: 6px; background: rgba(255,255,255,0.05);
            border-radius: 3px; overflow: hidden; margin: 12px 0;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #8B5CF6, #A78BFA);
            transition: width 0.5s;
        }}
        .config-list {{ margin-top: 15px; }}
        .config-item {{
            display: flex; align-items: center; justify-content: space-between;
            background: rgba(28,28,40,0.8);
            border: 1px solid rgba(255,255,255,0.05);
            padding: 10px 12px; border-radius: 8px; margin-bottom: 8px;
            font-size: 12.5px;
        }}
        .config-name {{
            font-weight: 600; color: rgba(255,255,255,0.8);
            overflow: hidden; text-overflow: ellipsis;
            white-space: nowrap; max-width: 60%;
        }}
        .btn {{
            font-family: inherit; font-size: 11.5px; font-weight: 700;
            border-radius: 6px; padding: 5px 10px; cursor: pointer;
            border: none; transition: all 0.2s;
        }}
        .btn-purple {{ background: #8B5CF6; color: #fff; }}
        .btn-purple:hover {{ background: #7C3AED; }}
        .btn-ghost {{ background: rgba(255,255,255,0.05); color: #fff; border: 1px solid rgba(255,255,255,0.1); }}
        .btn-ghost:hover {{ background: rgba(255,255,255,0.1); }}
        .mo {{
            position: fixed; inset: 0; background: rgba(0,0,0,0.8);
            z-index: 200; display: none; align-items: center;
            justify-content: center; backdrop-filter: blur(8px);
        }}
        .mo.show {{ display: flex; }}
        .mo-box {{
            background: rgba(20,20,28,0.95);
            border: 1px solid rgba(139,92,246,0.2);
            border-radius: 18px; padding: 24px; width: 90%;
            max-width: 320px; text-align: center; position: relative;
        }}
        .mo-box img {{
            max-width: 100%; border-radius: 8px;
            border: 3px solid rgba(139,92,246,0.15); margin-top: 15px;
        }}
        .mo-close {{
            position: absolute; top: 12px; right: 12px; font-size: 16px;
            cursor: pointer; color: rgba(255,255,255,0.4); background: none; border: none;
        }}
        .toast {{
            position: fixed; bottom: 20px; left: 50%;
            transform: translateX(-50%) translateY(16px);
            background: #0c0c10; color: #A78BFA;
            border: 1px solid rgba(139,92,246,0.2);
            border-radius: 10px; padding: 10px 18px;
            font-size: 13px; font-weight: 600; opacity: 0;
            transition: all 0.3s; z-index: 999;
        }}
        .toast.show {{ opacity: 1; transform: translateX(-50%) translateY(0); }}
    </style>
</head>
<body>
    <div class="bg-glow"></div>
    <div class="toast" id="toast">Copied!</div>
    <div class="container">
        <div class="brand">
            <svg viewBox="0 0 24 24" fill="none" stroke="#A78BFA" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <h1>PANEL</h1>
            <p>Panel</p>
        </div>
        <div class="card">
            <div class="user-header">
                <span class="username">{link['label']}</span>
                <span class="status-badge {'status-active' if is_active else 'status-expired'}">
                    {'Active' if is_active else 'Inactive'}
                </span>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {pct}%"></div>
            </div>
            <div style="display:flex; justify-content: space-between; margin-top: 10px;">
                <div>
                    <div class="label">Usage</div>
                    <div class="val">{usage_str}</div>
                </div>
                <div>
                    <div class="label">Remaining</div>
                    <div class="val">{rem_str}</div>
                </div>
            </div>
        </div>
        <div class="card">
            <div class="label">Time Validity / Expiration</div>
            <div class="val" style="color: #A78BFA; font-size: 18px; font-weight: 700; margin-top: 4px;">{expiry_str}</div>
        </div>
        <h3 style="margin: 20px 0 10px 5px; font-size: 14px; letter-spacing: 1px; color: rgba(255,255,255,0.5);">AVAILABLE NODES</h3>
        <div class="config-list" id="config-list"></div>
    </div>
    <div class="mo" id="qr-modal" onclick="if(event.target===this)this.classList.remove('show')">
        <div class="mo-box">
            <button class="mo-close" onclick="document.getElementById('qr-modal').classList.remove('show')">&#10005;</button>
            <h3 style="color:#A78BFA; font-family:'Cinzel',serif; font-size:14px;">QR Code</h3>
            <img id="qr-img" src="" alt="QR">
        </div>
    </div>
    <script>
        const config = {config_json};
        const listEl = document.getElementById('config-list');
        function showToast(txt) {{
            const t = document.getElementById('toast');
            t.textContent = txt; t.className = 'toast show';
            clearTimeout(t.timer);
            t.timer = setTimeout(() => t.className = 'toast', 2500);
        }}
        function copyTxt(text) {{
            navigator.clipboard.writeText(text)
                .then(() => showToast('Copied Successfully!'))
                .catch(() => showToast('Failed to copy.'));
        }}
        function showQR(text) {{
            document.getElementById('qr-img').src = 'https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=' + encodeURIComponent(text);
            document.getElementById('qr-modal').classList.add('show');
        }}
        const parts = config.split('#');
        const remark = parts[1] ? decodeURIComponent(parts[1]) : 'Node 1';
        listEl.innerHTML = `
            <div class="config-item">
                <span class="config-name">${{remark}}</span>
                <div style="display:flex; gap: 5px;">
                    <button class="btn btn-ghost" onclick="copyTxt(config)">Copy</button>
                    <button class="btn btn-purple" onclick="showQR(config)">QR</button>
                </div>
            </div>
        `;
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
    links_out.append(generate_vless_link(uid, remark=f"{link['label']}", port=DEFAULT_PORT))
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
        # Keepalive: send WebSocket ping every 20s to prevent cloud proxies (Render, etc.)
        # from killing idle connections. Uses protocol-level ping, not application data.
        async def ws_keepalive():
            try:
                while True:
                    await asyncio.sleep(20)
                    await websocket._send({"type": "websocket.ping", "bytes": b""})
            except Exception:
                pass
        task_ping = asyncio.create_task(ws_keepalive())
        done, pending = await asyncio.wait({task_up, task_down, task_ping}, return_when=asyncio.FIRST_COMPLETED)
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

# ── PANEL HTML ─────────────────────────────────────────────────────────────────
PANEL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title data-en="Panel" data-fa="پنل">Panel</title>
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@700;900&family=Inter:wght@300;400;500;600;700&family=Vazirmatn:wght@400;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --accent:#8B5CF6;--accent2:#A78BFA;--accent3:#7C3AED;--accent-dim:rgba(139,92,246,0.12);
  --black:#060608;--black2:#0c0c10;--black3:#111118;
  --surface:rgba(12,12,18,0.97);--surface2:rgba(20,20,28,0.9);--surface3:rgba(28,28,40,0.8);
  --border:rgba(139,92,246,0.1);--border2:rgba(139,92,246,0.2);
  --text:rgba(255,255,255,0.92);--text2:rgba(167,139,250,0.7);--text3:rgba(255,255,255,0.4);
  --white-neon:rgba(255,255,255,0.85);--white-glow:0 0 16px rgba(255,255,255,0.25);
  --accent-glow:0 0 20px rgba(139,92,246,0.4);
  --green:#4ade80;--green-dim:rgba(74,222,128,0.1);
  --red:#f87171;--red-dim:rgba(248,113,113,0.1);
  --yellow:#fbbf24;
  --nav-w:64px;
}
body.light-mode {
  --black:#f0f2f5;--black2:#ffffff;--black3:#e4e6eb;
  --surface:rgba(255,255,255,0.95);--surface2:#ffffff;--surface3:#f9fafb;
  --border:rgba(0,0,0,0.1);--border2:rgba(0,0,0,0.2);
  --text:#111827;--text2:#4b5563;--text3:#6b7280;
  --accent-dim:rgba(139,92,246,0.15);
  --accent-glow:0 4px 14px rgba(0,0,0,0.1);
}
html,body{height:100%;background:var(--black);transition:background .3s,color .3s}
body{font-family:'Inter','Vazirmatn',sans-serif;color:var(--text);display:flex;min-height:100vh}
body[dir="rtl"]{direction:rtl;text-align:right}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:rgba(139,92,246,0.2);border-radius:4px}
.bg-fixed{position:fixed;inset:0;z-index:0;pointer-events:none;background:radial-gradient(ellipse 70% 50% at 50% -10%,var(--accent-dim),transparent 60%)}
.grid-fixed{position:fixed;inset:0;z-index:0;pointer-events:none;background-image:linear-gradient(rgba(128,128,128,0.05) 1px,transparent 1px),linear-gradient(90deg,rgba(128,128,128,0.05) 1px,transparent 1px);background-size:56px 56px}

/* ── Login ─────────────────────────────────────────────────────────────────── */
.login-wrap{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;z-index:100;background:var(--black)}
.login-box{background:var(--surface);border:1px solid var(--border);border-radius:24px;padding:40px 32px;width:90%;max-width:380px;text-align:center;position:relative;box-shadow:0 0 60px rgba(139,92,246,0.08)}
.login-logo{margin-bottom:6px}
.login-logo svg{width:48px;height:48px;color:var(--accent2)}
.login-title{font-family:'Cinzel',serif;font-size:24px;color:var(--accent2);letter-spacing:3px;margin-bottom:4px}
.login-sub{font-size:12px;color:var(--text3);margin-bottom:28px}
.login-err{display:none;background:var(--red-dim);border:1px solid rgba(248,113,113,0.25);color:var(--red);border-radius:10px;padding:10px 14px;font-size:12.5px;font-weight:600;margin-bottom:14px}
.fg{margin-bottom:14px;text-align:left}
.fl{display:block;font-size:11.5px;font-weight:600;color:var(--text3);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px}
.fi{width:100%;background:var(--surface3);border:1px solid var(--border);border-radius:10px;padding:11px 14px;color:var(--text);font-size:14px;font-family:inherit;outline:none;transition:border .2s}
.fi:focus{border-color:var(--accent)}
.btn{font-family:inherit;font-size:12.5px;font-weight:700;border-radius:10px;padding:10px 18px;cursor:pointer;border:none;transition:all .2s;display:inline-flex;align-items:center;gap:5px}
.btn-accent{background:var(--accent);color:#fff;box-shadow:var(--accent-glow)}
.btn-accent:hover{background:var(--accent3);transform:translateY(-1px)}
.btn-danger{background:var(--red-dim);color:var(--red);border:1px solid rgba(248,113,113,0.25)}
.btn-danger:hover{background:rgba(248,113,113,0.2)}
.btn-ghost{background:rgba(255,255,255,0.05);color:var(--text);border:1px solid var(--border)}
.btn-ghost:hover{background:rgba(255,255,255,0.1)}
.btn-sm{font-size:11px;padding:6px 10px;border-radius:7px}

/* ── Sidebar ───────────────────────────────────────────────────────────────── */
.sidebar{width:var(--nav-w);min-height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;align-items:center;padding:16px 0;position:fixed;left:0;top:0;z-index:50;transition:transform .3s}
body[dir="rtl"] .sidebar{left:auto;right:0;border-right:none;border-left:1px solid var(--border)}
.sb-logo{width:36px;height:36px;margin-bottom:24px;cursor:pointer}
.sb-logo svg{width:100%;height:100%;color:var(--accent2)}
.nav-items{display:flex;flex-direction:column;gap:4px;flex:1;width:100%;padding:0 8px}
.nav-item{width:48px;height:48px;display:flex;align-items:center;justify-content:center;border-radius:12px;cursor:pointer;transition:all .2s;color:var(--text3);position:relative}
.nav-item:hover{background:var(--accent-dim);color:var(--text)}
.nav-item.active{background:var(--accent-dim);color:var(--accent2)}
.nav-item.active::before{content:'';position:absolute;left:-8px;top:50%;transform:translateY(-50%);width:3px;height:20px;background:var(--accent);border-radius:0 3px 3px 0}
body[dir="rtl"] .nav-item.active::before{left:auto;right:-8px;border-radius:3px 0 0 3px}
.nav-item svg{width:20px;height:20px}
.sb-bottom{display:flex;flex-direction:column;gap:4px;padding:0 8px}

/* ── Main Content ──────────────────────────────────────────────────────────── */
.main{margin-left:var(--nav-w);flex:1;padding:24px 28px;min-height:100vh;position:relative;z-index:1}
body[dir="rtl"] .main{margin-left:0;margin-right:var(--nav-w)}
.page{display:none;animation:fadeIn .3s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.page-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:12px}
.page-title{font-family:'Cinzel',serif;font-size:22px;color:var(--accent2);letter-spacing:1px}
.page-sub{font-size:12.5px;color:var(--text3);margin-top:3px}

/* ── Cards ─────────────────────────────────────────────────────────────────── */
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:16px;transition:all .3s;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(139,92,246,0.03),transparent 60%);pointer-events:none}
.card:hover{border-color:var(--border2)}
.card-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.card-title{font-size:13px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.5px}

/* ── Stat Cards ────────────────────────────────────────────────────────────── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:20px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px;position:relative;overflow:hidden;transition:all .3s}
.stat-card::after{content:'';position:absolute;top:-50%;right:-50%;width:100%;height:100%;background:radial-gradient(circle,var(--accent-dim),transparent 70%);pointer-events:none}
.stat-card:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:var(--accent-glow)}
.stat-icon{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;margin-bottom:10px}
.stat-icon svg{width:18px;height:18px}
.stat-icon.purple{background:var(--accent-dim);color:var(--accent2)}
.stat-icon.green{background:var(--green-dim);color:var(--green)}
.stat-icon.red{background:var(--red-dim);color:var(--red)}
.stat-icon.yellow{background:rgba(251,191,36,0.1);color:var(--yellow)}
.stat-label{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.stat-value{font-size:22px;font-weight:800;color:var(--text);font-variant-numeric:tabular-nums}
.stat-unit{font-size:12px;font-weight:500;color:var(--text3);margin-left:2px}

/* ── System Bars ───────────────────────────────────────────────────────────── */
.sys-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}
.sl-item{display:flex;align-items:center;justify-content:space-between;padding:6px 0}
.sl-k{font-size:12px;color:var(--text3)}
.sl-v{font-size:13px;font-weight:700;color:var(--text);font-variant-numeric:tabular-nums}
.bar-wrap{height:6px;background:rgba(255,255,255,0.05);border-radius:3px;overflow:hidden;margin-top:8px}
.bar-fill{height:100%;border-radius:3px;transition:width .5s,background .5s;background:var(--accent2)}

/* ── Charts ────────────────────────────────────────────────────────────────── */
.chart-container{height:200px;position:relative}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:14px}

/* ── Table ─────────────────────────────────────────────────────────────────── */
.toolbar{display:flex;align-items:center;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.chip{padding:6px 14px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid var(--border);background:transparent;color:var(--text3);transition:all .2s}
.chip.active{background:var(--accent-dim);color:var(--accent2);border-color:var(--border2)}
.chip:hover{border-color:var(--border2)}
.srch{background:var(--surface3);border:1px solid var(--border);border-radius:8px;padding:7px 12px;color:var(--text);font-size:12.5px;font-family:inherit;outline:none;min-width:180px;transition:border .2s}
.srch:focus{border-color:var(--accent)}
.tbl{width:100%;border-collapse:collapse;font-size:12.5px}
.tbl thead th{text-align:left;padding:10px 12px;font-size:11px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border)}
body[dir="rtl"] .tbl thead th{text-align:right}
.tbl tbody td{padding:10px 12px;border-bottom:1px solid rgba(255,255,255,0.03);vertical-align:middle}
.tbl tbody tr:hover{background:rgba(139,92,246,0.03)}

/* ── Tags & Pills ──────────────────────────────────────────────────────────── */
.tag{display:inline-block;padding:3px 8px;border-radius:6px;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.5px}
.tag-vless{background:var(--accent-dim);color:var(--accent2);border:1px solid rgba(139,92,246,0.2)}
.tag-on{background:var(--green-dim);color:var(--green);border:1px solid rgba(74,222,128,0.2)}
.tag-off{background:var(--red-dim);color:var(--red);border:1px solid rgba(248,113,113,0.2)}
.pill{display:flex;align-items:center;gap:8px;font-size:11.5px}
.pill-used{color:var(--text2);font-weight:600;min-width:60px}
.pill-bar{flex:1;height:5px;background:rgba(255,255,255,0.05);border-radius:3px;overflow:hidden;min-width:50px}
.pill-fill{height:100%;border-radius:3px;transition:width .5s}
.pill-lim{color:var(--text3);font-size:10.5px;min-width:50px;text-align:right}

/* ── Toggle Switch ─────────────────────────────────────────────────────────── */
.toggle{width:36px;height:20px;border-radius:10px;background:rgba(255,255,255,0.1);border:none;cursor:pointer;position:relative;transition:background .2s}
.toggle::after{content:'';position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;transition:transform .2s}
.toggle.on{background:var(--accent)}
.toggle.on::after{transform:translateX(16px)}

/* ── Action Buttons ────────────────────────────────────────────────────────── */
.act-btn{font-family:inherit;font-size:10.5px;font-weight:700;border-radius:6px;padding:5px 9px;cursor:pointer;border:1px solid var(--border);background:transparent;color:var(--text3);transition:all .15s}
.act-btn:hover{border-color:var(--border2);color:var(--text)}
.act-edit:hover{color:var(--accent2);border-color:rgba(139,92,246,0.3)}
.act-copy:hover{color:var(--green);border-color:rgba(74,222,128,0.3)}
.act-sub:hover{color:var(--yellow);border-color:rgba(251,191,36,0.3)}
.act-qr:hover{color:var(--accent2);border-color:rgba(139,92,246,0.3)}
.act-del:hover{color:var(--red);border-color:rgba(248,113,113,0.3)}

/* ── Mobile Cards ──────────────────────────────────────────────────────────── */
.m-cards{display:none}
.m-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:14px;margin-bottom:10px}
.m-card-hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.m-card-acts{display:flex;gap:5px;margin-top:10px;flex-wrap:wrap}

/* ── Alerts ────────────────────────────────────────────────────────────────── */
.alerts-box{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:14px;margin-bottom:16px}
.alert-item{display:flex;align-items:center;justify-content:space-between;padding:8px 10px;border-radius:8px;background:var(--surface3);margin-bottom:6px;font-size:12px}
.alert-item:last-child{margin-bottom:0}

/* ── Modals ────────────────────────────────────────────────────────────────── */
.mo{position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(8px)}
.mo.show{display:flex}
.mo-box{background:var(--surface);border:1px solid var(--border2);border-radius:18px;padding:28px 24px;width:90%;max-width:420px;position:relative;animation:modalIn .25s ease}
@keyframes modalIn{from{opacity:0;transform:scale(.95) translateY(10px)}to{opacity:1;transform:scale(1) translateY(0)}}
.mo-close{position:absolute;top:14px;right:14px;width:28px;height:28px;display:flex;align-items:center;justify-content:center;border-radius:8px;cursor:pointer;color:var(--text3);background:none;border:none;font-size:16px;transition:all .2s}
.mo-close:hover{background:var(--accent-dim);color:var(--text)}
.mo-title{font-family:'Cinzel',serif;font-size:16px;color:var(--accent2);letter-spacing:2px;margin-bottom:20px;text-align:center}
.qr-box{background:var(--surface3);border-radius:12px;padding:16px;display:flex;justify-content:center}
.qr-box img{max-width:100%;border-radius:8px}
.fr{display:flex;gap:10px}
.fs{width:100%;background:var(--surface3);border:1px solid var(--border);border-radius:10px;padding:11px 14px;color:var(--text);font-size:14px;font-family:inherit;outline:none;cursor:pointer}
.fs:focus{border-color:var(--accent)}

/* ── Toast ─────────────────────────────────────────────────────────────────── */
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(16px);background:var(--surface);color:var(--accent2);border:1px solid var(--border2);border-radius:10px;padding:10px 18px;font-size:13px;font-weight:600;opacity:0;transition:all .3s;z-index:999;pointer-events:none}
.toast.err{color:var(--red);border-color:rgba(248,113,113,0.3)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}

/* ── Empty State ───────────────────────────────────────────────────────────── */
.empty{text-align:center;padding:40px 20px;color:var(--text3);font-size:14px}

/* ── Mobile Bottom Nav ─────────────────────────────────────────────────────── */
.bottom-nav{display:none;position:fixed;bottom:0;left:0;right:0;background:var(--surface);border-top:1px solid var(--border);z-index:50;padding:6px 0 env(safe-area-inset-bottom,6px)}
.bottom-nav-inner{display:flex;justify-content:space-around;align-items:center}
.bn-item{display:flex;flex-direction:column;align-items:center;gap:2px;padding:6px 12px;cursor:pointer;color:var(--text3);transition:color .2s;font-size:9px;font-weight:600}
.bn-item.active{color:var(--accent2)}
.bn-item svg{width:20px;height:20px}

/* ── Responsive ────────────────────────────────────────────────────────────── */
@media(max-width:768px){
  .sidebar{transform:translateX(-100%)}
  body[dir="rtl"] .sidebar{transform:translateX(100%)}
  .main{margin-left:0!important;margin-right:0!important;padding:16px 14px 80px}
  .bottom-nav{display:block}
  .d-table{display:none!important}
  .m-cards{display:block!important}
  .stats-grid{grid-template-columns:1fr 1fr}
  .sys-grid,.grid-2{grid-template-columns:1fr}
  .page-title{font-size:18px}
  .toolbar{gap:6px}
  .srch{min-width:120px;font-size:12px;padding:6px 10px}
}
</style>
</head>
<body>
<div class="bg-fixed"></div>
<div class="grid-fixed"></div>

<!-- Login Page -->
<div class="login-wrap" id="login-page">
  <div class="login-box">
    <div class="login-logo">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    </div>
    <div class="login-title">PANEL</div>
    <div class="login-sub" data-en="Secure VLESS Proxy Panel" data-fa="\u067e\u0646\u0644 \u067e\u0631\u0648\u06a9\u0633\u06cc VLESS \u0627\u0645\u0646">Secure VLESS Proxy Panel</div>
    <div class="login-err" id="login-err" data-en="Invalid password" data-fa="\u0631\u0645\u0632 \u0639\u0628\u0648\u0631 \u0627\u0634\u062a\u0628\u0627\u0647 \u0627\u0633\u062a">Invalid password</div>
    <div class="fg">
      <label class="fl" data-en="Password" data-fa="\u0631\u0645\u0632 \u0639\u0628\u0648\u0631">Password</label>
      <input class="fi" type="password" id="login-pw" data-ph-en="Enter panel password" data-ph-fa="\u0631\u0645\u0632 \u0639\u0628\u0648\u0631 \u067e\u0646\u0644 \u0631\u0627 \u0648\u0627\u0631\u062f \u06a9\u0646\u06cc\u062f" placeholder="Enter panel password" onkeydown="if(event.key==='Enter')doLogin()">
    </div>
    <button class="btn btn-accent" style="width:100%;justify-content:center;padding:13px;font-size:14px" onclick="doLogin()" data-en="Login" data-fa="\u0648\u0631\u0648\u062f">Login</button>
  </div>
</div>

<!-- Dashboard -->
<div id="dashboard-page" style="display:none;width:100%">
  <!-- Sidebar -->
  <nav class="sidebar">
    <div class="sb-logo" onclick="switchPage('dashboard')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    </div>
    <div class="nav-items">
      <div class="nav-item active" data-page="dashboard" title="Dashboard">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
      </div>
      <div class="nav-item" data-page="inbounds" title="Inbounds">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/><line x1="9" y1="12" x2="15" y2="12"/><line x1="9" y1="16" x2="13" y2="16"/></svg>
      </div>
      <div class="nav-item" data-page="traffic" title="Traffic">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      </div>
    </div>
    <div class="sb-bottom">
      <div class="nav-item" onclick="toggleLang()" title="Language">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
      </div>
      <div class="nav-item" id="theme-btn-desk" onclick="toggleTheme()" title="Theme">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
      </div>
      <div class="nav-item" onclick="doLogout()" title="Logout">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      </div>
    </div>
  </nav>

  <main class="main">
    <!-- Dashboard Page -->
    <section class="page active" id="page-dashboard">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Dashboard" data-fa="\u062f\u0627\u0634\u0628\u0648\u0631\u062f">Dashboard</div>
          <div class="page-sub" data-en="System overview &amp; statistics" data-fa="\u0646\u0645\u0627\u06cc \u06a9\u0644\u06cc \u0633\u06cc\u0633\u062a\u0645 \u0648 \u0622\u0645\u0627\u0631">System overview & statistics</div>
        </div>
        <div style="display:flex;gap:6px;align-items:center">
          <span style="font-size:11px;color:var(--text3)" id="last-up"></span>
        </div>
      </div>

      <div class="alerts-box" id="alerts-box" style="display:none">
        <div id="alerts-list"></div>
      </div>

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-icon purple">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          </div>
          <div class="stat-label" data-en="Total Traffic" data-fa="\u06a9\u0644 \u062a\u0631\u0627\u0641\u06cc\u06a9">Total Traffic</div>
          <div class="stat-value"><span id="sv-traffic">0</span><span class="stat-unit"> MB</span></div>
        </div>
        <div class="stat-card">
          <div class="stat-icon green">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>
          </div>
          <div class="stat-label" data-en="Inbounds" data-fa="\u0627\u06cc\u0646\u0628\u0627\u0646\u062f\u0647\u0627">Inbounds</div>
          <div class="stat-value" id="sv-links">0</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon yellow">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          </div>
          <div class="stat-label" data-en="Uptime" data-fa="\u0622\u067e\u062a\u0627\u06cc\u0645">Uptime</div>
          <div class="stat-value" id="sv-uptime">--:--:--</div>
        </div>
        <div class="stat-card">
          <div class="stat-icon red">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
          </div>
          <div class="stat-label" data-en="Domain" data-fa="\u062f\u0627\u0645\u0646\u0647">Domain</div>
          <div class="stat-value" id="sv-domain" style="font-size:14px;word-break:break-all">--</div>
        </div>
      </div>

      <div class="sys-grid" style="margin-bottom:20px">
        <div class="card">
          <div class="card-hd"><div class="card-title" data-en="System Resources" data-fa="\u0645\u0646\u0627\u0628\u0639 \u0633\u06cc\u0633\u062a\u0645">System Resources</div></div>
          <div class="sl-item"><span class="sl-k" data-en="CPU" data-fa="\u067e\u0631\u062f\u0627\u0632\u0646\u062f\u0647">CPU</span><span class="sl-v" id="cpu-v">--</span></div>
          <div class="bar-wrap"><div class="bar-fill" id="cpu-b" style="width:0%"></div></div>
          <div class="sl-item" style="margin-top:10px"><span class="sl-k" data-en="Memory" data-fa="\u062d\u0627\u0641\u0638\u0647">Memory</span><span class="sl-v" id="mem-v">--</span></div>
          <div class="bar-wrap"><div class="bar-fill" id="mem-b" style="width:0%"></div></div>
        </div>
        <div class="card">
          <div class="card-hd"><div class="card-title" data-en="Hourly Traffic" data-fa="\u062a\u0631\u0627\u0641\u06cc\u06a9 \u0633\u0627\u0639\u062a\u06cc">Hourly Traffic</div></div>
          <div class="chart-container"><canvas id="tc"></canvas></div>
        </div>
      </div>
    </section>

    <!-- Inbounds Page -->
    <section class="page" id="page-inbounds">
      <div class="page-header">
        <div>
          <div class="page-title" data-en="Inbounds" data-fa="\u0627\u06cc\u0646\u0628\u0627\u0646\u062f\u0647\u0627">Inbounds</div>
          <div class="page-sub" data-en="Manage VLESS connections" data-fa="\u0645\u062f\u06cc\u0631\u06cc\u062a \u0627\u062a\u0635\u0627\u0644\u0627\u062a VLESS">Manage VLESS connections</div>
        </div>
        <button class="btn btn-accent" onclick="showAddMo()" data-en="+ Add" data-fa="+ \u0627\u0641\u0632\u0648\u062f\u0646">+ Add</button>
      </div>
      <div class="toolbar">
        <div class="chip active" data-f="all" onclick="setFilter('all',this)" data-en="All" data-fa="\u0647\u0645\u0647">All</div>
        <div class="chip" data-f="active" onclick="setFilter('active',this)" data-en="Active" data-fa="\u0641\u0639\u0627\u0644">Active</div>
        <div class="chip" data-f="off" onclick="setFilter('off',this)" data-en="Disabled" data-fa="\u063a\u06cc\u0631\u0641\u0639\u0627\u0644">Disabled</div>
        <input class="srch" id="srch" data-ph-en="Search..." data-ph-fa="\u062c\u0633\u062a\u062c\u0648..." placeholder="Search..." oninput="filterLinks()">
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="d-table" style="overflow-x:auto">
          <table class="tbl">
            <thead><tr>
              <th data-en="#" data-fa="#">#</th>
              <th data-en="Name" data-fa="\u0646\u0627\u0645">Name</th>
              <th data-en="Type" data-fa="\u0646\u0648\u0639">Type</th>
              <th data-en="Usage" data-fa="\u0645\u0635\u0631\u0641">Usage</th>
              <th data-en="IPs" data-fa="\u0622\u06cc\u200c\u067e\u06cc">IPs</th>
              <th data-en="Expiry" data-fa="\u0627\u0646\u0642\u0636\u0627">Expiry</th>
              <th data-en="Status" data-fa="\u0648\u0636\u0639\u06cc\u062a">Status</th>
              <th data-en="Actions" data-fa="\u0639\u0645\u0644\u06cc\u0627\u062a">Actions</th>
            </tr></thead>
            <tbody id="ltb"></tbody>
          </table>
        </div>
        <div class="m-cards" id="mcards"></div>
        <div class="empty" id="lempty" style="display:none" data-en="No inbounds found" data-fa="\u0647\u06cc\u0686 \u0627\u06cc\u0646\u0628\u0627\u0646\u062f\u06cc \u06cc\u0627\u0641\u062a \u0646\u0634\u062f">No inbounds found</div>
      </div>
    </section>

    <!-- Traffic Page -->
    <section class="page" id="page-traffic">
      <div class="page-header"><div><div class="page-title" data-en="Traffic" data-fa="\u062a\u0631\u0627\u0641\u06cc\u06a9">Traffic</div><div class="page-sub" data-en="Statistics &amp; inbound comparison" data-fa="\u0622\u0645\u0627\u0631 \u0648 \u0645\u0642\u0627\u06cc\u0633\u0647 \u0645\u0635\u0631\u0641 \u06a9\u0627\u0631\u0628\u0631\u0627\u0646">Statistics & inbound comparison</div></div></div>
      <div class="grid-2" style="margin-bottom:14px">
        <div class="card">
          <div class="sl-item"><span class="sl-k" data-en="Total Traffic" data-fa="\u06a9\u0644 \u062a\u0631\u0627\u0641\u06cc\u06a9">Total Traffic</span><span class="sl-v" id="t-tr">--</span></div>
          <div class="sl-item"><span class="sl-k" data-en="Total Requests" data-fa="\u06a9\u0644 \u062f\u0631\u062e\u0648\u0627\u0633\u062a\u200c\u0647\u0627">Total Requests</span><span class="sl-v" id="t-rq">--</span></div>
          <div class="sl-item"><span class="sl-k" data-en="Uptime" data-fa="\u0622\u067e\u062a\u0627\u06cc\u0645">Uptime</span><span class="sl-v" id="t-up">--</span></div>
        </div>
        <div class="card">
          <div class="card-hd"><div class="card-title" data-en="Inbound Traffic Share" data-fa="\u0633\u0647\u0645 \u062a\u0631\u0627\u0641\u06cc\u06a9 \u06a9\u0627\u0631\u0628\u0631\u0627\u0646">Inbound Traffic Share</div></div>
          <div class="chart-container"><canvas id="inbound-chart"></canvas></div>
        </div>
      </div>
      <div class="card">
        <div class="card-hd"><div class="card-title" data-en="Daily Traffic" data-fa="\u062a\u0631\u0627\u0641\u06cc\u06a9 \u0631\u0648\u0632\u0627\u0646\u0647">Daily Traffic</div></div>
        <div class="chart-container" style="height:240px"><canvas id="daily-chart"></canvas></div>
      </div>
    </section>
  </main>

  <!-- Bottom Nav (Mobile) -->
  <div class="bottom-nav">
    <div class="bottom-nav-inner">
      <div class="bn-item active" data-page="dashboard" onclick="switchPage('dashboard')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
        <span data-en="Home" data-fa="\u062e\u0627\u0646\u0647">Home</span>
      </div>
      <div class="bn-item" data-page="inbounds" onclick="switchPage('inbounds')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/></svg>
        <span data-en="Inbounds" data-fa="\u0627\u06cc\u0646\u0628\u0627\u0646\u062f\u0647\u0627">Inbounds</span>
      </div>
      <div class="bn-item" data-page="traffic" onclick="switchPage('traffic')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        <span data-en="Traffic" data-fa="\u062a\u0631\u0627\u0641\u06cc\u06a9">Traffic</span>
      </div>
      <div class="bn-item" onclick="toggleTheme()" id="theme-btn-mob">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
        <span data-en="Theme" data-fa="\u067e\u0648\u0633\u062a\u0647">Theme</span>
      </div>
      <div class="bn-item" onclick="doLogout()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        <span data-en="Logout" data-fa="\u062e\u0631\u0648\u062c">Logout</span>
      </div>
    </div>
  </div>
</div>

<!-- Modals -->
<div class="mo" id="mo-add" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-add').classList.remove('show')">&#10005;</button>
    <div class="mo-title" data-en="ADD INBOUND" data-fa="\u0627\u0641\u0632\u0648\u062f\u0646 \u0627\u06cc\u0646\u0628\u0627\u0646\u062f">ADD INBOUND</div>
    <div class="fg"><label class="fl" data-en="Remark" data-fa="\u062a\u0648\u0636\u06cc\u062d">Remark</label><input class="fi" id="nl" data-ph-en="e.g. User 1" data-ph-fa="\u0645\u062b\u0644\u0627\u064b \u06a9\u0627\u0631\u0628\u0631 \u06f1" placeholder="e.g. User 1"></div>
    <div class="fr">
      <div class="fg"><label class="fl" data-en="Traffic Limit" data-fa="\u0645\u062d\u062f\u0648\u062f\u06cc\u062a \u062a\u0631\u0627\u0641\u06cc\u06a9">Traffic Limit</label><input class="fi" id="nv" type="number" min="0" step=".1" data-ph-en="0 = \u221e" data-ph-fa="\u06f0 = \u0646\u0627\u0645\u062d\u062f\u0648\u062f" placeholder="0 = \u221e"></div>
      <div class="fg" style="max-width:100px"><label class="fl" data-en="Unit" data-fa="\u0648\u0627\u062d\u062f">Unit</label><select class="fs" id="nu"><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl" data-en="Max Connections" data-fa="\u062d\u062f\u0627\u06a9\u062b\u0631 \u0627\u062a\u0635\u0627\u0644">Max Connections</label><input class="fi" id="nc" type="number" min="0" data-ph-en="0 = \u221e" data-ph-fa="\u06f0 = \u0646\u0627\u0645\u062d\u062f\u0648\u062f" placeholder="0 = \u221e"></div>
    <div class="fg"><label class="fl" data-en="Days Valid" data-fa="\u0631\u0648\u0632\u0647\u0627\u06cc \u0627\u0639\u062a\u0628\u0627\u0631">Days Valid</label><input class="fi" id="nd" type="number" min="0" data-ph-en="0 = No expiry" data-ph-fa="\u06f0 = \u0628\u062f\u0648\u0646 \u0627\u0646\u0642\u0636\u0627" placeholder="0 = No expiry"></div>
    <button class="btn btn-accent" onclick="createLink()" style="width:100%;justify-content:center;margin-top:12px;padding:12px" data-en="CREATE" data-fa="\u0627\u06cc\u062c\u0627\u062f">CREATE</button>
  </div>
</div>

<div class="mo" id="mo-edit" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box">
    <button class="mo-close" onclick="document.getElementById('mo-edit').classList.remove('show')">&#10005;</button>
    <div class="mo-title" id="et" data-en="EDIT INBOUND" data-fa="\u0648\u06cc\u0631\u0627\u06cc\u0634 \u0627\u06cc\u0646\u0628\u0627\u0646\u062f">EDIT INBOUND</div>
    <input type="hidden" id="eu">
    <div class="fg"><label class="fl" data-en="Name" data-fa="\u0646\u0627\u0645">Name</label><input class="fi" id="en2" readonly style="opacity:.5;cursor:not-allowed"></div>
    <div class="fr">
      <div class="fg"><label class="fl" data-en="Traffic Limit" data-fa="\u0645\u062d\u062f\u0648\u062f\u06cc\u062a \u062a\u0631\u0627\u0641\u06cc\u06a9">Traffic Limit</label><input class="fi" id="el" type="number" min="0" step=".1" data-ph-en="0 = \u221e" data-ph-fa="\u06f0 = \u0646\u0627\u0645\u062d\u062f\u0648\u062f" placeholder="0 = \u221e"></div>
      <div class="fg" style="max-width:100px"><label class="fl" data-en="Unit" data-fa="\u0648\u0627\u062d\u062f">Unit</label><select class="fs" id="eu2"><option>GB</option></select></div>
    </div>
    <div class="fg"><label class="fl" data-en="Max Connections" data-fa="\u062d\u062f\u0627\u06a9\u062b\u0631 \u0627\u062a\u0635\u0627\u0644">Max Connections</label><input class="fi" id="ec" type="number" min="0" data-ph-en="0 = \u221e" data-ph-fa="\u06f0 = \u0646\u0627\u0645\u062d\u062f\u0648\u062f" placeholder="0 = \u221e"></div>
    <div class="fg"><label class="fl" data-en="Extend Days" data-fa="\u0627\u0641\u0632\u0627\u06cc\u0634 \u0631\u0648\u0632\u0647\u0627">Extend Days</label><input class="fi" id="ed" type="number" min="0" data-ph-en="0 = no change" data-ph-fa="\u06f0 = \u0628\u062f\u0648\u0646 \u062a\u063a\u06cc\u06cc\u0631" placeholder="0 = no change"></div>
    <div style="display:flex;gap:10px;margin-top:16px">
      <button class="btn btn-accent" onclick="saveEdit()" style="flex:1;justify-content:center;padding:12px" data-en="SAVE" data-fa="\u0630\u062e\u06cc\u0631\u0647">SAVE</button>
      <button class="btn btn-danger" onclick="resetTraf()" style="padding:12px" data-en="Reset" data-fa="\u0628\u0627\u0632\u0646\u0634\u0627\u0646\u06cc \u062a\u0631\u0627\u0641\u06cc\u06a9">Reset</button>
    </div>
  </div>
</div>

<div class="mo" id="mo-qr" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="mo-box" style="max-width:340px">
    <button class="mo-close" onclick="document.getElementById('mo-qr').classList.remove('show')">&#10005;</button>
    <div class="mo-title" data-en="QR CODE" data-fa="\u06a9\u062f QR">QR CODE</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR"></div>
    <div style="display:flex;gap:10px;margin-top:16px;justify-content:center">
      <button class="btn btn-accent btn-sm" onclick="dlQR()" style="padding:10px 16px" data-en="Download" data-fa="\u062f\u0627\u0646\u0644\u0648\u062f">Download</button>
      <button class="btn btn-ghost btn-sm" onclick="document.getElementById('mo-qr').classList.remove('show')" style="padding:10px 16px" data-en="Close" data-fa="\u0628\u0633\u062a\u0646">Close</button>
    </div>
  </div>
</div>

<script>
function $(s){return document.querySelector(s);}
function $m(id){return document.getElementById(id);}
function esc(s){return String(s).replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

const langMap={
  en:{edit:'Edit',copy:'Copy',sub:'Sub',qr:'QR',del:'Del'},
  fa:{edit:'\u0648\u06cc\u0631\u0627\u06cc\u0634',copy:'\u06a9\u067e\u06cc',sub:'\u0627\u0634\u062a\u0631\u0627\u06a9',qr:'QR',del:'\u062d\u0630\u0641'}
};
function tr(key){return(langMap[lang]&&langMap[lang][key])||langMap['en'][key]||key;}

let lang=localStorage.getItem('p_lang')||'en';
let theme=localStorage.getItem('p_theme')||'dark';
let allLinks=[];
let cf='all';
let sData={};
let tChart=null;
let iChart=null;
let dChart=null;
let isAuthenticated=false;
let defaultPort=443;

// Theme
function setTheme(t){
  theme=t;
  if(t==='light')document.body.classList.add('light-mode');
  else document.body.classList.remove('light-mode');
  localStorage.setItem('p_theme',t);
  const mb=$m('theme-btn-mob');
  const db=$m('theme-btn-desk');
  if(mb)mb.querySelector('span').textContent=lang==='fa'?(t==='light'?'\u0631\u0648\u0634\u0646':'\u062a\u0627\u0631\u06cc\u06a9'):(t==='light'?'Light':'Dark');
  if(db){
    db.querySelector('svg').innerHTML=t==='light'
      ?'<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>'
      :'<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
  }
  updChartColors();
}
function toggleTheme(){setTheme(theme==='dark'?'light':'dark');}

// Lang
function toggleLang(){setLang(lang==='en'?'fa':'en');}
function setLang(l){
  lang=l;
  document.body.dir=l==='fa'?'rtl':'ltr';
  document.querySelectorAll('[data-en]').forEach(el=>{
    const v=el.getAttribute('data-'+l);
    if(v)el.textContent=v;
  });
  document.querySelectorAll('[data-ph-en]').forEach(el=>{
    const v=el.getAttribute('data-ph-'+l);
    if(v)el.placeholder=v;
  });
  localStorage.setItem('p_lang',l);
  filterLinks();
  setTheme(theme);
}

// Auth
async function checkAuth(){
  try{
    const r=await fetch('/api/dashboard');
    if(r.ok){showDashboard();}else{showLogin();}
  }catch(e){showLogin();}
}
function showLogin(){isAuthenticated=false;$m('login-page').style.display='';$m('dashboard-page').style.display='none';}
function showDashboard(){
  isAuthenticated=true;$m('login-page').style.display='none';$m('dashboard-page').style.display='';
  initChart();loadStats();loadLinks();
}
async function doLogin(){
  const pw=$m('login-pw').value;$m('login-err').style.display='none';
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
    if(r.ok){$m('login-pw').value='';showDashboard();}else{$m('login-err').style.display='block';}
  }catch(e){$m('login-err').style.display='block';}
}
async function doLogout(){await fetch('/api/logout',{method:'POST'});showLogin();}

// Navigation
document.querySelectorAll('.nav-item[data-page]').forEach(el=>{el.addEventListener('click',()=>switchPage(el.dataset.page));});
function switchPage(id){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  const target=$m('page-'+id);if(target)target.classList.add('active');
  document.querySelectorAll('.nav-item[data-page]').forEach(n=>n.classList.toggle('active',n.dataset.page===id));
  document.querySelectorAll('.bn-item[data-page]').forEach(n=>n.classList.toggle('active',n.dataset.page===id));
}

// Toast
function toast(msg,err){const t=$m('toast');t.textContent=msg;t.className='toast'+(err?' err':'')+' show';clearTimeout(t._hide);t._hide=setTimeout(()=>t.classList.remove('show'),3000);}

// Format helpers
function fmtB(b){if(!b||b===0)return'0 B';return b>=1073741824?(b/1073741824).toFixed(2)+' GB':b>=1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB';}
function fmtLim(b){if(!b||b===0)return'\u221e';const g=b/1073741824;return(g%1===0?g.toFixed(0):g.toFixed(1))+' GB';}
function fmtExp(ea){if(!ea||ea===0)return'\u221e';const d=new Date(ea)-new Date();if(d<=0)return'Expired';const days=Math.floor(d/86400000);if(days>0)return days+'d';const hours=Math.floor(d/3600000);if(hours>0)return hours+'h';return Math.floor(d/60000)+'m';}

// Links
function setFilter(filter,el){cf=filter;document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));if(el)el.classList.add('active');filterLinks();}
function filterLinks(){
  const q=($m('srch')?.value||'').toLowerCase();let r=allLinks;
  if(cf==='active')r=r.filter(l=>l.active);else if(cf==='off')r=r.filter(l=>!l.active);
  if(q)r=r.filter(l=>l.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));
  renderLinks(r);
}

function processAlertsAndCharts(){
  const alertsList=$m('alerts-list');const alertsBox=$m('alerts-box');alertsList.innerHTML='';let alertCount=0;
  allLinks.forEach(l=>{
    const u=l.used_bytes||0;const lim=l.limit_bytes||0;const pct=lim>0?(u/lim)*100:0;
    if(lim>0&&pct>=90){alertCount++;alertsList.innerHTML+='<div class="alert-item"><span style="font-weight:600">\ud83d\udd34 Inbound \''+esc(l.label)+'\' is near quota limit:</span><span>'+pct.toFixed(1)+'% Used</span></div>';}
    if(l.expires_at){const diff=new Date(l.expires_at)-new Date();const days=diff/86400000;if(days>0&&days<=3){alertCount++;alertsList.innerHTML+='<div class="alert-item"><span style="font-weight:600">\ud83d\udfe1 Inbound \''+esc(l.label)+'\' will expire soon:</span><span>'+days.toFixed(1)+' Days Left</span></div>';}}
  });
  alertsBox.style.display=alertCount>0?'block':'none';
  if(iChart){
    const sorted=[...allLinks].sort((a,b)=>(b.used_bytes||0)-(a.used_bytes||0)).slice(0,8);
    iChart.data.labels=sorted.map(x=>x.label);iChart.data.datasets[0].data=sorted.map(x=>Math.round((x.used_bytes||0)/(1024*1024)));iChart.update();
  }
}

function renderLinks(links){
  const tb=$m('ltb');const em=$m('lempty');const mc=$m('mcards');
  if(!links||!links.length){tb.innerHTML='';mc.innerHTML='';em.style.display='block';const emptyText=em.getAttribute('data-'+lang)||em.getAttribute('data-en')||'No inbounds found';em.textContent=emptyText;processAlertsAndCharts();return;}
  em.style.display='none';let idx=links.length;
  const rows=links.map(l=>{
    const u=l.used_bytes||0;const lim=l.limit_bytes||0;const pct=lim>0?Math.min(100,(u/lim)*100):0;
    const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--accent2)';const ex=fmtExp(l.expires_at);
    const ec=ex==='Expired'?'var(--red)':ex==='\u221e'?'var(--text3)':'var(--text2)';const i=idx--;
    const cc=l.current_connections||0;const mc2=l.max_connections||0;
    return{l,pct,col,ex,ec,i,cc,mc2,u,lim};
  });
  const editText=tr('edit');const copyText=tr('copy');const subText=tr('sub');const qrText=tr('qr');const delText=tr('del');
  tb.innerHTML=rows.map(r=>'<tr><td style="color:var(--text3);font-size:10.5px">'+r.i+'</td><td style="font-weight:600">'+esc(r.l.label)+'</td><td><span class="tag tag-vless">VLESS</span></td><td><div class="pill"><span class="pill-used">'+fmtB(r.u)+'</span><div class="pill-bar"><div class="pill-fill" style="width:'+r.pct+'%;background:'+r.col+'"></div></div><span class="pill-lim">'+fmtLim(r.lim)+'</span></div></td><td style="font-size:11px;font-weight:600;color:'+(r.mc2>0&&r.cc>=r.mc2?'var(--red)':'var(--text2)')+'">'+r.cc+'/'+(r.mc2||'\u221e')+'</td><td style="font-size:10.5px;font-weight:700;color:'+r.ec+'">'+r.ex+'</td><td><span class="tag '+(r.l.active?'tag-on':'tag-off')+'">'+(r.l.active?'On':'Off')+'</span></td><td><div style="display:flex;gap:3px;align-items:center;flex-wrap:wrap"><button class="toggle '+(r.l.active?'on':'')+'" data-uid="'+r.l.uuid+'" onclick="togLink(this)"></button><button class="act-btn act-edit" onclick="showEditMo(\''+r.l.uuid+'\')">'+editText+'</button><button class="act-btn act-copy" onclick="cpLink(\''+esc(r.l.vless_link||'')+'\')">'+copyText+'</button><button class="act-btn act-sub" onclick="cpSub(\''+r.l.uuid+'\')">'+subText+'</button><button class="act-btn act-qr" onclick="showQR(\''+esc(r.l.vless_link||'')+'\')">'+qrText+'</button><button class="act-btn act-del" onclick="delLink(\''+r.l.uuid+'\')">'+delText+'</button></div></td></tr>').join('');
  mc.innerHTML=rows.map(r=>'<div class="m-card"><div class="m-card-hd"><div style="display:flex;align-items:center;gap:7px"><span style="font-size:11px;color:var(--text3)">#'+r.i+'</span><span style="font-weight:600;font-size:14px">'+esc(r.l.label)+'</span><span class="tag tag-vless">VLESS</span></div><button class="toggle '+(r.l.active?'on':'')+'" data-uid="'+r.l.uuid+'" onclick="togLink(this)"></button></div><div class="pill"><span class="pill-used">'+fmtB(r.u)+'</span><div class="pill-bar"><div class="pill-fill" style="width:'+r.pct+'%;background:'+r.col+'"></div></div><span class="pill-lim">'+fmtLim(r.lim)+'</span></div><div style="font-size:11.5px;color:'+r.ec+';margin-top:6px;font-weight:600">\u23f3 '+r.ex+' \u00b7 '+r.cc+'/'+(r.mc2||'\u221e')+' Conn</div><div class="m-card-acts"><button class="act-btn act-edit" onclick="showEditMo(\''+r.l.uuid+'\')">'+editText+'</button><button class="act-btn act-copy" onclick="cpLink(\''+esc(r.l.vless_link||'')+'\')">'+copyText+'</button><button class="act-btn act-sub" onclick="cpSub(\''+r.l.uuid+'\')">'+subText+'</button><button class="act-btn act-qr" onclick="showQR(\''+esc(r.l.vless_link||'')+'\')">'+qrText+'</button><button class="act-btn act-del" onclick="delLink(\''+r.l.uuid+'\')">'+delText+'</button></div></div>').join('');
  processAlertsAndCharts();
}

async function togLink(el){
  const uid=el.dataset.uid;try{
    const r=await fetch('/api/links/'+uid+'/toggle',{method:'POST'});if(!r.ok)throw new Error();
    const d=await r.json();const l=allLinks.find(x=>x.uuid===uid);if(l)l.active=d.active;filterLinks();loadStats();
  }catch(e){toast('Failed to toggle',true);}
}

function showAddMo(){$m('mo-add').classList.add('show');}

async function createLink(){
  const label=$m('nl').value.trim()||'New Link';
  if(!/^[a-zA-Z0-9\-_. ]+$/.test(label)){toast('Only English letters allowed',true);return;}
  const v=parseFloat($m('nv').value)||0;const mc=parseInt($m('nc').value)||0;const days=parseInt($m('nd').value)||0;
  try{
    const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,limit_value:v,limit_unit:'GB',max_connections:mc,days_valid:days})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Error');}
    toast('Created');$m('nl').value='';$m('nv').value='';$m('nc').value='';$m('nd').value='';$m('mo-add').classList.remove('show');await loadLinks();await loadStats();
  }catch(e){toast(e.message||'Error creating link',true);}
}

function showEditMo(uid){
  const l=allLinks.find(x=>x.uuid===uid);if(!l)return;
  $m('eu').value=uid;$m('en2').value=l.label;$m('el').value=l.limit_bytes>0?(l.limit_bytes/1073741824):'';
  $m('ec').value=l.max_connections>0?l.max_connections:'';$m('ed').value='';
  $m('et').textContent=(lang==='fa'?'\u0648\u06cc\u0631\u0627\u06cc\u0634: ':'EDIT: ')+l.label;$m('mo-edit').classList.add('show');
}

async function saveEdit(){
  const uid=$m('eu').value;const v=parseFloat($m('el').value)||0;const mc=parseInt($m('ec').value)||0;const days=parseInt($m('ed').value)||0;
  const body={limit_value:v,limit_unit:'GB',max_connections:mc};if(days>0)body.days_valid=days;
  try{
    const r=await fetch('/api/links/'+uid,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!r.ok)throw new Error();toast('Updated');$m('mo-edit').classList.remove('show');await loadLinks();
  }catch(e){toast('Error updating',true);}
}

async function resetTraf(){
  const uid=$m('eu').value;if(!confirm('Reset traffic for this inbound?'))return;
  try{const r=await fetch('/api/links/'+uid+'/reset',{method:'POST'});if(!r.ok)throw new Error();toast('Traffic reset');await loadLinks();}catch(e){toast('Error resetting',true);}
}

async function delLink(uid){
  if(!confirm('Delete this inbound?'))return;
  try{const r=await fetch('/api/links/'+uid,{method:'DELETE'});if(!r.ok)throw new Error();toast('Deleted');await loadLinks();await loadStats();}catch(e){toast('Error deleting',true);}
}

function cpLink(txt){if(!txt){toast('No link to copy',true);return;}navigator.clipboard.writeText(txt).then(()=>toast('Copied!')).catch(()=>toast('Failed to copy',true));}

async function cpSub(uid){
  try{const r=await fetch('/api/links/'+uid+'/sub');if(!r.ok)throw new Error();const d=await r.json();await navigator.clipboard.writeText(d.sub_url);toast('Sub URL copied!');}catch(e){toast('Failed to copy',true);}
}

function showQR(txt){if(!txt){toast('No QR data',true);return;}$m('qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(txt);$m('mo-qr').classList.add('show');}
function dlQR(){const a=document.createElement('a');a.href=$m('qr-img').src;a.download='qr.png';a.click();}

// Stats API
async function loadStats(){
  try{
    const r=await fetch('/api/dashboard');if(r.status===401){showLogin();return;}if(!r.ok)throw new Error();sData=await r.json();
    $m('sv-traffic').innerHTML=(sData.total_traffic_mb||0)+'<span class="stat-unit"> MB</span>';
    $m('sv-links').textContent=sData.links_count||0;$m('sv-uptime').textContent=sData.uptime||'--:--:--';
    $m('sv-domain').textContent=sData.domain||'--';$m('last-up').textContent='Updated '+new Date().toLocaleTimeString();
    if($m('t-tr'))$m('t-tr').textContent=(sData.total_traffic_mb||0)+' MB';
    if($m('t-rq'))$m('t-rq').textContent=(sData.total_requests||0).toLocaleString();
    if($m('t-up'))$m('t-up').textContent=sData.uptime||'--:--:--';
    if(sData.cpu_percent!==undefined&&sData.cpu_percent>0){
      const c=sData.cpu_percent;const cc=c>80?'var(--red)':c>50?'var(--yellow)':'var(--accent2)';
      $m('cpu-v').textContent=c.toFixed(1)+'%';$m('cpu-v').style.color=cc;$m('cpu-b').style.width=c+'%';$m('cpu-b').style.background=cc;
    }else{$m('cpu-v').textContent='N/A';}
    if(sData.memory_percent!==undefined&&sData.memory_percent>0){
      const m=sData.memory_percent;const mc2=m>80?'var(--red)':m>50?'var(--yellow)':'var(--green)';
      $m('mem-v').textContent=m.toFixed(1)+'%';$m('mem-v').style.color=mc2;$m('mem-b').style.width=m+'%';$m('mem-b').style.background=mc2;
    }else{$m('mem-v').textContent='N/A';}
    updChart();updDailyChart();
  }catch(e){}
}

async function loadLinks(){
  try{const r=await fetch('/api/links');if(r.status===401){showLogin();return;}if(!r.ok)throw new Error();const d=await r.json();allLinks=d.links||[];filterLinks();}catch(e){}
}

// Chart
function initChart(){
  const ctx=$m('tc');if(!ctx||tChart)return;
  tChart=new Chart(ctx,{type:'bar',data:{labels:[],datasets:[{label:'MB',data:[],backgroundColor:'rgba(139,92,246,0.55)',borderColor:'#8B5CF6',borderWidth:1,borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:'rgba(139,92,246,0.3)',font:{size:10}}},y:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'rgba(139,92,246,0.3)',font:{size:10},callback:v=>v+' MB'},beginAtZero:true}}}});
  const ctx2=$m('inbound-chart');if(ctx2&&!iChart){iChart=new Chart(ctx2,{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:['#8B5CF6','#4ade80','#fbbf24','#f87171','#38bdf8','#ec4899','#f43f5e','#A78BFA'],borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:true,position:'right',labels:{color:'rgba(255,255,255,0.6)',font:{size:10}}}}}});}
  const ctx3=$m('daily-chart');if(ctx3&&!dChart){dChart=new Chart(ctx3,{type:'line',data:{labels:[],datasets:[{label:'MB',data:[],borderColor:'#8B5CF6',backgroundColor:'rgba(139,92,246,0.1)',fill:true,tension:0.4,pointRadius:3,pointBackgroundColor:'#8B5CF6',borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:'rgba(139,92,246,0.3)',font:{size:10}}},y:{grid:{color:'rgba(255,255,255,0.04)'},ticks:{color:'rgba(139,92,246,0.3)',font:{size:10},callback:v=>v+' MB'},beginAtZero:true}}}});}
  updChartColors();
}
function updChartColors(){
  if(!tChart)return;const col=theme==='light'?'rgba(0,0,0,0.5)':'rgba(139,92,246,0.4)';const gridCol=theme==='light'?'rgba(0,0,0,0.08)':'rgba(255,255,255,0.06)';
  tChart.options.scales.x.ticks.color=col;tChart.options.scales.y.ticks.color=col;tChart.options.scales.y.grid.color=gridCol;tChart.update();
  if(dChart){dChart.options.scales.x.ticks.color=col;dChart.options.scales.y.ticks.color=col;dChart.options.scales.y.grid.color=gridCol;dChart.update();}
}
function updChart(){if(!tChart||!sData.hourly_traffic)return;const entries=Object.entries(sData.hourly_traffic).sort((a,b)=>a[0].localeCompare(b[0])).slice(-12);tChart.data.labels=entries.map(x=>x[0]);tChart.data.datasets[0].data=entries.map(x=>Math.round(x[1]/1048576));tChart.update();}
function updDailyChart(){if(!dChart||!sData.daily_traffic)return;const entries=Object.entries(sData.daily_traffic).sort((a,b)=>a[0].localeCompare(b[0])).slice(-14);dChart.data.labels=entries.map(x=>x[0]);dChart.data.datasets[0].data=entries.map(x=>Math.round(x[1]/1048576));dChart.update();}

// Init
setTheme(theme);setLang(lang);checkAuth();
let statsInterval=null;
function startPolling(){if(statsInterval)clearInterval(statsInterval);statsInterval=setInterval(()=>{if(isAuthenticated){loadStats();loadLinks();}},12000);}
startPolling();
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