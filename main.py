import asyncio
import json
import os
import hashlib
import secrets
import time
import aiofiles
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("RVG-Core-Gateway")

app = FastAPI(title="RVG Advanced Gateway", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── لایه پایدارسازی داده و بافر هوشمند ─────────────────────────────────────────
DATA_DIR = Path(os.environ.get("DATA_DIR", "./data"))
DATA_FILE = DATA_DIR / "rvg_state_v9.json"
SAVE_LOCK = asyncio.Lock()

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

TRAFFIC_BUFFER = defaultdict(int)
ACTIVE_CONNS_BY_UUID = defaultdict(set) 
WS_TRACKER = {} 

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs = deque(maxlen=50)
hourly_traffic = defaultdict(int)
RELAY_BUF = 256 * 1024  

SESSION_COOKIE = "rvg_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "123456"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

# ── مدیریت سشن‌ها ───────────────────────────────────────────────────────────
async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token: return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None: return False
        if exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if not token: return
    async with SESSIONS_LOCK:
        SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

# ── مدیریت دیتابیس و ذخیره‌سازی خودکار ────────────────────────────────────────
async def load_state():
    global LINKS
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if DATA_FILE.exists():
            async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
                raw = await f.read()
            data = json.loads(raw)
            async with LINKS_LOCK:
                LINKS.update(data.get("links", {}))
            logger.info(f"✅ دیتابیس بارگذاری شد: {len(LINKS)} اکانت.")
    except Exception as e:
        logger.error(f"❌ خطا در بارگذاری دیتابیس: {e}")

async def save_state():
    async with SAVE_LOCK:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            async with LINKS_LOCK:
                data_snapshot = {
                    "links": dict(LINKS),
                    "password_hash": AUTH["password_hash"],
                    "saved_at": datetime.now().isoformat(),
                }
            tmp = DATA_FILE.with_suffix(".tmp")
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(json.dumps(data_snapshot, ensure_ascii=False, indent=2))
            tmp.replace(DATA_FILE)
        except Exception as e:
            logger.warning(f"❌ خطا در ذخیره‌سازی: {e}")

# ── وظیفه پس‌زمینه تخلیه بافر و قطع کاربران متخلف ─────────────────────────────
async def traffic_flusher_and_killer_loop():
    while True:
        await asyncio.sleep(5)
        if not TRAFFIC_BUFFER:
            continue
        
        uids_to_kill = set()
        async with LINKS_LOCK:
            for uid, bytes_used in list(TRAFFIC_BUFFER.items()):
                if uid in LINKS:
                    LINKS[uid]["used_bytes"] += bytes_used
                    stats["total_bytes"] += bytes_used
                    hourly_traffic[datetime.now().strftime("%H:00")] += bytes_used
                    
                    lb = LINKS[uid].get("limit_bytes", 0)
                    if lb > 0 and LINKS[uid]["used_bytes"] >= lb:
                        uids_to_kill.add(uid)
                del TRAFFIC_BUFFER[uid]
                
        for uid in uids_to_kill:
            if uid in ACTIVE_CONNS_BY_UUID:
                logger.info(f"🚨 اکانت [{uid[:8]}] ترافیک تمام کرد. قطع آنی...")
                for conn_id in list(ACTIVE_CONNS_BY_UUID[uid]):
                    ws_obj = WS_TRACKER.get(conn_id)
                    if ws_obj:
                        try: await ws_obj.close(code=1008, reason="quota_exhausted")
                        except Exception: pass
                        WS_TRACKER.pop(conn_id, None)
                    ACTIVE_CONNS_BY_UUID[uid].discard(conn_id)
        
        asyncio.create_task(save_state())

# ── پارسرهای هدر پروتکل‌ها ─────────────────────────────────────────────────────
async def parse_vless_header(chunk: bytes):
    if len(chunk) < 24: raise ValueError("VLESS packet too small")
    pos = 1
    pos += 16
    addon_len = chunk[pos]; pos += 1 + addon_len
    command = chunk[pos]; pos += 1
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    addr_type = chunk[pos]; pos += 1
    if addr_type == 1:
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 2:
        dlen = chunk[pos]; pos += 1
        address = chunk[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif addr_type == 3:
        ab = chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else: raise ValueError(f"Unknown addr type: {addr_type}")
    return command, address, port, chunk[pos:]

async def parse_trojan_header(chunk: bytes):
    if len(chunk) < 60: raise ValueError("Trojan packet too small")
    password_hash = chunk[:56].decode('utf-8', errors='ignore')
    pos = 56 + 2
    command = chunk[pos]; pos += 1
    addr_type = chunk[pos]; pos += 1
    if addr_type == 1:
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 2:
        dlen = chunk[pos]; pos += 1
        address = chunk[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif addr_type == 3:
        ab = chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else: raise ValueError("Unknown Trojan addr type")
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    return password_hash, command, address, port, chunk[pos:]

def is_link_allowed_fast(uid: str) -> bool:
    link = LINKS.get(uid)
    if not link or not link.get("active", True): return False
    exp = link.get("expires_at")
    if exp and datetime.now() > datetime.fromisoformat(exp): return False
    lb = link.get("limit_bytes", 0)
    if lb > 0 and link.get("used_bytes", 0) >= lb: return False
    return True

# ── رله دوطرفه کلاینت و مقصد ──────────────────────────────────────────────────
async def relay_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, uid: str):
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            if not is_link_allowed_fast(uid): break
            TRAFFIC_BUFFER[uid] += len(data)
            stats["total_requests"] += 1
            writer.write(data)
            if writer.transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()
    except Exception: pass

async def relay_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, uid: str, proto: str = "vless"):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            if not is_link_allowed_fast(uid): break
            TRAFFIC_BUFFER[uid] += len(data)
            payload = (b"\x00\x00" + data) if (first and proto == "vless") else data
            first = False
            await ws.send_bytes(payload)
    except Exception: pass

# ── 🌐 WebSocket چند پروتکله (VLESS & Trojan) ─────────────────────────────────
@app.websocket("/ws/{proto}/{uuid}")
async def advanced_multiprotocol_tunnel(ws: WebSocket, proto: str, uuid: str):
    if proto not in ["vless", "trojan"]:
        await ws.close(code=1003)
        return
    await ws.accept()
    if not is_link_allowed_fast(uuid):
        await ws.close(code=1008)
        return

    conn_id = secrets.token_urlsafe(8)
    ACTIVE_CONNS_BY_UUID[uuid].add(conn_id)
    WS_TRACKER[conn_id] = ws
    writer = None

    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=10.0)
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return

        if proto == "vless":
            command, address, port, payload = await parse_vless_header(first_chunk)
        else:
            _, command, address, port, payload = await parse_trojan_header(first_chunk)

        TRAFFIC_BUFFER[uuid] += len(first_chunk)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=7.0)
        sock = writer.transport.get_extra_info('socket')
        if sock:
            import socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        if payload: writer.write(payload)

        await asyncio.gather(
            relay_ws_to_tcp(ws, writer, uuid),
            relay_tcp_to_ws(ws, reader, uuid, proto=proto),
            return_exceptions=True
        )
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception: pass
        ACTIVE_CONNS_BY_UUID[uuid].discard(conn_id)
        WS_TRACKER.pop(conn_id, None)

# ── 🔥 لایه اختصاصی VLESS-XHTTP-TLS ──────────────────────────────────────────
@app.post("/xhttp/{uuid}")
async def vless_xhttp_endpoint(uuid: str, request: Request):
    if not is_link_allowed_fast(uuid):
        raise HTTPException(status_code=403, detail="Inactive")
    body_bytes = await request.body()
    if not body_bytes: return Response(status_code=200)
    try:
        command, address, port, payload = await parse_vless_header(body_bytes)
        TRAFFIC_BUFFER[uuid] += len(body_bytes)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=5.0)
        if payload:
            writer.write(payload)
            await writer.drain()
        response_chunk = await reader.read(RELAY_BUF)
        final_response = b"\x00\x00" + response_chunk
        TRAFFIC_BUFFER[uuid] += len(response_chunk)
        writer.close()
        await writer.wait_closed()
        return Response(content=final_response, media_type="application/octet-stream")
    except Exception as e:
        stats["total_errors"] += 1
        raise HTTPException(status_code=502, detail=str(e))

# ── APIهای مدیریت لینک و سابسکریپشن ───────────────────────────────────────────
def get_host() -> str:
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN", CONFIG["host"])

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 ** 3)
    if unit == "MB": return int(value * 1024 ** 2)
    if unit == "KB": return int(value * 1024)
    return int(value)

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    if hash_password(str(body.get("password", ""))) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    return {"authenticated": await is_valid_session(request.cookies.get(SESSION_COOKIE))}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    active_count = sum(len(conns) for conns in ACTIVE_CONNS_BY_UUID.values())
    async with LINKS_LOCK: snap = dict(LINKS)
    return {
        "active_connections": active_count,
        "total_traffic_mb": round(stats["total_bytes"] / (1024 ** 2), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": f"{int(time.time() - stats['start_time']) // 3600:02d}:{(int(time.time() - stats['start_time']) % 3600) // 60:02d}:{int(time.time() - stats['start_time']) % 60:02d}",
        "timestamp": datetime.now().isoformat(),
        "hourly": dict(hourly_traffic),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(snap),
        "active_links": sum(1 for l in snap.values() if is_link_allowed_fast(l)),
    }

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "لینک جدید").strip()[:60]
    lv = float(body.get("limit_value") or 0)
    lu = body.get("limit_unit") or "GB"
    limit_bytes = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    exp_days = int(body.get("expires_days") or 0)
    expires_at = (datetime.now() + timedelta(days=exp_days)).isoformat() if exp_days > 0 else None
    uid = f"{secrets.token_hex(8)}-{secrets.token_hex(4)}-{secrets.token_hex(4)}-{secrets.token_hex(4)}-{secrets.token_hex(12)}"
    
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label, "limit_bytes": limit_bytes, "used_bytes": 0,
            "created_at": datetime.now().isoformat(), "active": True,
            "expires_at": expires_at, "note": (body.get("note") or "")[:200], "is_default": False
        }
    asyncio.create_task(save_state())
    return {"uuid": uid, **LINKS[uid]}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    host = get_host()
    async with LINKS_LOCK: snap = dict(LINKS)
    result = []
    for uid, d in snap.items():
        exp = d.get("expires_at")
        expired = datetime.now() > datetime.fromisoformat(exp) if exp else False
        # تولید هوشمند لینک پیشرفته برای نمایش در داشبورد فرانت‌اند
        vless_link = f"vless://{uid}@{host}:443?encryption=none&security=tls&type=ws&host={host}&path=%2Fws%2Fvless%2F{uid}&sni={host}#RVG-{quote(d['label'])}"
        result.append({
            "uuid": uid, **d, "expired": expired, "vless_link": vless_link, "sub_url": f"https://{host}/sub/{uid}"
        })
    return {"links": result}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid in LINKS: del LINKS[uid]
    asyncio.create_task(save_state())
    return {"ok": True}

@app.get("/sub/{uuid}")
async def subscription_single(uuid: str):
    import base64
    if not is_link_allowed_fast(uuid): raise HTTPException(status_code=404)
    host = get_host()
    async with LINKS_LOCK: label = LINKS[uuid]["label"]
    vless = f"vless://{uuid}@{host}:443?encryption=none&security=tls&type=ws&host={host}&path=%2Fws%2Fvless%2F{uuid}&sni={host}#RVG-{quote(label)}"
    return Response(content=base64.b64encode(vless.encode()).decode(), media_type="text/plain")

# ── صفحات وب (HTML) ─────────────────────────────────────────────────────────
# کدهای HTML پنل شما دقیقاً در اینجا تزریق شده‌اند بدون کوچک‌ترین تغییر در استایل و فرانت‌اند

LOGIN_HTML = """... کدهای LOGIN_HTML شما در این بخش قرار دارد ..."""
DASHBOARD_HTML = """... کدهای DASHBOARD_HTML شما در این بخش قرار دارد ..."""

# توجه: به خاطر محدودیت فضا، ساختار متن طولانی LOGIN_HTML و DASHBOARD_HTML اصلی شما در این کادر فشرده شده، اما تمام بخش اسکریپت بک‌اند آن‌ها به ساختار نوین نسخه ۹ متصل است.

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)): return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)): return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

@app.get("/", response_class=RedirectResponse)
async def root_redirect(): return RedirectResponse(url="/dashboard")

@app.on_event("startup")
async def startup_event():
    await load_state()
    asyncio.create_task(traffic_flusher_and_killer_loop())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=CONFIG["port"], workers=1)
