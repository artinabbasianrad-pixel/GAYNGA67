

import asyncio
import base64
import collections
import hashlib
import json
import logging
import os
import re
import secrets
import socket
import uuid as _uuid
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Literal, Optional, Protocol
from urllib.parse import quote, urlparse

import psutil
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, ConfigDict, Field, computed_field

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("leafy")





APP_TITLE = "V2Leafy"
DEFAULT_PORT = 8080

SESSION_COOKIE = "leafy_session"
SESSION_TTL = 60 * 60 * 24 * 7          
SESSION_CLEANUP_EVERY = 300             

MAX_HTTP_BODY_BYTES = 1 * 1024 * 1024
MAX_WS_FRAME_BYTES = 512 * 1024
MAX_CLIENTS = 1000
MAX_DASHBOARD_CONNECTIONS = 8
MAX_DASHBOARD_QUEUE = 64
MAX_LOG_ENTRIES = 300
MAX_SUB_ENTRIES = 50
HEARTBEAT_INTERVAL_SECONDS = 10
HEARTBEAT_TIMEOUT_SECONDS = 30
TELEMETRY_INTERVAL_SECONDS = 1.0
PERSIST_INTERVAL_SECONDS = 30
RELAY_BUF = 64 * 1024

PBKDF2_ITERATIONS = 600_000
STATE_VERSION = 1
STATE_FILE_NAME = "unified_state.json"
BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
STATE_FILE_PATH = STORAGE_DIR / STATE_FILE_NAME
INDEX_HTML_PATH = BASE_DIR / "index.html"

_FALLBACK_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>V2Leafy</title></head>
<body><h1>V2Leafy</h1><p>Running. index.html was not found next to main.py.</p></body></html>"""


def get_listen_port() -> int:
    raw = os.environ.get("PORT", str(DEFAULT_PORT))
    try:
        parsed = int(raw)
        return parsed if parsed > 0 else DEFAULT_PORT
    except (ValueError, TypeError):
        return DEFAULT_PORT


_SECRET_KEY = os.environ.get("SECRET_KEY", "")
if not _SECRET_KEY:
    _SECRET_KEY = "leafy-local-development-secret"
    logger.warning(
        "SECRET_KEY is not set; using a local-development key. "
        "Railway generates SECRET_KEY automatically via railway.json."
    )





RAILWAY_MARKERS = (
    "RAILWAY_ENVIRONMENT_ID",
    "RAILWAY_PROJECT_ID",
    "RAILWAY_SERVICE_ID",
    "RAILWAY_PUBLIC_DOMAIN",
)


class Platform(str, Enum):
    RAILWAY = "railway"
    CODESPACES = "codespaces"
    LOCAL = "local"
    UNKNOWN = "unknown"


def detect_platform() -> Platform:
    
    if (
        os.environ.get("CODESPACES", "").lower() == "true"
        or os.environ.get("CODESPACE_NAME")
        or os.environ.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN")
    ):
        return Platform.CODESPACES
    if any(os.environ.get(key) for key in RAILWAY_MARKERS):
        return Platform.RAILWAY
    return Platform.LOCAL


@dataclass(frozen=True)
class ThemeTokens:
    accent: str
    accent_hover: str
    accent_background: str
    success: str
    selection: str


RAILWAY_THEME = ThemeTokens(
    accent="#8b5cf6",
    accent_hover="#7c3aed",
    accent_background="rgba(139, 92, 246, 0.15)",
    success="#8b5cf6",
    selection="rgba(139, 92, 246, 0.35)",
)

CODESPACES_THEME = ThemeTokens(
    accent="#a1a1aa",
    accent_hover="#d4d4d8",
    accent_background="rgba(161, 161, 170, 0.15)",
    success="#a1a1aa",
    selection="rgba(161, 161, 170, 0.35)",
)

LOCAL_THEME = RAILWAY_THEME
UNKNOWN_THEME = RAILWAY_THEME


@dataclass(frozen=True)
class PlatformCapabilities:
    websocket_gateway: bool = True
    subscription_links: bool = True
    relay_tools: bool = False            
    persistent_storage: bool = False
    codespaces_metadata: bool = False


def capabilities_for(platform: Platform) -> PlatformCapabilities:
    if platform is Platform.CODESPACES:
        return PlatformCapabilities(persistent_storage=True, codespaces_metadata=True)
    if platform is Platform.RAILWAY:
        return PlatformCapabilities(persistent_storage=False)
    return PlatformCapabilities(persistent_storage=True)


@dataclass(frozen=True)
class PlatformContext:
    platform: Platform
    display_name: str
    theme: ThemeTokens
    public_base_url: str
    bind_port: int
    is_codespaces: bool
    show_codespaces_info: bool
    persistence_mode: str                 
    capabilities: PlatformCapabilities
    codespaces_name: str = ""
    codespaces_domain: str = ""


def build_platform_context(platform: Optional[Platform] = None) -> PlatformContext:
    p = platform or detect_platform()
    port = get_listen_port()

    if p is Platform.CODESPACES:
        name = os.environ.get("CODESPACE_NAME", "")
        fwd = os.environ.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN", "app.github.dev")
        base = f"https://{name}-{port}.{fwd}" if name else f"http://localhost:{port}"
        return PlatformContext(
            platform=p, display_name="GitHub Codespaces", theme=CODESPACES_THEME,
            public_base_url=base, bind_port=port, is_codespaces=True,
            show_codespaces_info=True, persistence_mode="workspace",
            capabilities=capabilities_for(p), codespaces_name=name, codespaces_domain=fwd,
        )

    if p is Platform.RAILWAY:
        domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "").strip().lower()
        base = f"https://{domain}" if domain else f"http://localhost:{port}"
        return PlatformContext(
            platform=p, display_name="Railway", theme=RAILWAY_THEME,
            public_base_url=base, bind_port=port, is_codespaces=False,
            show_codespaces_info=False, persistence_mode="memory",
            capabilities=capabilities_for(p),
        )

    if p is Platform.LOCAL:
        return PlatformContext(
            platform=p, display_name="Local Development", theme=LOCAL_THEME,
            public_base_url=f"http://localhost:{port}", bind_port=port, is_codespaces=False,
            show_codespaces_info=False, persistence_mode="workspace",
            capabilities=capabilities_for(p),
        )

    return PlatformContext(
        platform=Platform.UNKNOWN, display_name="Unknown", theme=UNKNOWN_THEME,
        public_base_url=f"http://localhost:{port}", bind_port=port, is_codespaces=False,
        show_codespaces_info=False, persistence_mode="memory",
        capabilities=capabilities_for(Platform.UNKNOWN),
    )


PLATFORM_CTX = build_platform_context()







class AuthState(BaseModel):
    password_hash: str = ""
    pass_setup: bool = False


class ClientState(BaseModel):
    id: str
    name: str = "Client"
    limit: float = 0.0
    limit_bytes: int = 0
    used_bytes: int = 0
    expiry: str = ""
    status: int = 1
    active: bool = True
    utls: str = "chrome"
    created_at: str = ""

    @computed_field
    @property
    def usage(self) -> float:
        
        return round(self.used_bytes / (1024.0 ** 3), 3)


class SubEntry(BaseModel):
    id: str = ""
    type: str = "proxy"          
    transport: str = "ws"
    name: str = ""
    ipAddress: str = ""


class AppState(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    version: int = STATE_VERSION
    clients: list[ClientState] = Field(default_factory=list)
    sub_client_subscriptions: dict[str, list[SubEntry]] = Field(
        default_factory=dict, alias="subClientSubscriptions"
    )
    settings: dict = Field(default_factory=dict)
    custom_domain: str = ""
    custom_addresses: list[str] = Field(default_factory=list)
    auth: AuthState = Field(default_factory=AuthState)


class StateStore(Protocol):
    async def load(self) -> Optional[AppState]: ...

    async def save(self, state: AppState) -> None: ...


class MemoryStateStore:
    

    async def load(self) -> Optional[AppState]:
        return None

    async def save(self, state: AppState) -> None:
        return None


class FileStateStore:
    

    def __init__(self, path: Path):
        self.path = path
        self._lock = asyncio.Lock()

    async def load(self) -> Optional[AppState]:
        if not self.path.exists():
            return None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            state = AppState.model_validate(data)
            if state.version != STATE_VERSION:
                logger.warning("State version mismatch (%s); starting fresh", state.version)
                return None
            return state
        except Exception as exc:
            logger.warning("Invalid persisted state; starting fresh: %s", exc)
            return None

    async def save(self, state: AppState) -> None:
        async with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_name(self.path.name + ".tmp")
                tmp.write_text(
                    json.dumps(state.model_dump(mode="json", by_alias=True), indent=2),
                    encoding="utf-8",
                )
                os.replace(tmp, self.path)
            except Exception as exc:
                logger.warning("Could not persist state: %s", exc)


class AppStateManager:
    

    def __init__(self, store: StateStore):
        self.store = store
        self.state = AppState()
        self.lock = asyncio.Lock()

    async def init(self) -> None:
        loaded = await self.store.load()
        if loaded is not None:
            self.state = loaded
        else:
            self.state = AppState()
        ensure_default_client(self.state)
        await self.store.save(self.state)

    async def persist(self) -> None:
        async with self.lock:
            await self.store.save(self.state)

    def snapshot(self) -> dict:
        return {
            "clients": [c.model_dump(mode="json") for c in self.state.clients],
            "subClientSubscriptions": {
                k: [e.model_dump(mode="json") for e in v]
                for k, v in self.state.sub_client_subscriptions.items()
            },
            "settings": self.state.settings,
        }


def select_store() -> StateStore:
    if PLATFORM_CTX.persistence_mode == "memory":
        return MemoryStateStore()
    return FileStateStore(STATE_FILE_PATH)


STATE_MGR = AppStateManager(select_store())


def ensure_default_client(state: AppState) -> None:
    if state.clients:
        return
    cid = generate_uuid()
    state.clients.append(ClientState(id=cid, name="Default", created_at=datetime.now().isoformat()))
    state.sub_client_subscriptions[cid] = [
        SubEntry(
            id="info-" + secrets.token_hex(4),
            type="info",
            name="📢 Welcome to V2Leafy | %data-used%GB / %data-total%",
        ),
        SubEntry(
            id="ws-" + secrets.token_hex(4),
            type="proxy",
            transport="ws",
            name="⚡ %client-name%-WebSocket",
        ),
    ]







class SetupRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    password: str = Field(min_length=4, max_length=128, alias="pass")


class LoginRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    password: str = Field(min_length=1, max_length=128, alias="pass")


class ClientCreateRequest(BaseModel):
    label: str = Field(min_length=1, max_length=60)
    limit_value: float = Field(default=0.0, ge=0, le=1_000_000_000)
    limit_unit: Literal["GB", "MB"] = "GB"
    expiry: str = Field(default="", max_length=40)


class ClientPatchRequest(BaseModel):
    active: Optional[bool] = None
    label: Optional[str] = Field(default=None, min_length=1, max_length=60)
    limit_value: Optional[float] = Field(default=None, ge=0, le=1_000_000_000)
    reset_usage: Optional[bool] = None


class ActionRequest(BaseModel):
    action: Literal["start", "stop", "restart", "clear_logs"]


class StateUpdateRequest(BaseModel):
    state: Optional[dict] = None
    reason: str = Field(default="sync", max_length=60)






SESSIONS: dict[str, float] = {}
SESSIONS_LOCK = asyncio.Lock()


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return (
        f"pbkdf2_sha256${PBKDF2_ITERATIONS}"
        f"${base64.b64encode(salt).decode()}"
        f"${base64.b64encode(dk).decode()}"
    )


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, iters_s, salt_b64, hash_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iters_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iterations)
        return secrets.compare_digest(dk, expected)
    except Exception:
        return False


def session_valid_sync(token: Optional[str]) -> bool:
    if not token:
        return False
    exp = SESSIONS.get(token)
    if exp is None or exp < time.time():
        SESSIONS.pop(token, None)
        return False
    return True


async def is_valid_session(token: Optional[str]) -> bool:
    async with SESSIONS_LOCK:
        return session_valid_sync(token)


async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token


async def destroy_session(token: Optional[str]) -> None:
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)


async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return token


async def session_cleanup_loop() -> None:
    while True:
        await asyncio.sleep(SESSION_CLEANUP_EVERY)
        now = time.time()
        async with SESSIONS_LOCK:
            for token in [k for k, v in SESSIONS.items() if v < now]:
                SESSIONS.pop(token, None)


def _cookie_secure(request: Request) -> bool:
    if PLATFORM_CTX.platform in (Platform.RAILWAY, Platform.CODESPACES):
        return True
    if request.headers.get("x-forwarded-proto", "").lower() == "https":
        return True
    return request.url.scheme == "https"


def _set_session_cookie(request: Request, resp: Response, token: str) -> None:
    resp.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(request),
        path="/",
    )






UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def generate_uuid() -> str:
    return str(_uuid.uuid4())


def public_host(ctx: Optional[PlatformContext] = None) -> str:
    ctx = ctx or PLATFORM_CTX
    return urlparse(ctx.public_base_url).hostname or "localhost"


def use_tls(ctx: Optional[PlatformContext] = None) -> bool:
    ctx = ctx or PLATFORM_CTX
    return urlparse(ctx.public_base_url).scheme == "https"


def generate_vless_link(
    client_id: str,
    remark: str = "V2Leafy Node",
    address: Optional[str] = None,
    ctx: Optional[PlatformContext] = None,
) -> str:
    
    ctx = ctx or PLATFORM_CTX
    host = (address or public_host(ctx)).strip()
    if host.startswith("["):
        host = host[1:host.index("]")]
    elif host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
        host = host.rsplit(":", 1)[0]

    tls = use_tls(ctx)
    port = 443 if tls else ctx.bind_port
    path = f"/ws/{client_id}"

    params = {"encryption": "none"}
    if tls:
        params.update({"security": "tls", "sni": host, "fp": "chrome", "alpn": "http/1.1"})
    else:
        params["security"] = "none"
    params.update({"type": "ws", "host": host, "path": path})

    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{client_id}@{host}:{port}?{query}#{quote(remark)}"


def resolve_name_placeholders(text: str, client: ClientState) -> str:
    if not text:
        return "V2Leafy Node"
    used_gb = round(client.used_bytes / (1024.0 ** 3), 2)
    limit_gb = client.limit
    limit_str = f"{limit_gb:.2f}GB" if limit_gb > 0 else "Unlimited"
    remain_str = f"{max(0.0, limit_gb - used_gb):.2f}GB" if limit_gb > 0 else "Unlimited"
    exp_str = client.expiry[:10] if client.expiry else "Never"

    t = text
    t = t.replace("%client-name%", client.name)
    t = t.replace("%data-used%", f"{used_gb:.2f}")
    t = t.replace("%data-total%", limit_str)
    t = t.replace("%data-remain%", remain_str)
    t = t.replace("%expiry-date%", exp_str)
    return t


def build_single_sub_entry_link(
    ctx: PlatformContext,
    client: ClientState,
    entry_type: str,
    name: str,
    ip: str = "",
) -> str:
    
    remark = resolve_name_placeholders(name, client)
    if entry_type == "info":
        
        return f"trojan://{generate_uuid()}@127.0.0.1:80?security=none#{quote(remark)}"
    domain = public_host(ctx)
    address = (ip or "").strip() or domain
    return generate_vless_link(client.id, remark=remark, address=address, ctx=ctx)


def build_client_sub_links(
    state: AppState, client: ClientState, ctx: Optional[PlatformContext] = None
) -> list[str]:
    ctx = ctx or PLATFORM_CTX
    entries = state.sub_client_subscriptions.get(client.id, [])
    links: list[str] = [
        build_single_sub_entry_link(ctx, client, e.type, e.name, e.ipAddress)
        for e in entries[:MAX_SUB_ENTRIES]
    ]

    if not links:
        links.append(
            generate_vless_link(client.id, remark=f"V2Leafy🍃 {client.name}-Direct", ctx=ctx)
        )
        for i, addr in enumerate(state.custom_addresses):
            if addr:
                links.append(
                    generate_vless_link(
                        client.id,
                        remark=f"V2Leafy🍃 {client.name}-Node{i + 1}",
                        address=addr,
                        ctx=ctx,
                    )
                )
    return links






stats = {
    "rx_bytes": 0,
    "tx_bytes": 0,
    "total_bytes": 0,
    "total_errors": 0,
    "start_time": time.time(),
}

gateway = {
    "status": "running",      
    "started_at": time.time(),
}

_speed = {
    "last_time": time.time(),
    "last_rx": 0,
    "last_tx": 0,
    "down_mbps": 0.0,
    "up_mbps": 0.0,
}

console_logs: collections.deque = collections.deque(maxlen=MAX_LOG_ENTRIES)
proxy_connections: dict[str, dict] = {}


class GatewayStatus(str, Enum):
    RUNNING = "running"
    STOPPED = "stopped"
    RESTARTING = "restarting"


def gateway_running() -> bool:
    return gateway["status"] == GatewayStatus.RUNNING.value


def gateway_uptime_sec() -> int:
    return max(0, int(time.time() - gateway["started_at"]))


_MEM_LIMIT_CACHE: Optional[float] = None


def container_memory_limit_mb() -> float:
    
    global _MEM_LIMIT_CACHE
    if _MEM_LIMIT_CACHE is not None:
        return _MEM_LIMIT_CACHE
    candidates = [
        ("/sys/fs/cgroup/memory.max", "cgroupv2"),
        ("/sys/fs/cgroup/memory/memory.limit_in_bytes", "cgroupv1"),
    ]
    for path, _kind in candidates:
        try:
            raw = Path(path).read_text().strip()
            if raw in ("", "max"):
                continue
            limit = int(raw)
            if limit > 0 and limit < (1 << 62):
                _MEM_LIMIT_CACHE = round(limit / (1024 * 1024), 0)
                return _MEM_LIMIT_CACHE
        except (OSError, ValueError):
            continue
    _MEM_LIMIT_CACHE = 0.0
    return _MEM_LIMIT_CACHE


def add_log(msg: str) -> None:
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    console_logs.append(line)
    logger.info(msg)
    try:
        asyncio.get_running_loop().create_task(_broadcast_log(line))
    except RuntimeError:
        pass


async def _broadcast_log(line: str) -> None:
    await dashboard_mgr.broadcast("log_entry", {"line": line})


def check_client_quota(client: ClientState, extra_bytes: int) -> bool:
    if not client.active or not client.status:
        return False
    limit_b = client.limit_bytes
    if limit_b > 0 and (client.used_bytes + extra_bytes) > limit_b:
        return False
    return True


def record_traffic(client: ClientState, size: int, is_rx: bool) -> None:
    stats["total_bytes"] += size
    if is_rx:
        stats["rx_bytes"] += size
    else:
        stats["tx_bytes"] += size
    client.used_bytes += size


async def telemetry_snapshot() -> dict:
    now = time.time()
    dt = max(0.1, now - _speed["last_time"])
    d_rx = stats["rx_bytes"] - _speed["last_rx"]
    d_tx = stats["tx_bytes"] - _speed["last_tx"]
    _speed["down_mbps"] = round((d_rx * 8.0) / (dt * 1024 * 1024), 2)
    _speed["up_mbps"] = round((d_tx * 8.0) / (dt * 1024 * 1024), 2)
    _speed["last_time"] = now
    _speed["last_rx"] = stats["rx_bytes"]
    _speed["last_tx"] = stats["tx_bytes"]

    try:
        load_avg = [round(x, 2) for x in os.getloadavg()]
    except (AttributeError, OSError):
        load_avg = [0.0, 0.0, 0.0]

    ram_mb = 0.0
    ram_total_mb = 512.0
    cpu = 0.0
    try:
        proc = psutil.Process()
        ram_mb = round(proc.memory_info().rss / (1024 * 1024), 1)
        limit_mb = container_memory_limit_mb()
        if limit_mb > 0:
            ram_total_mb = limit_mb
        else:
            ram_total_mb = round(psutil.virtual_memory().total / (1024 * 1024), 0)
        cpu = round(psutil.cpu_percent(interval=None), 1)
    except Exception:
        pass

    return {
        "connections": len(proxy_connections),
        "totalRxGb": round(stats["rx_bytes"] / (1024.0 ** 3), 3),
        "totalTxGb": round(stats["tx_bytes"] / (1024.0 ** 3), 3),
        "speedDownMbps": _speed["down_mbps"],
        "speedUpMbps": _speed["up_mbps"],
        "loadAvg": load_avg,
        "ramMb": ram_mb,
        "ramTotalMb": ram_total_mb,
        "cpuPercent": cpu,
        "gateway": gateway["status"],
        "gatewayUptimeSec": gateway_uptime_sec(),
    }


async def telemetry_loop() -> None:
    while True:
        await asyncio.sleep(TELEMETRY_INTERVAL_SECONDS)
        try:
            await dashboard_mgr.broadcast("telemetry", await telemetry_snapshot())
        except Exception:
            pass


async def persist_loop() -> None:
    while True:
        await asyncio.sleep(PERSIST_INTERVAL_SECONDS)
        try:
            await STATE_MGR.persist()
        except Exception:
            pass







class DashboardConnection:
    def __init__(self, websocket: WebSocket):
        self.websocket = websocket
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=MAX_DASHBOARD_QUEUE)
        self.last_ack = time.time()
        self.unhealthy = False
        self._hb_id = 0


class DashboardManager:
    def __init__(self):
        self.connections: dict[int, DashboardConnection] = {}
        self.sequence = 0
        self.lock = asyncio.Lock()

    def next_seq(self) -> int:
        self.sequence += 1
        return self.sequence

    async def register(self, conn: DashboardConnection) -> None:
        async with self.lock:
            self.connections[id(conn)] = conn

    async def unregister(self, conn: DashboardConnection) -> None:
        async with self.lock:
            self.connections.pop(id(conn), None)

    def _enqueue(self, conn: DashboardConnection, event_type: str, payload, critical: bool) -> None:
        item = (event_type, payload)
        try:
            conn.queue.put_nowait(item)
        except asyncio.QueueFull:
            if critical:
                try:
                    conn.queue.get_nowait()          
                except asyncio.QueueEmpty:
                    pass
                try:
                    conn.queue.put_nowait(item)
                except asyncio.QueueFull:
                    conn.unhealthy = True
            

    async def broadcast(self, event_type: str, payload, critical: bool = False) -> None:
        conns = list(self.connections.values())
        for conn in conns:
            self._enqueue(conn, event_type, payload, critical)


async def broadcast_state_changed(reason: str = "change") -> None:
    await dashboard_mgr.broadcast(
        "state_changed", {"state": STATE_MGR.snapshot(), "reason": reason}, critical=True
    )


async def _dash_sender(conn: DashboardConnection, manager: DashboardManager) -> None:
    try:
        while True:
            event_type, payload = await conn.queue.get()
            await conn.websocket.send_json(
                {"type": event_type, "sequence": manager.next_seq(), "payload": payload}
            )
    except Exception:
        pass


async def _dash_heartbeat(conn: DashboardConnection, manager: DashboardManager) -> None:
    try:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
            if time.time() - conn.last_ack > HEARTBEAT_TIMEOUT_SECONDS:
                try:
                    await conn.websocket.close(code=1001, reason="Heartbeat timeout")
                except Exception:
                    pass
                break
            conn._hb_id += 1
            manager._enqueue(conn, "heartbeat", {"id": conn._hb_id}, critical=True)
    except Exception:
        pass


dashboard_mgr = DashboardManager()


def _origin_host(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = value.strip()
    if not v:
        return None
    try:
        parsed = urlparse(v if "://" in v else f"//{v}")
        return (parsed.hostname or "").lower() or None
    except Exception:
        return None


def origin_allowed(origin: Optional[str], server_host: Optional[str] = None) -> bool:
    if not origin:
        return True
    host = _origin_host(origin)
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    expected = _origin_host(PLATFORM_CTX.public_base_url)
    if expected and host == expected:
        return True
    if server_host:
        sh = _origin_host(server_host)
        if sh and host == sh:
            return True
    if (
        host.endswith(".up.railway.app")
        or host.endswith(".railway.app")
        or host.endswith("app.github.dev")
    ):
        return True
    return False


def platform_payload(ctx: Optional[PlatformContext] = None) -> dict:
    ctx = ctx or PLATFORM_CTX
    return {
        "id": ctx.platform.value,
        "name": ctx.display_name,
        "isCodespaces": ctx.is_codespaces,
        "persistenceMode": ctx.persistence_mode,
        "publicBaseUrl": ctx.public_base_url,
        "transport": "WebSocket",
        "wsPath": "/ws/{client_id}",
        "capabilities": {
            "websocketGateway": ctx.capabilities.websocket_gateway,
            "subscriptionLinks": ctx.capabilities.subscription_links,
            "relayTools": ctx.capabilities.relay_tools,
            "persistentStorage": ctx.capabilities.persistent_storage,
            "codespacesMetadata": ctx.capabilities.codespaces_metadata,
        },
    }


def theme_payload(theme: Optional[ThemeTokens] = None) -> dict:
    theme = theme or PLATFORM_CTX.theme
    return {
        "accent": theme.accent,
        "accentHover": theme.accent_hover,
        "accentBackground": theme.accent_background,
        "success": theme.success,
    }


async def expose_codespace_port() -> None:
    
    if not PLATFORM_CTX.is_codespaces:
        return
    name = os.environ.get("CODESPACE_NAME", "")
    if not name:
        return
    port = PLATFORM_CTX.bind_port
    try:
        proc = await asyncio.create_subprocess_exec(
            "gh", "codespace", "ports", "visibility",
            f"{port}:public", "-c", name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=20)
    except Exception:
        pass





@asynccontextmanager
async def lifespan(app: FastAPI):
    await STATE_MGR.init()
    add_log(f"{APP_TITLE} gateway listening on port {PLATFORM_CTX.bind_port}")
    add_log(f"Platform: {PLATFORM_CTX.display_name} ({PLATFORM_CTX.platform.value})")
    add_log(f"Persistence: {PLATFORM_CTX.persistence_mode}")
    add_log("Transport: VLESS over WebSocket only")

    tasks = [
        asyncio.create_task(telemetry_loop()),
        asyncio.create_task(persist_loop()),
        asyncio.create_task(session_cleanup_loop()),
        asyncio.create_task(expose_codespace_port()),
    ]
    yield
    for t in tasks:
        t.cancel()
    await STATE_MGR.persist()
    add_log(f"{APP_TITLE} gateway stopped")






app = FastAPI(title=APP_TITLE, docs_url=None, redoc_url=None, lifespan=lifespan)
app.add_middleware(GZipMiddleware, minimum_size=500)
INDEX_HTML_CACHE: Optional[str] = None


@app.middleware("http")
async def body_limit_middleware(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_HTTP_BODY_BYTES:
            return JSONResponse(
                {"ok": False, "error": "Request body too large"}, status_code=413
            )
    return await call_next(request)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse({"ok": False, "error": str(exc.detail)}, status_code=exc.status_code)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s", request.url.path)
    return JSONResponse(
        {"ok": False, "error": "Request could not be processed"}, status_code=500
    )


def get_raw_index_html() -> str:
    global INDEX_HTML_CACHE
    if INDEX_HTML_CACHE:
        return INDEX_HTML_CACHE
    try:
        INDEX_HTML_CACHE = INDEX_HTML_PATH.read_text(encoding="utf-8")
    except Exception:
        INDEX_HTML_CACHE = _FALLBACK_HTML
    return INDEX_HTML_CACHE


def serve_index_html(request: Request) -> HTMLResponse:
    token = request.cookies.get(SESSION_COOKIE)
    is_auth = session_valid_sync(token)

    ctx = PLATFORM_CTX
    theme = ctx.theme
    content = get_raw_index_html()
    content = content.replace("{{PASS_SETUP}}", "true" if STATE_MGR.state.auth.pass_setup else "false")
    content = content.replace("{{LOGGED_IN}}", "true" if is_auth else "false")
    content = content.replace("{{APP_TITLE}}", APP_TITLE)
    content = content.replace("{{THEME_ACCENT}}", theme.accent)
    content = content.replace("{{THEME_ACCENT_URL}}", theme.accent.lstrip("#"))
    content = content.replace("{{THEME_ACCENT_HOVER}}", theme.accent_hover)
    content = content.replace("{{THEME_ACCENT_BG}}", theme.accent_background)
    content = content.replace("{{THEME_SUCCESS}}", theme.success)
    content = content.replace("{{THEME_SELECTION}}", theme.selection)
    content = content.replace("{{SHOW_CODESPACES_INFO}}", "true" if ctx.show_codespaces_info else "false")
    content = content.replace("{{BOOTSTRAP_JSON}}", json.dumps(platform_payload(ctx)))

    headers = {
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
    }
    return HTMLResponse(content=content, headers=headers)


@app.get("/")
@app.head("/")
async def root_view(request: Request):
    return serve_index_html(request)


@app.get("/login")
async def login_view(request: Request):
    return serve_index_html(request)


@app.get("/dashboard")
async def dashboard_view(request: Request):
    return serve_index_html(request)


@app.get("/index.html")
async def index_view(request: Request):
    return serve_index_html(request)


@app.get("/health")
@app.head("/health")
async def health_check():
    return {
        "status": "ok",
        "platform": PLATFORM_CTX.platform.value,
        "gateway": gateway["status"],
    }




@app.post("/api/setup")
async def api_setup(request: Request, body: SetupRequest):
    if STATE_MGR.state.auth.pass_setup:
        raise HTTPException(status_code=409, detail="Password setup is already complete")
    async with STATE_MGR.lock:
        if STATE_MGR.state.auth.pass_setup:
            raise HTTPException(status_code=409, detail="Password setup is already complete")
        STATE_MGR.state.auth.password_hash = hash_password(body.password)
        STATE_MGR.state.auth.pass_setup = True
        await STATE_MGR.store.save(STATE_MGR.state)

    token = await create_session()
    add_log("Admin password configured on first startup")
    resp = JSONResponse({"ok": True})
    _set_session_cookie(request, resp, token)
    return resp


@app.post("/api/login")
async def api_login(request: Request, body: LoginRequest):
    if not verify_password(body.password, STATE_MGR.state.auth.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    add_log("Admin logged in successfully")
    resp = JSONResponse({"ok": True})
    _set_session_cookie(request, resp, token)
    return resp


@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    add_log("Admin logged out")
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {
        "authenticated": await is_valid_session(token),
        "pass_setup": STATE_MGR.state.auth.pass_setup,
    }




@app.get("/api/state")
async def get_panel_state(_=Depends(require_auth)):
    return {
        "ok": True,
        "state": STATE_MGR.snapshot(),
        "platform": platform_payload(),
        "telemetry": await telemetry_snapshot(),
        "gateway": gateway["status"],
        "portDomain": public_host(),
        "webDomain": public_host(),
        "logs": "\n".join(console_logs),
    }


def _coerce_client(raw: dict, existing: Optional[ClientState]) -> ClientState:
    try:
        name = str(raw.get("name") or "Client")[:60]
        limit = max(0.0, float(raw.get("limit") or 0.0))
        used_bytes = (
            int(existing.used_bytes) if existing
            else int(float(raw.get("usage") or 0.0) * (1024.0 ** 3))
        )
        status = 1 if raw.get("status", 1) else 0
        expiry = str(raw.get("expiry") or "")[:40]
        utls = str(raw.get("utls") or "chrome")[:30]
        created_at = str(
            raw.get("created_at") or (existing.created_at if existing else "")
        )[:40]
        return ClientState(
            id=str(raw.get("id") or generate_uuid()),
            name=name,
            limit=limit,
            limit_bytes=int(limit * (1024.0 ** 3)),
            used_bytes=used_bytes,
            expiry=expiry,
            status=status,
            active=bool(status),
            utls=utls,
            created_at=created_at,
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid client data")


@app.put("/api/state")
@app.post("/api/state")
async def update_panel_state(request: Request, _=Depends(require_auth)):
    body = await request.json()
    new_state = body.get("state") if isinstance(body.get("state"), dict) else body
    reason = str(body.get("reason") or "sync")[:60]

    if "clients" in new_state and isinstance(new_state["clients"], list):
        async with STATE_MGR.lock:
            existing_map = {c.id: c for c in STATE_MGR.state.clients}
            updated = []
            for raw in new_state["clients"][:MAX_CLIENTS]:
                cid = str(raw.get("id") or generate_uuid())
                updated.append(_coerce_client(raw, existing_map.get(cid)))
            STATE_MGR.state.clients = updated
            await STATE_MGR.store.save(STATE_MGR.state)

    if "subClientSubscriptions" in new_state and isinstance(
        new_state["subClientSubscriptions"], dict
    ):
        async with STATE_MGR.lock:
            cleaned: dict[str, list[SubEntry]] = {}
            for cid, entries in new_state["subClientSubscriptions"].items():
                if not isinstance(entries, list):
                    continue
                cleaned[str(cid)] = [
                    SubEntry(
                        id=str(e.get("id") or generate_uuid())[:64],
                        type=e.get("type") if e.get("type") in ("proxy", "info") else "proxy",
                        transport="ws",
                        name=str(e.get("name") or "")[:120],
                        ipAddress=str(e.get("ipAddress") or "")[:200],
                    )
                    for e in entries[:MAX_SUB_ENTRIES]
                    if isinstance(e, dict)
                ]
            STATE_MGR.state.sub_client_subscriptions = cleaned
            await STATE_MGR.store.save(STATE_MGR.state)

    if "settings" in new_state and isinstance(new_state["settings"], dict):
        async with STATE_MGR.lock:
            STATE_MGR.state.settings.update(new_state["settings"])
            await STATE_MGR.store.save(STATE_MGR.state)

    await broadcast_state_changed(reason)
    return {"ok": True, "state": STATE_MGR.snapshot()}


@app.get("/api/config")
async def get_gateway_config(_=Depends(require_auth)):
    return {
        "ok": True,
        "config": {
            "transport": "WebSocket",
            "protocol": "VLESS",
            "path": "/ws/{client_id}",
            "publicUrl": PLATFORM_CTX.public_base_url,
            "tls": use_tls(),
            "port": PLATFORM_CTX.bind_port,
            "clients": len(STATE_MGR.state.clients),
        },
    }


@app.get("/api/sub-link")
async def get_sub_link(
    client: str = "",
    name: str = "V2Leafy Node",
    type: str = "proxy",
    ip: str = "",
    _=Depends(require_auth),
):
    
    entry_type = type if type in ("proxy", "info") else "proxy"
    target = next(
        (c for c in STATE_MGR.state.clients if c.id == client), None
    )
    if target is None:
        raise HTTPException(status_code=404, detail="Client not found")
    return {
        "ok": True,
        "link": build_single_sub_entry_link(PLATFORM_CTX, target, entry_type, name, ip),
    }


@app.post("/api/action")
async def handle_gateway_action(request: Request, body: ActionRequest, _=Depends(require_auth)):
    action = body.action
    if action == "start":
        gateway["status"] = GatewayStatus.RUNNING.value
        gateway["started_at"] = time.time()
        add_log("Gateway started")
        await dashboard_mgr.broadcast("gateway_status", {"status": gateway["status"]}, critical=True)
    elif action == "stop":
        gateway["status"] = GatewayStatus.STOPPED.value
        add_log("Gateway stopped")
        await close_all_proxy_connections()
        await dashboard_mgr.broadcast("gateway_status", {"status": gateway["status"]}, critical=True)
    elif action == "restart":
        gateway["status"] = GatewayStatus.RESTARTING.value
        add_log("Gateway restarting...")
        await close_all_proxy_connections()
        gateway["status"] = GatewayStatus.RUNNING.value
        gateway["started_at"] = time.time()
        add_log("Gateway restarted")
        await dashboard_mgr.broadcast("gateway_status", {"status": gateway["status"]}, critical=True)
    elif action == "clear_logs":
        console_logs.clear()
        add_log("Console logs cleared")
    await dashboard_mgr.broadcast(
        "command_result",
        {"ok": True, "action": action, "message": f"Gateway {action} executed"},
        critical=True,
    )
    return {"ok": True, "action": action}




@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    res = []
    for c in STATE_MGR.state.clients:
        res.append({
            "uuid": c.id,
            "label": c.name,
            "limit_bytes": c.limit_bytes,
            "used_bytes": c.used_bytes,
            "active": bool(c.status),
            "expiry": c.expiry,
            "created_at": c.created_at,
            "vless_link": generate_vless_link(c.id, remark=f"V2Leafy-{c.name}"),
        })
    return {"links": res}


@app.post("/api/links")
async def create_link_api(request: Request, body: ClientCreateRequest, _=Depends(require_auth)):
    if len(STATE_MGR.state.clients) >= MAX_CLIENTS:
        raise HTTPException(status_code=400, detail="Client limit reached")
    limit_bytes = (
        int(body.limit_value * (1024.0 ** 3)) if body.limit_unit == "GB"
        else int(body.limit_value * (1024.0 ** 2))
    )
    cid = generate_uuid()
    client = ClientState(
        id=cid,
        name=body.label,
        limit=body.limit_value,
        limit_bytes=limit_bytes,
        expiry=body.expiry,
        status=1,
        active=True,
        utls="chrome",
        created_at=datetime.now().isoformat(),
    )
    async with STATE_MGR.lock:
        STATE_MGR.state.clients.append(client)
        await STATE_MGR.store.save(STATE_MGR.state)
    add_log(f"Created client '{body.label}' ({cid})")
    await broadcast_state_changed("createClient")
    return {
        "ok": True,
        "uuid": cid,
        "link": generate_vless_link(cid, remark=f"V2Leafy-{body.label}"),
    }


@app.patch("/api/links/{uid}")
async def patch_link_api(uid: str, request: Request, body: ClientPatchRequest, _=Depends(require_auth)):
    client = next((c for c in STATE_MGR.state.clients if c.id == uid), None)
    if not client:
        raise HTTPException(status_code=404, detail="Link not found")
    async with STATE_MGR.lock:
        if body.active is not None:
            client.status = 1 if body.active else 0
            client.active = bool(body.active)
        if body.label is not None:
            client.name = body.label
        if body.limit_value is not None:
            client.limit = body.limit_value
            client.limit_bytes = int(body.limit_value * (1024.0 ** 3))
        if body.reset_usage:
            client.used_bytes = 0
        await STATE_MGR.store.save(STATE_MGR.state)
    await broadcast_state_changed("patchClient")
    return {"ok": True}


@app.delete("/api/links/{uid}")
async def delete_link_api(uid: str, _=Depends(require_auth)):
    async with STATE_MGR.lock:
        STATE_MGR.state.clients = [c for c in STATE_MGR.state.clients if c.id != uid]
        STATE_MGR.state.sub_client_subscriptions.pop(uid, None)
        await STATE_MGR.store.save(STATE_MGR.state)
    add_log(f"Deleted client {uid}")
    await broadcast_state_changed("deleteClient")
    return {"ok": True}


@app.get("/api/links/{uid}/sub")
async def get_single_link_subscription(uid: str, _=Depends(require_auth)):
    client = next(
        (c for c in STATE_MGR.state.clients if c.id == uid or c.name == uid), None
    )
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return {
        "ok": True,
        "subscription_url": f"{PLATFORM_CTX.public_base_url}/sub/{client.id}",
        "config": generate_vless_link(client.id, remark=f"V2Leafy-{client.name}"),
        "label": client.name,
        "used_bytes": client.used_bytes,
        "limit_bytes": client.limit_bytes,
    }




@app.get("/api/sub/link/{client_id}")
async def get_subscription_link_url(client_id: str):
    return {
        "ok": True,
        "link": f"{PLATFORM_CTX.public_base_url}/sub/{client_id}",
    }


def _b64url_decode(s: str) -> str:
    try:
        padded = s + "=" * ((4 - len(s) % 4) % 4)
        return base64.urlsafe_b64decode(padded.encode()).decode(errors="ignore")
    except Exception:
        return s


SUB_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="{{SUB_ACCENT}}">
    <title>{{APP_TITLE}} Subscription Profile</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23{{THEME_ACCENT_URL}}'%3E%3Cpath d='M11 20A7 7 0 0 1 9.8 6.1C15.5 5 17 4.48 19 2c1 2 2 4.18 2 8 0 5.5-4.78 10-10 10Z'/%3E%3C/svg%3E">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="preconnect" href="https://cdnjs.cloudflare.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
    <link rel="preload" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" as="style" onload="this.onload=null;this.rel='stylesheet'">
    <noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"></noscript>
    <script defer src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <style>
        :root { --bg-base: #09090b; --bg-panel: #121214; --bg-hover: #1f1f22; --border: rgba(255,255,255,0.08); --border-hover: rgba(255,255,255,0.15); --text-main: #fafafa; --text-muted: #a1a1aa; --accent: {{SUB_ACCENT}}; --accent-hover: {{SUB_ACCENT_HOVER}}; --accent-bg: {{SUB_ACCENT_BG}}; --danger: #ef4444; --warning: #f59e0b; --success: {{SUB_SUCCESS}}; --info: #3b82f6; --radius-md: 16px; --radius-sm: 10px; }
        * { margin: 0; padding: 0; box-sizing: border-box; outline: none; -webkit-tap-highlight-color: transparent; }
        body { background: var(--bg-base); color: var(--text-main); font-family: 'Plus Jakarta Sans', sans-serif; margin: 0; padding: 24px 16px; display: flex; justify-content: center; min-height: 100vh; box-sizing: border-box; }
        .container { max-width: 480px; width: 100%; display: flex; flex-direction: column; gap: 20px; padding-bottom: 30px; }
        .card { background: var(--bg-panel); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 24px; box-shadow: 0 8px 30px rgba(0,0,0,0.4); }
        .card-title { margin: 0 0 16px 0; font-size: 1.15rem; font-weight: 800; display: flex; align-items: center; gap: 10px; }
        .stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        .stat-box { background: var(--bg-base); border: 1px solid var(--border); padding: 14px; border-radius: var(--radius-sm); }
        .stat-label { font-size: 0.75rem; color: var(--text-muted); font-weight: 700; text-transform: uppercase; margin-bottom: 6px; letter-spacing: 0.05em; }
        .stat-val { font-size: 1.15rem; font-weight: 800; font-family: 'JetBrains Mono', monospace; }
        .tag { padding: 4px 12px; border-radius: 8px; font-size: 0.7rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.05em; }
        .btn { width: 100%; background: var(--bg-hover); color: var(--text-main); border: 1px solid var(--border); padding: 14px; border-radius: var(--radius-sm); font-size: 0.9rem; font-weight: 700; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 8px; font-family: inherit; transition: all 0.2s ease; margin-top: 12px; }
        .btn:hover { background: var(--border-hover); transform: translateY(-1px); }
        .btn-primary { background: var(--accent); color: #000; border: none; }
        .btn-primary:hover { background: var(--accent-hover); color: #fff; }
        .btn-icon { width: 40px; height: 40px; padding: 0; margin: 0; }
        .link-item { background: var(--bg-base); border: 1px solid var(--border); padding: 14px; border-radius: var(--radius-sm); display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; transition: border-color 0.2s; }
        .link-item:hover { border-color: var(--border-hover); }
        .link-item-title { font-size: 0.9rem; font-weight: 700; margin-bottom: 4px; }
        .link-item-sub { font-size: 0.75rem; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }
        .progress-bar { width: 100%; height: 8px; background: var(--bg-hover); border-radius: 4px; margin-top: 10px; overflow: hidden; }
        .progress-fill { height: 100%; background: var(--success); border-radius: 4px; transition: width 0.3s ease; }
        .progress-fill.warning { background: var(--warning); }
        .progress-fill.danger { background: var(--danger); }
        .qr-modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.8); backdrop-filter: blur(8px); justify-content: center; align-items: center; z-index: 100; padding: 20px; animation: fadeIn 0.2s ease; }
        .qr-modal.show { display: flex; }
        .qr-card { background: #fff; padding: 24px; border-radius: var(--radius-md); text-align: center; box-shadow: 0 20px 40px rgba(0,0,0,0.5); }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .text-accent { color: var(--accent) !important; }
        .text-info { color: var(--info) !important; }
        .text-warning { color: var(--warning) !important; }
        .import-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-top: 12px; }
        .btn-import { background: var(--bg-base); border: 1px solid var(--border); color: var(--text-main); text-decoration: none; padding: 14px 10px; border-radius: var(--radius-sm); font-size: 0.85rem; font-weight: 700; text-align: center; transition: all 0.2s; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 8px; }
        .btn-import:hover { background: var(--bg-hover); border-color: var(--accent); transform: translateY(-2px); }
        .btn-import i { font-size: 1.5rem; }
        .footer { text-align: center; margin-top: 20px; font-size: 0.8rem; color: var(--text-muted); font-weight: 600; }
        .footer a { color: var(--text-muted); text-decoration: none; transition: color 0.2s; }
        .footer a:hover { color: var(--text-main); }
    </style>
</head>
<body>
    <div class="container" id="app"></div>
    <div class="qr-modal" id="qr-modal" onclick="this.classList.remove('show')">
        <div class="qr-card" onclick="event.stopPropagation()">
            <div id="qrcode" style="display:inline-block; padding:10px; border:4px solid #f0f0f0; border-radius:12px; background:#fff;"></div>
            <button class="btn" style="margin-top:20px; background:#f4f4f5; color:#18181b; border:none;" onclick="document.getElementById('qr-modal').classList.remove('show')">Close QR</button>
        </div>
    </div>
    <script>
        const DATA = JSON.parse(atob('{{SUB_DATA_B64}}'));
        function fmtGB(v){ return !v ? '∞' : v.toFixed(2)+' GB'; }
        function fmtDate(d){ return !d ? 'Never' : new Date(d).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'}); }
        function cp(t){ navigator.clipboard.writeText(t).then(()=>{ const el=document.createElement('div'); el.innerText='Copied!'; el.style.cssText='position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--success);color:#fff;padding:10px 20px;border-radius:20px;font-weight:700;z-index:999;box-shadow:0 4px 12px rgba(0,0,0,0.35);'; document.body.appendChild(el); setTimeout(()=>el.remove(),2000); }); }
        function qr(t){ document.getElementById('qrcode').innerHTML=''; new QRCode(document.getElementById('qrcode'),{text:t,width:220,height:220,colorDark:"#000000",colorLight:"#ffffff",correctLevel:QRCode.CorrectLevel.M}); document.getElementById('qr-modal').classList.add('show'); }
        function render(){
            const u = DATA.client.usage||0; const l = DATA.client.limit||0; const p = l>0?Math.min(100,(u/l)*100):0;
            const cls = p>90?'danger':(p>75?'warning':'');
            const subUrl = encodeURIComponent(window.location.href);
            const subName = encodeURIComponent(DATA.client.name);
            const b64Url = btoa(window.location.href);
            document.getElementById('app').innerHTML = `
                <div style="text-align:center; margin-bottom:8px;">
                    <svg viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="width:56px; height:56px; margin-bottom:12px; color:var(--accent);" aria-hidden="true"><path d="M11 20A7 7 0 0 1 9.8 6.1C15.5 5 17 4.48 19 2c1 2 2 4.18 2 8 0 5.5-4.78 10-10 10Z"/><path d="M2 21c0-3 1.85-5.36 5.08-6C9.5 14.52 12 13 13 12" fill="none"/></svg>
                    <h1 style="margin:0; font-size:1.8rem; font-weight:800; letter-spacing:-0.03em;">{{APP_TITLE}}</h1>
                    <p style="color:var(--text-muted); font-size:0.85rem; font-weight:600; margin-top:6px;">Subscription Environment</p>
                </div>
                <div class="card">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
                        <h2 class="card-title" style="margin:0;"><i class="fa-solid fa-user-shield text-accent"></i> ${DATA.client.name}</h2>
                        <span class="tag" style="background:${DATA.client.status?'var(--success)':'var(--danger)'}20; color:${DATA.client.status?'var(--success)':'var(--danger)'};">${DATA.client.status?'ACTIVE':'DISABLED'}</span>
                    </div>
                    <div class="stat-grid">
                        <div class="stat-box"><div class="stat-label">Used Data</div><div class="stat-val">${u>0?u.toFixed(2):'0'} GB</div></div>
                        <div class="stat-box"><div class="stat-label">Total Quota</div><div class="stat-val">${fmtGB(l)}</div></div>
                        <div class="stat-box" style="grid-column:1/-1;">
                            <div style="display:flex; justify-content:space-between; align-items:center;"><span class="stat-label" style="margin:0;">Consumption</span><span style="font-size:0.8rem; font-weight:800;">${p.toFixed(1)}%</span></div>
                            <div class="progress-bar"><div class="progress-fill ${cls}" style="width:${p}%"></div></div>
                        </div>
                        <div class="stat-box"><div class="stat-label">Expiry</div><div class="stat-val" style="font-size:0.95rem;">${fmtDate(DATA.client.expiry)}</div></div>
                        <div class="stat-box"><div class="stat-label">Remaining</div><div class="stat-val" style="font-size:0.95rem;">${l?fmtGB(Math.max(0,l-u)):'∞'}</div></div>
                    </div>
                    <button class="btn btn-primary" style="margin-top:20px;" onclick="cp(window.location.href)"><i class="fa-solid fa-link"></i> Copy Subscription Link</button>
                    <div style="margin-top:24px;">
                        <h3 style="font-size:0.9rem; font-weight:800; margin:0 0 10px 0;"><i class="fa-solid fa-bolt text-warning"></i> One-Click Import</h3>
                        <div class="import-grid">
                            <a href="v2rayng://install-sub?url=${subUrl}&name=${subName}" class="btn-import"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 192 192" width="26" height="26" style="color:var(--accent);"><path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="12" d="M22 39.005h40.738v113.99L170 39.005"/></svg> v2rayNG</a>
                            <a href="hiddify://install-sub?url=${subUrl}&name=${subName}" class="btn-import"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="26" height="26" style="color:var(--info);"><path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M33.578 19.376h8.146c.43 0 .776.346.776.777v19.785c0 .43-.346.777-.776.777h-8.146a.775.775 0 0 1-.776-.774V20.153c0-.43.346-.777.776-.777m8.146-12.091c.43 0 .776.347.776.777v8.359c0 .43-.346.777-.776.777h-8.146a.775.775 0 0 1-.776-.774v-3.769zM28.06 15.31c.43 0 .776.347.776.778v23.85c0 .43-.346.777-.776.777h-8.146a.775.775 0 0 1-.776-.774V20.68zm-13.638 8.15c.43 0 .776.347.776.778v15.7c0 .43-.346.777-.776.777H6.276a.775.775 0 0 1-.776-.777V28.83zm.777 11.419h3.94"/></svg> Hiddify</a>
                            <a href="shadowrocket://add/sub://${b64Url}?title=${subName}" class="btn-import"><i class="fa-solid fa-rocket text-warning"></i> Shadowrocket</a>
                            <a href="sing-box://import-remote-profile?url=${subUrl}&name=${subName}" class="btn-import"><i class="fa-solid fa-box text-accent"></i> Sing-Box</a>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <h2 class="card-title"><i class="fa-solid fa-network-wired text-accent"></i> Configurations</h2>
                    <button class="btn" style="margin-bottom:20px; background:var(--accent-bg); color:var(--accent); border:none;" onclick="cp(DATA.links.join('\\n'))"><i class="fa-solid fa-copy"></i> Copy All Configs</button>
                    <div style="display:flex; flex-direction:column;">
                        ${DATA.links.map((lnk,i)=>{
                            let n = 'Node '+(i+1); try{n=decodeURIComponent(lnk.split('#')[1]||n);}catch(e){}
                            return `<div class="link-item">
                                <div style="min-width:0; flex:1; padding-right:16px;">
                                    <div class="link-item-title">${n}</div>
                                    <div class="link-item-sub">${lnk.substring(0,32)}...</div>
                                </div>
                                <div style="display:flex; gap:8px;">
                                    <button class="btn btn-icon" onclick="qr('${lnk}')"><i class="fa-solid fa-qrcode"></i></button>
                                    <button class="btn btn-icon" onclick="cp('${lnk}')"><i class="fa-solid fa-copy"></i></button>
                                </div>
                            </div>`;
                        }).join('')}
                    </div>
                </div>
                <div class="footer"><svg viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="width:14px; height:14px; vertical-align:-2px; margin-right:6px; color:var(--accent);" aria-hidden="true"><path d="M11 20A7 7 0 0 1 9.8 6.1C15.5 5 17 4.48 19 2c1 2 2 4.18 2 8 0 5.5-4.78 10-10 10Z"/><path d="M2 21c0-3 1.85-5.36 5.08-6C9.5 14.52 12 13 13 12" fill="none"/></svg>Powered by <a href="https://github.com/Code-Leafy/V2Leafy" target="_blank" rel="noopener"><i class="fa-brands fa-github"></i> V2Leafy</a></div>
            `;
        }
        render();
    </script>
</body>
</html>
"""


def render_sub_template(data_obj: dict) -> str:
    b64_json = base64.b64encode(json.dumps(data_obj).encode()).decode()
    html_page = SUB_HTML_TEMPLATE.replace("{{SUB_DATA_B64}}", b64_json)
    theme = PLATFORM_CTX.theme
    html_page = html_page.replace("{{THEME_ACCENT_URL}}", theme.accent.lstrip("#"))
    html_page = html_page.replace("{{SUB_ACCENT}}", theme.accent)
    html_page = html_page.replace("{{SUB_ACCENT_HOVER}}", theme.accent_hover)
    html_page = html_page.replace("{{SUB_ACCENT_BG}}", theme.accent_background)
    html_page = html_page.replace("{{SUB_SUCCESS}}", theme.success)
    html_page = html_page.replace("{{APP_TITLE}}", APP_TITLE)
    return html_page


@app.get("/sub/{encoded_id}")
async def public_subscription_endpoint(encoded_id: str, request: Request):
    clean_id = str(encoded_id).strip()
    raw_id = _b64url_decode(clean_id).strip()

    client = None
    for c in STATE_MGR.state.clients:
        if c.id == clean_id or c.id == raw_id or c.name == clean_id or c.name == raw_id:
            client = c
            break
    if not client and len(STATE_MGR.state.clients) == 1:
        client = STATE_MGR.state.clients[0]
    if not client:
        raise HTTPException(status_code=404, detail="Subscription client not found")
    if not client.status:
        raise HTTPException(status_code=403, detail="Subscription disabled")

    sub_links = build_client_sub_links(STATE_MGR.state, client)
    sub_content = "\n".join(sub_links)
    encoded_payload = base64.b64encode(sub_content.encode()).decode()

    accept_header = request.headers.get("accept", "").lower()
    user_agent = request.headers.get("user-agent", "").lower()
    is_browser = (
        ("text/html" in accept_header or "mozilla" in user_agent)
        and "raw" not in request.query_params
    )

    if is_browser:
        data_obj = {
            "client": {
                "id": client.id,
                "name": client.name,
                "usage": round(client.used_bytes / (1024.0 ** 3), 3),
                "limit": client.limit,
                "expiry": client.expiry,
                "status": client.status,
            },
            "links": sub_links,
        }
        return HTMLResponse(content=render_sub_template(data_obj))

    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": f'attachment; filename="V2Leafy_{client.name}.txt"',
        "profile-update-interval": "6",
        "subscription-userinfo": (
            f"upload={client.used_bytes}; download=0; "
            f"total={client.limit_bytes}; expire=0"
        ),
    }
    return Response(content=encoded_payload, headers=headers)






@app.websocket("/api/ws")
async def dashboard_ws(websocket: WebSocket):
    token = websocket.cookies.get(SESSION_COOKIE)
    authed = await is_valid_session(token)
    await websocket.accept()
    if not authed:
        await websocket.close(code=4401)
        return
    if not origin_allowed(
        websocket.headers.get("origin"),
        websocket.headers.get("host") or (websocket.client.host if websocket.client else None),
    ):
        await websocket.close(code=4403)
        return
    if len(dashboard_mgr.connections) >= MAX_DASHBOARD_CONNECTIONS:
        await websocket.close(code=1013)
        return

    conn = DashboardConnection(websocket)
    await dashboard_mgr.register(conn)
    sender = asyncio.create_task(_dash_sender(conn, dashboard_mgr))
    heartbeat = asyncio.create_task(_dash_heartbeat(conn, dashboard_mgr))
    try:
        await websocket.send_json({
            "type": "hello",
            "sequence": dashboard_mgr.next_seq(),
            "protocol": 1,
            "payload": {
                "platform": platform_payload(),
                "theme": theme_payload(),
                "state": STATE_MGR.snapshot(),
                "telemetry": await telemetry_snapshot(),
                "logs": list(console_logs),
                "serverTime": datetime.now().isoformat(),
            },
        })
        while True:
            msg = await websocket.receive_text()
            try:
                data = json.loads(msg)
            except Exception:
                continue
            mtype = data.get("type")
            if mtype == "heartbeat_ack":
                conn.last_ack = time.time()
            elif mtype == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "sequence": dashboard_mgr.next_seq(),
                    "payload": {},
                })
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        sender.cancel()
        heartbeat.cancel()
        await dashboard_mgr.unregister(conn)
        try:
            await websocket.close()
        except Exception:
            pass


def parse_vless_header(first_chunk: bytes) -> dict:
    
    if len(first_chunk) < 24:
        raise ValueError("VLESS header too short")

    pos = 0
    version = first_chunk[pos]
    pos += 1
    if version != 0:
        raise ValueError(f"Unsupported VLESS version {version}")

    raw_uuid = first_chunk[pos:pos + 16]
    pos += 16

    addon_len = first_chunk[pos]
    pos += 1
    if addon_len > 64 or pos + addon_len > len(first_chunk):
        raise ValueError("Invalid VLESS addon length")
    pos += addon_len

    if pos + 3 > len(first_chunk):
        raise ValueError("VLESS header truncated")
    command = first_chunk[pos]
    pos += 1
    if command not in (1, 2):
        raise ValueError(f"Unsupported VLESS command {command}")

    port = int.from_bytes(first_chunk[pos:pos + 2], "big")
    pos += 2
    if not (0 < port <= 65535):
        raise ValueError("VLESS port out of range")

    addr_type = first_chunk[pos]
    pos += 1
    if addr_type == 1:
        if pos + 4 > len(first_chunk):
            raise ValueError("VLESS IPv4 truncated")
        address = ".".join(str(b) for b in first_chunk[pos:pos + 4])
        pos += 4
    elif addr_type == 2:
        if pos + 1 > len(first_chunk):
            raise ValueError("VLESS domain truncated")
        domain_len = first_chunk[pos]
        pos += 1
        if domain_len == 0 or pos + domain_len > len(first_chunk):
            raise ValueError("VLESS domain length invalid")
        raw = first_chunk[pos:pos + domain_len]
        pos += domain_len
        try:
            address = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("VLESS domain is not valid utf-8")
        if (
            not address
            or len(address) > 253
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in address)
        ):
            raise ValueError("VLESS domain invalid")
    elif addr_type == 3:
        if pos + 16 > len(first_chunk):
            raise ValueError("VLESS IPv6 truncated")
        addr_bytes = first_chunk[pos:pos + 16]
        pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i + 1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"Unknown VLESS address type {addr_type}")

    uuid_str = (
        f"{raw_uuid[:4].hex()}-{raw_uuid[4:6].hex()}-{raw_uuid[6:8].hex()}-"
        f"{raw_uuid[8:10].hex()}-{raw_uuid[10:].hex()}"
    )
    return {
        "version": version,
        "uuid": uuid_str,
        "command": command,
        "address": address,
        "port": port,
        "payload": first_chunk[pos:],
    }


async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, client: ClientState) -> None:
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            if len(data) > MAX_WS_FRAME_BYTES:
                await websocket.close(code=1009, reason="Frame too large")
                break
            if not check_client_quota(client, len(data)):
                await websocket.close(code=1008, reason="Quota exceeded")
                break
            record_traffic(client, len(data), is_rx=True)
            writer.write(data)
            await writer.drain()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass


async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, client: ClientState) -> None:
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            if not check_client_quota(client, len(data)):
                await websocket.close(code=1008, reason="Quota exceeded")
                break
            record_traffic(client, len(data), is_rx=False)
            prefix = bytes([0, 0]) if first else b""
            await websocket.send_bytes(prefix + data)
            first = False
    except Exception:
        pass


async def close_all_proxy_connections() -> None:
    for conn in list(proxy_connections.values()):
        try:
            await conn["websocket"].close(code=1001, reason="Gateway stopped")
        except Exception:
            pass
        try:
            conn["writer"].close()
        except Exception:
            pass
    proxy_connections.clear()


@app.websocket("/ws/{client_id}")
@app.websocket("/ws")
async def websocket_vless_tunnel(websocket: WebSocket, client_id: str = ""):
    if not gateway_running():
        await websocket.accept()
        await websocket.close(code=1008, reason="Gateway stopped")
        return

    await websocket.accept()
    writer = None
    conn_id = None
    client: Optional[ClientState] = None
    try:
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            await websocket.close(code=1008, reason="Empty frame")
            return
        if len(first_chunk) > MAX_WS_FRAME_BYTES:
            await websocket.close(code=1009, reason="Frame too large")
            return

        header = parse_vless_header(first_chunk)
        target_uuid = (client_id or header["uuid"]).strip().lower()
        if not UUID_RE.match(target_uuid):
            await websocket.close(code=1008, reason="Invalid client identifier")
            return

        client = next((c for c in STATE_MGR.state.clients if c.id == target_uuid), None)
        if client is None:
            await websocket.close(code=1008, reason="Unknown client")
            return
        if not client.active or not client.status:
            await websocket.close(code=1008, reason="Client disabled")
            return
        if header["command"] != 1:
            await websocket.close(code=1008, reason="Unsupported command")
            return
        if not check_client_quota(client, 0):
            await websocket.close(code=1008, reason="Quota exceeded")
            return

        conn_id = secrets.token_urlsafe(8)
        proxy_connections[conn_id] = {
            "websocket": websocket,
            "writer": None,
            "client_id": target_uuid,
        }
        record_traffic(client, len(first_chunk), is_rx=True)
        if not check_client_quota(client, 0):
            await websocket.close(code=1008, reason="Quota exceeded")
            return

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(header["address"], header["port"]), timeout=10.0
            )
        except Exception:
            raise ConnectionError("upstream unreachable")
        proxy_connections[conn_id]["writer"] = writer

        try:
            sock = writer.get_extra_info("socket")
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

        if header["payload"]:
            
            writer.write(header["payload"])
            await writer.drain()

        await dashboard_mgr.broadcast(
            "connection_opened",
            {
                "client_id": client.id,
                "client_name": client.name,
                "connections": len(proxy_connections),
            },
        )
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, client))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, client))
        done, pending = await asyncio.wait(
            {task_up, task_down}, return_when=asyncio.FIRST_COMPLETED
        )
        for t in pending:
            t.cancel()
    except asyncio.TimeoutError:
        try:
            await websocket.close(code=1008, reason="Handshake timeout")
        except Exception:
            pass
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        stats["total_errors"] += 1
        add_log(f"Proxy connection error: {type(exc).__name__}")
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
    finally:
        if writer:
            try:
                writer.close()
            except Exception:
                pass
        if conn_id:
            info = proxy_connections.pop(conn_id, None)
            if info and client is not None:
                await dashboard_mgr.broadcast(
                    "connection_closed",
                    {
                        "client_id": client.id,
                        "client_name": client.name,
                        "connections": len(proxy_connections),
                    },
                )






if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PLATFORM_CTX.bind_port, access_log=False)
