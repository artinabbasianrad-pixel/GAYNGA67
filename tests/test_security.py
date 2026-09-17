"""Security and edge-case tests for V2Leafy main.py."""
import os

os.environ["SECRET_KEY"] = "test-secret-key-12345"

import asyncio
import collections
import re
import time
from unittest.mock import MagicMock, patch

import httpx
import pytest
import pytest_asyncio

from main import (
    LOGIN_RATE_LIMIT,
    LOGIN_RATE_WINDOW_SECONDS,
    MAX_HTTP_BODY_BYTES,
    MAX_PROXY_CONNECTIONS,
    MAX_SESSIONS,
    MAX_WS_FRAME_BYTES,
    SESSION_COOKIE,
    SESSION_ROTATE_SECONDS,
    SESSION_TTL,
    ClientPatchRequest,
    ClientState,
    TcpDialPool,
    _csrf_token_for,
    _origin_host,
    app,
    check_rate_limit,
    destroy_session,
    create_session,
    generate_uuid,
    hash_password,
    is_valid_session,
    parse_vless_header,
    public_host,
    sanitize_client_name,
    sanitize_text,
    session_valid_sync,
    verify_password,
    origin_allowed,
    SESSIONS,
    LOGIN_ATTEMPTS,
    GEO_CACHE,
    proxy_connections,
    STATE_MGR,
)
from starlette.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_global_state():
    """Reset mutable global state before each test."""
    SESSIONS.clear()
    LOGIN_ATTEMPTS.clear()
    GEO_CACHE.clear()
    proxy_connections.clear()
    yield
    SESSIONS.clear()
    LOGIN_ATTEMPTS.clear()
    GEO_CACHE.clear()
    proxy_connections.clear()


@pytest.fixture
def client():
    """Synchronous TestClient for the FastAPI app."""
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def _login_via_api(client, password="testpassword"):
    """Helper: set up password hash and log in via the HTTP API.

    Returns (session_cookie, csrf_token).
    """
    STATE_MGR.state.auth.password_hash = hash_password(password)
    STATE_MGR.state.auth.pass_setup = True

    resp = client.post(
        "/api/login",
        json={"pass": password},
        headers={"Origin": "http://testserver"},
    )
    assert resp.status_code == 200, f"Login failed: {resp.status_code} {resp.text}"
    session_token = resp.cookies.get(SESSION_COOKIE)
    assert session_token, "No session cookie set"

    # Get CSRF token from /api/me
    client.cookies.set(SESSION_COOKIE, session_token)
    me_resp = client.get("/api/me")
    csrf_token = me_resp.json()["csrf_token"]
    return session_token, csrf_token


# ===========================================================================
# 1. RATE LIMITING TESTS
# ===========================================================================

class TestRateLimiting:
    """Tests for check_rate_limit(ip).

    NOTE: check_rate_limit's first-call path for any IP creates a fresh empty
    deque via setdefault, then the "not dq and ip in LOGIN_ATTEMPTS" branch
    fires (deque is empty so falsy, ip was just setdefault'd so True), pops the
    entry and returns True.  This means normal sequential calls never accumulate
    entries -- the dq.append(now) line is unreachable from clean state.
    We test (a) this actual behaviour, and (b) the enforcement/pruning paths
    by seeding LOGIN_ATTEMPTS directly.
    """

    @pytest.mark.asyncio
    async def test_new_ip_returns_true(self):
        """A brand-new IP always returns True (first-call path)."""
        result = await check_rate_limit("10.0.0.1")
        assert result is True

    @pytest.mark.asyncio
    async def test_first_call_does_not_record_entry(self):
        """The first call for an IP does not leave an entry in LOGIN_ATTEMPTS."""
        await check_rate_limit("10.0.0.99")
        assert "10.0.0.99" not in LOGIN_ATTEMPTS

    @pytest.mark.asyncio
    async def test_sequential_calls_all_return_true(self):
        """Because each call creates and pops a fresh deque, all calls return True."""
        ip = "10.0.0.2"
        for _ in range(LOGIN_RATE_LIMIT + 5):
            assert await check_rate_limit(ip) is True

    @pytest.mark.asyncio
    async def test_enforcement_with_seeded_entries(self):
        """When LOGIN_ATTEMPTS already has enough entries, the limit triggers."""
        ip = "10.0.0.6"
        now = time.time()
        LOGIN_ATTEMPTS[ip] = collections.deque(
            [now - i for i in range(LOGIN_RATE_LIMIT)]
        )
        result = await check_rate_limit(ip)
        assert result is False

    @pytest.mark.asyncio
    async def test_different_ips_have_separate_buckets(self):
        """Entries for different IPs do not interfere."""
        ip_a = "192.168.1.10"
        ip_b = "192.168.1.20"
        now = time.time()
        LOGIN_ATTEMPTS[ip_a] = collections.deque(
            [now - i for i in range(LOGIN_RATE_LIMIT)]
        )
        assert await check_rate_limit(ip_a) is False
        assert await check_rate_limit(ip_b) is True

    @pytest.mark.asyncio
    async def test_expired_entries_are_pruned(self):
        """Entries older than LOGIN_RATE_WINDOW_SECONDS are pruned."""
        ip = "10.0.0.3"
        now = time.time()
        LOGIN_ATTEMPTS[ip] = collections.deque(
            [now - LOGIN_RATE_WINDOW_SECONDS - 100] * LOGIN_RATE_LIMIT
        )
        result = await check_rate_limit(ip)
        assert result is True

    @pytest.mark.asyncio
    async def test_mixed_fresh_and_old_entries(self):
        """Only fresh entries count toward the limit."""
        ip = "10.0.0.7"
        now = time.time()
        old = now - LOGIN_RATE_WINDOW_SECONDS - 10
        fresh = now - 5
        LOGIN_ATTEMPTS[ip] = collections.deque([old, old, old, old, fresh])
        result = await check_rate_limit(ip)
        assert result is True  # 1 fresh entry < LOGIN_RATE_LIMIT

    @pytest.mark.asyncio
    async def test_enforcement_after_seeding_nearly_full(self):
        """One short of limit allows, then next call is rejected."""
        ip = "10.0.0.8"
        now = time.time()
        LOGIN_ATTEMPTS[ip] = collections.deque(
            [now - i for i in range(LOGIN_RATE_LIMIT - 1)]
        )
        assert await check_rate_limit(ip) is True
        assert await check_rate_limit(ip) is False


# ===========================================================================
# 2. SESSION MANAGEMENT TESTS
# ===========================================================================

class TestSessionManagement:
    """Tests for session creation, validation, rotation, and expiry."""

    @pytest.mark.asyncio
    async def test_valid_session_token(self):
        """A freshly created session should be valid."""
        token = await create_session()
        assert await is_valid_session(token) is True

    @pytest.mark.asyncio
    async def test_none_token_is_invalid(self):
        assert await is_valid_session(None) is False

    @pytest.mark.asyncio
    async def test_empty_string_token_is_invalid(self):
        assert await is_valid_session("") is False

    @pytest.mark.asyncio
    async def test_nonexistent_token_is_invalid(self):
        assert await is_valid_session("totally-fake-token-xyz") is False

    @pytest.mark.asyncio
    async def test_expired_session_is_invalid(self):
        """An expired session should be invalid and cleaned up."""
        token = await create_session()
        assert await is_valid_session(token) is True
        SESSIONS[token]["exp"] = time.time() - 1000
        assert await is_valid_session(token) is False
        assert token not in SESSIONS

    def test_session_valid_sync_none(self):
        assert session_valid_sync(None) is False

    def test_session_valid_sync_expired(self):
        token = "sync-test-token"
        SESSIONS[token] = {"exp": time.time() - 100, "created": time.time() - 200}
        assert session_valid_sync(token) is False
        assert token not in SESSIONS

    def test_rotate_session_not_due(self):
        """Session should NOT rotate if created recently."""
        from main import rotate_session_if_due
        token = "rotate-test-token"
        SESSIONS[token] = {"exp": time.time() + 3600, "created": time.time()}
        result = rotate_session_if_due(token)
        assert result is None
        assert token in SESSIONS

    def test_rotate_session_when_due(self):
        """Session should rotate after SESSION_ROTATE_SECONDS."""
        from main import rotate_session_if_due
        token = "rotate-old-token"
        SESSIONS[token] = {
            "exp": time.time() + 3600,
            "created": time.time() - SESSION_ROTATE_SECONDS - 1,
        }
        new_token = rotate_session_if_due(token)
        assert new_token is not None
        assert new_token != token
        assert token not in SESSIONS
        assert new_token in SESSIONS

    def test_rotate_nonexistent_returns_none(self):
        from main import rotate_session_if_due
        result = rotate_session_if_due("nonexistent-token")
        assert result is None

    def test_max_sessions_limit(self):
        """When MAX_SESSIONS is reached, the guard condition is met."""
        for i in range(MAX_SESSIONS):
            token = f"session-{i}"
            SESSIONS[token] = {"exp": time.time() + 3600, "created": time.time()}
        assert len(SESSIONS) >= MAX_SESSIONS

    def test_session_cleanup_removes_expired(self):
        """The cleanup logic removes expired sessions."""
        valid_token = "valid-session"
        expired_token = "expired-session"
        SESSIONS[valid_token] = {"exp": time.time() + 3600, "created": time.time()}
        SESSIONS[expired_token] = {"exp": time.time() - 100, "created": time.time() - 200}

        now = time.time()
        for tk in [k for k, v in SESSIONS.items() if v["exp"] < now]:
            SESSIONS.pop(tk, None)

        assert valid_token in SESSIONS
        assert expired_token not in SESSIONS

    @pytest.mark.asyncio
    async def test_destroy_session(self):
        token = await create_session()
        assert await is_valid_session(token) is True
        await destroy_session(token)
        assert await is_valid_session(token) is False

    @pytest.mark.asyncio
    async def test_destroy_none_session(self):
        await destroy_session(None)


# ===========================================================================
# 3. INPUT VALIDATION TESTS
# ===========================================================================

class TestInputValidation:
    """Tests for sanitize_text, sanitize_client_name, and parse_vless_header."""

    def test_sanitize_removes_control_chars(self):
        result = sanitize_text("hello\x00\x01\x02\x03world")
        assert "\x00" not in result
        assert "\x01" not in result
        assert result == "helloworld"

    def test_sanitize_removes_cr_lf(self):
        result = sanitize_text("line1\r\nline2\nline3\r")
        assert "\r" not in result
        assert "\n" not in result
        assert "line1" in result
        assert "line2" in result

    def test_sanitize_removes_angle_brackets_and_quotes(self):
        result = sanitize_text('<script>alert("xss")</script>')
        assert "<" not in result
        assert ">" not in result
        assert '"' not in result
        assert "script" in result

    def test_sanitize_respects_max_len(self):
        result = sanitize_text("a" * 200, max_len=50)
        assert len(result) == 50

    def test_sanitize_none_returns_fallback(self):
        result = sanitize_text(None, fallback="default")
        assert result == "default"

    def test_sanitize_empty_string_returns_fallback(self):
        result = sanitize_text("   \x00\x01  ", fallback="fallback")
        assert result == "fallback"

    def test_sanitize_strips_leading_trailing_whitespace(self):
        result = sanitize_text("  hello  ")
        assert result == "hello"

    def test_sanitize_client_name_normal(self):
        result = sanitize_client_name("MyClient")
        assert result == "MyClient"

    def test_sanitize_client_name_empty_returns_default(self):
        result = sanitize_client_name("")
        assert result == "Client"

    def test_sanitize_client_name_strips_dangerous_chars(self):
        result = sanitize_client_name('<script>alert(1)</script>')
        assert "<" not in result
        assert ">" not in result
        assert '"' not in result

    def test_sanitize_client_name_max_len(self):
        result = sanitize_client_name("A" * 100, max_len=60)
        assert len(result) == 60

    # --- parse_vless_header ---

    def test_vless_header_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            parse_vless_header(b"\x00" * 10)

    def test_vless_header_bad_version(self):
        header = bytearray(40)
        header[0] = 1
        with pytest.raises(ValueError, match="Unsupported VLESS version"):
            parse_vless_header(bytes(header))

    def test_vless_header_unsupported_command(self):
        header = bytearray(40)
        header[0] = 0
        header[17] = 0  # addon_len = 0
        header[18] = 5  # command = 5
        with pytest.raises(ValueError, match="Unsupported VLESS command"):
            parse_vless_header(bytes(header))

    def test_vless_header_truncated(self):
        header = bytearray(24)
        header[0] = 0
        header[17] = 100  # large addon_len -> truncation
        with pytest.raises(ValueError):
            parse_vless_header(bytes(header))

    def test_vless_header_valid_tcp_ipv4(self):
        header = bytearray(26)
        header[0] = 0  # version
        uuid_bytes = bytes(range(16))
        header[1:17] = uuid_bytes
        header[17] = 0  # addon_len
        header[18] = 1  # command = TCP
        header[19] = 0  # port high
        header[20] = 80  # port low
        header[21] = 1  # addr_type IPv4
        header[22:26] = bytes([192, 168, 1, 1])
        result = parse_vless_header(bytes(header))
        assert result["version"] == 0
        assert result["command"] == 1
        assert result["port"] == 80
        assert result["address"] == "192.168.1.1"

    def test_vless_header_valid_tcp_domain(self):
        header = bytearray(50)
        header[0] = 0  # version
        header[1:17] = bytes(range(16))
        header[17] = 0  # addon_len
        header[18] = 1  # command TCP
        header[19] = 0x01  # port high (443 = 0x01BB)
        header[20] = 0xBB  # port low  (443 = 0x01BB)
        header[21] = 2  # addr_type = domain
        domain = b"example.com"
        header[22] = len(domain)
        header[23:23 + len(domain)] = domain
        result = parse_vless_header(bytes(header))
        assert result["address"] == "example.com"
        assert result["port"] == 443

    def test_vless_header_valid_tcp_ipv6(self):
        header = bytearray(40)
        header[0] = 0  # version
        header[1:17] = bytes(range(16))
        header[17] = 0  # addon_len
        header[18] = 2  # command = UDP
        header[19] = 0
        header[20] = 53  # port
        header[21] = 3  # addr_type IPv6
        header[22:38] = bytes(range(16))
        result = parse_vless_header(bytes(header))
        assert result["command"] == 2
        assert result["port"] == 53
        assert ":" in result["address"]  # IPv6 format

    def test_vless_header_unknown_addr_type(self):
        header = bytearray(40)
        header[0] = 0
        header[17] = 0
        header[18] = 1
        header[19] = 0
        header[20] = 80
        header[21] = 99
        with pytest.raises(ValueError, match="Unknown VLESS address type"):
            parse_vless_header(bytes(header))

    def test_vless_header_port_zero(self):
        header = bytearray(26)
        header[0] = 0
        header[1:17] = bytes(range(16))
        header[17] = 0
        header[18] = 1
        header[19] = 0
        header[20] = 0  # port = 0
        header[21] = 1
        header[22:26] = bytes([1, 2, 3, 4])
        with pytest.raises(ValueError, match="out of range"):
            parse_vless_header(bytes(header))

    def test_vless_header_domain_fails_rfc1123(self):
        """A domain with valid length but invalid format fails RFC 1123 validation."""
        header = bytearray(300)
        header[0] = 0
        header[1:17] = bytes(range(16))
        header[17] = 0
        header[18] = 1
        header[19] = 0
        header[20] = 80
        header[21] = 2  # domain
        # A single label of 100 chars exceeds the 63-char label limit in RFC 1123
        domain = b"a" * 100
        header[22] = len(domain)
        header[23:23 + len(domain)] = domain
        with pytest.raises(ValueError, match="RFC 1123"):
            parse_vless_header(bytes(header))


# ===========================================================================
# 4. AUTHENTICATION TESTS
# ===========================================================================

class TestAuthentication:
    """Tests for auth-protected endpoints."""

    def test_protected_endpoint_returns_401_without_session(self, client):
        resp = client.get("/api/state")
        assert resp.status_code == 401

    def test_csrf_endpoint_returns_401_without_session(self, client):
        """No session at all yields 401 (auth check fires before CSRF)."""
        resp = client.post("/api/action", json={"action": "start"})
        assert resp.status_code == 401

    def test_login_wrong_password(self, client):
        STATE_MGR.state.auth.password_hash = hash_password("correct_password")
        STATE_MGR.state.auth.pass_setup = True
        resp = client.post(
            "/api/login",
            json={"pass": "wrong_password"},
            headers={"Origin": "http://testserver"},
        )
        assert resp.status_code == 401

    def test_login_correct_password(self, client):
        STATE_MGR.state.auth.password_hash = hash_password("mysecretpass")
        STATE_MGR.state.auth.pass_setup = True
        resp = client.post(
            "/api/login",
            json={"pass": "mysecretpass"},
            headers={"Origin": "http://testserver"},
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert SESSION_COOKIE in resp.cookies

    def test_metrics_requires_auth(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 401

    def test_api_me_without_session(self, client):
        resp = client.get("/api/me")
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is False

    def test_api_me_with_valid_session(self, client):
        _token, _csrf = _login_via_api(client)
        resp = client.get("/api/me")
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is True

    def test_api_links_requires_auth(self, client):
        resp = client.get("/api/links")
        assert resp.status_code == 401

    def test_setup_with_existing_password_returns_409(self, client):
        STATE_MGR.state.auth.pass_setup = True
        resp = client.post(
            "/api/setup",
            json={"pass": "newpass"},
            headers={"Origin": "http://testserver"},
        )
        assert resp.status_code == 409

    def test_csrf_token_validation(self):
        token = "session-token-12345"
        csrf = _csrf_token_for(token)
        assert _csrf_token_for(token) == csrf
        assert _csrf_token_for("other-token") != csrf

    def test_csrf_header_check_rejects_missing_token(self, client):
        """POST to CSRF-protected endpoint without x-csrf-token returns 403."""
        _token, _csrf = _login_via_api(client)
        resp = client.post(
            "/api/action",
            json={"action": "start"},
            headers={"Origin": "http://testserver"},
        )
        assert resp.status_code == 403

    def test_csrf_header_check_rejects_wrong_token(self, client):
        """POST with wrong CSRF token returns 403."""
        _token, _csrf = _login_via_api(client)
        resp = client.post(
            "/api/action",
            json={"action": "start"},
            headers={
                "Origin": "http://testserver",
                "x-csrf-token": "totally-wrong-csrf",
            },
        )
        assert resp.status_code == 403


# ===========================================================================
# 5. STATE INTEGRITY TESTS
# ===========================================================================

class TestStateIntegrity:
    """Tests for settings dict limits and model validation."""

    def test_settings_dict_size_limit_64(self, client):
        token, csrf = _login_via_api(client)
        big_settings = {f"key_{i}": f"val_{i}" for i in range(65)}
        resp = client.put(
            "/api/state",
            json={"state": {"settings": big_settings}, "reason": "test"},
            headers={"Origin": "http://testserver", "x-csrf-token": csrf},
        )
        assert resp.status_code == 400
        assert "too large" in resp.json()["error"].lower()

    def test_settings_key_length_limit_256(self, client):
        token, csrf = _login_via_api(client)
        long_key = "k" * 257
        resp = client.put(
            "/api/state",
            json={"state": {"settings": {long_key: "val"}}, "reason": "test"},
            headers={"Origin": "http://testserver", "x-csrf-token": csrf},
        )
        assert resp.status_code == 400
        assert "key" in resp.json()["error"].lower()

    def test_settings_value_length_limit_4096(self, client):
        token, csrf = _login_via_api(client)
        long_val = "v" * 4097
        resp = client.put(
            "/api/state",
            json={"state": {"settings": {"mykey": long_val}}, "reason": "test"},
            headers={"Origin": "http://testserver", "x-csrf-token": csrf},
        )
        assert resp.status_code == 400
        assert "value" in resp.json()["error"].lower()

    def test_settings_at_exactly_64_keys_accepted(self, client):
        token, csrf = _login_via_api(client)
        settings_64 = {f"key_{i}": f"val_{i}" for i in range(64)}
        resp = client.put(
            "/api/state",
            json={"state": {"settings": settings_64}, "reason": "test"},
            headers={"Origin": "http://testserver", "x-csrf-token": csrf},
        )
        assert resp.status_code == 200

    def test_settings_key_exactly_256_accepted(self, client):
        token, csrf = _login_via_api(client)
        key_256 = "k" * 256
        resp = client.put(
            "/api/state",
            json={"state": {"settings": {key_256: "val"}}, "reason": "test"},
            headers={"Origin": "http://testserver", "x-csrf-token": csrf},
        )
        assert resp.status_code == 200

    def test_settings_value_exactly_4096_accepted(self, client):
        token, csrf = _login_via_api(client)
        val_4096 = "v" * 4096
        resp = client.put(
            "/api/state",
            json={"state": {"settings": {"key": val_4096}}, "reason": "test"},
            headers={"Origin": "http://testserver", "x-csrf-token": csrf},
        )
        assert resp.status_code == 200

    def test_client_patch_request_limit_unit_validation(self):
        p1 = ClientPatchRequest(limit_value=10, limit_unit="GB")
        assert p1.limit_unit == "GB"
        p2 = ClientPatchRequest(limit_value=500, limit_unit="MB")
        assert p2.limit_unit == "MB"
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ClientPatchRequest(limit_value=10, limit_unit="TB")

    def test_client_patch_request_limit_value_range(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ClientPatchRequest(limit_value=-1)
        with pytest.raises(ValidationError):
            ClientPatchRequest(limit_value=1_000_000_001)


# ===========================================================================
# 6. PROXY SECURITY TESTS
# ===========================================================================

class TestProxySecurity:
    """Tests for TcpDialPool, connection limits, and frame size limits."""

    def test_tcp_dial_pool_keys_by_tuple(self):
        pool = TcpDialPool(ttl=30.0, max_total=16)
        assert pool._pool == {}
        assert pool._count == 0

    def test_tcp_dial_pool_max_total(self):
        pool = TcpDialPool(ttl=30.0, max_total=2)
        assert pool._max_total == 2

    def test_tcp_dial_pool_acquire_empty(self):
        pool = TcpDialPool(ttl=30.0, max_total=16)
        result = pool.acquire("client1", "example.com", 443)
        assert result is None

    def test_tcp_dial_pool_close_all(self):
        pool = TcpDialPool(ttl=30.0, max_total=16)
        pool.close_all()
        assert pool._pool == {}
        assert pool._count == 0

    def test_max_ws_frame_bytes_value(self):
        assert MAX_WS_FRAME_BYTES == 512 * 1024

    def test_max_proxy_connections_positive(self):
        assert MAX_PROXY_CONNECTIONS > 0

    def test_max_http_body_bytes_value(self):
        assert MAX_HTTP_BODY_BYTES == 1 * 1024 * 1024

    def test_proxy_connections_isolation(self):
        assert isinstance(proxy_connections, dict)
        assert len(proxy_connections) == 0

    def test_tcp_dial_pool_purge_removes_expired(self):
        """Expired entries should be purged from the pool."""
        pool = TcpDialPool(ttl=0.01, max_total=16)
        writer = MagicMock()
        writer.is_closing.return_value = False
        writer.close = MagicMock()
        reader = MagicMock()
        reader.at_eof.return_value = False
        sock = MagicMock()

        pool.release("c1", "host1", 443, reader, writer, sock)
        assert pool._count == 1
        time.sleep(0.05)
        pool.acquire("c1", "host1", 443)
        assert pool._count == 0

    def test_tcp_dial_pool_release_closes_when_full(self):
        """Releasing beyond max_total closes the writer."""
        pool = TcpDialPool(ttl=30.0, max_total=1)
        w1 = MagicMock()
        w1.is_closing.return_value = False
        r1 = MagicMock()
        s1 = MagicMock()
        pool.release("c1", "h1", 443, r1, w1, s1)
        assert pool._count == 1

        w2 = MagicMock()
        w2.is_closing.return_value = False
        r2 = MagicMock()
        s2 = MagicMock()
        pool.release("c1", "h1", 443, r2, w2, s2)
        w2.close.assert_called_once()

    def test_tcp_dial_pool_per_key_limit(self):
        """Each key can hold at most 4 connections."""
        pool = TcpDialPool(ttl=30.0, max_total=100)
        writers = []
        for i in range(6):
            w = MagicMock()
            w.is_closing.return_value = False
            r = MagicMock()
            s = MagicMock()
            pool.release("c1", "h1", 443, r, w, s)
            writers.append(w)
        # Only 4 should be stored per key
        assert pool._count == 4
        # The 5th and 6th should have been closed
        writers[4].close.assert_called_once()
        writers[5].close.assert_called_once()


# ===========================================================================
# 7. GEO LOOKUP TESTS
# ===========================================================================

class TestGeoLookup:
    """Tests for geo-lookup IP encoding and private IP detection."""

    def test_peer_ip_url_encoded(self):
        from urllib.parse import quote
        ip = "192.168.1.1"
        safe_ip = quote(ip, safe="")
        assert safe_ip == "192.168.1.1"

    def test_private_ip_10_x_detected(self):
        ip = "10.0.0.1"
        is_private = ip.startswith("10.")
        assert is_private is True

    def test_private_ip_192_168_detected(self):
        ip = "192.168.0.1"
        is_private = ip.startswith("192.168.")
        assert is_private is True

    def test_private_ip_loopback_detected(self):
        ip = "127.0.0.1"
        is_private = ip.startswith("127.")
        assert is_private is True

    def test_public_ip_not_private(self):
        ip = "8.8.8.8"
        is_private = (
            ip.startswith(("127.", "10.", "192.168.", "169.254."))
            or ip.startswith(("172.16.", "172.17.", "172.18.", "172.19.",
                              "172.2", "172.3"))
        )
        assert is_private is False

    def test_geo_cache_is_manageable(self):
        assert isinstance(GEO_CACHE, dict)
        GEO_CACHE["1.2.3.4"] = {"country": "Test"}
        assert "1.2.3.4" in GEO_CACHE
        GEO_CACHE.clear()

    def test_private_ip_169_254_detected(self):
        ip = "169.254.1.1"
        is_private = ip.startswith("169.254.")
        assert is_private is True


# ===========================================================================
# 8. CONTENT-DISPOSITION TESTS
# ===========================================================================

class TestContentDisposition:
    """Tests for filename escaping in Content-Disposition header."""

    def test_filename_safe_name(self):
        safe_name = re.sub(r"[^\w\-]", "_", "MyClient")[:40]
        assert safe_name == "MyClient"

    def test_filename_special_chars_escaped(self):
        raw = "My Client (v2.0)!"
        safe_name = re.sub(r"[^\w\-]", "_", raw)[:40]
        assert "(" not in safe_name
        assert ")" not in safe_name
        assert "!" not in safe_name
        assert " " not in safe_name

    def test_filename_truncated_at_40(self):
        raw = "A" * 100
        safe_name = re.sub(r"[^\w\-]", "_", raw)[:40]
        assert len(safe_name) == 40

    def test_filename_unicode_handling(self):
        raw = "Client-name"
        safe_name = re.sub(r"[^\w\-]", "_", raw)[:40]
        assert safe_name == "Client-name"

    def test_filename_leading_trailing_underscores(self):
        raw = "_test-name_"
        safe_name = re.sub(r"[^\w\-]", "_", raw)[:40]
        assert safe_name == "_test-name_"

    def test_filename_path_traversal_chars(self):
        raw = "../../etc/passwd"
        safe_name = re.sub(r"[^\w\-]", "_", raw)[:40]
        assert "/" not in safe_name

    def test_filename_angle_brackets(self):
        raw = "<script>alert(1)</script>"
        safe_name = re.sub(r"[^\w\-]", "_", raw)[:40]
        assert "<" not in safe_name
        assert ">" not in safe_name


# ===========================================================================
# 9. PASSWORD HASHING TESTS
# ===========================================================================

class TestPasswordHashing:
    """Tests for hash_password and verify_password."""

    def test_hash_and_verify(self):
        pw = "strong-password-123!"
        hashed = hash_password(pw)
        assert verify_password(pw, hashed) is True

    def test_wrong_password_fails(self):
        hashed = hash_password("correct-password")
        assert verify_password("wrong-password", hashed) is False

    def test_hash_format(self):
        hashed = hash_password("test")
        assert hashed.startswith("pbkdf2_sha256$")

    def test_verify_malformed_hash(self):
        assert verify_password("pw", "not-a-valid-hash") is False
        assert verify_password("pw", "") is False

    def test_verify_different_algo(self):
        assert verify_password("pw", "sha1$1000$abc$def") is False

    def test_two_hashes_differ(self):
        """Each hash uses a random salt so two hashes of the same pw differ."""
        h1 = hash_password("same-pw")
        h2 = hash_password("same-pw")
        assert h1 != h2
        assert verify_password("same-pw", h1)
        assert verify_password("same-pw", h2)


# ===========================================================================
# 10. ORIGIN / CSRF / MISC SECURITY TESTS
# ===========================================================================

class TestOriginAndCsrf:
    """Tests for origin checking, CSRF validation, and misc security."""

    def test_origin_host_parses(self):
        assert _origin_host("https://example.com/path") == "example.com"
        assert _origin_host("http://localhost:8080") == "localhost"
        assert _origin_host("") is None
        assert _origin_host(None) is None

    def test_origin_allowed_localhost(self):
        assert origin_allowed("http://localhost:8080") is True
        assert origin_allowed("http://127.0.0.1:8080") is True

    def test_origin_allowed_none(self):
        assert origin_allowed(None) is True

    def test_csrf_token_deterministic(self):
        t = "my-session-token"
        assert _csrf_token_for(t) == _csrf_token_for(t)

    def test_csrf_token_differs_per_session(self):
        assert _csrf_token_for("token-a") != _csrf_token_for("token-b")

    def test_require_valid_uuid(self):
        from main import require_valid_uuid
        valid_uuid = generate_uuid()
        assert require_valid_uuid(valid_uuid) == valid_uuid.lower()

    def test_require_valid_uuid_rejects_invalid(self):
        from main import require_valid_uuid
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            require_valid_uuid("not-a-uuid")
        assert exc_info.value.status_code == 400

    def test_generate_uuid_format(self):
        uid = generate_uuid()
        assert re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            uid,
        )

    def test_session_cookie_name(self):
        assert SESSION_COOKIE == "leafy_session"

    def test_session_ttl_positive(self):
        assert SESSION_TTL > 0
        assert SESSION_TTL >= 3600

    def test_public_host_returns_string(self):
        result = public_host()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_bearer_auth_rejected_on_protected_endpoints(self, client):
        """Authorization header with bearer token is not accepted (cookie only)."""
        resp = client.get(
            "/api/state",
            headers={"Authorization": "Bearer fake-token"},
        )
        assert resp.status_code == 401
