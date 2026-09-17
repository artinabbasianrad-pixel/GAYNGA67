"""Comprehensive API endpoint tests for V2Leafy."""

import os
import base64
import hashlib
import time
import secrets
import pytest
import pytest_asyncio

# Set env vars BEFORE importing main
os.environ["SECRET_KEY"] = "test-secret-key-12345"
os.environ["PROMETHEUS"] = "0"  # disable prometheus to avoid metric conflicts
os.environ["GEO_LOOKUP"] = "0"  # disable geo lookups during tests

from httpx import AsyncClient, ASGITransport

# Import after env vars are set
from main import (
    app,
    SESSIONS,
    STATE_MGR,
    SESSION_COOKIE,
    _csrf_token_for,
    hash_password,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TEST_PASSWORD = "testpass123"
BASE = "http://testserver"


def _csrf_for(session_token: str) -> str:
    """Compute the CSRF token for a given session token."""
    return _csrf_token_for(session_token)


def _extract_session_cookie(response) -> str | None:
    """Extract the leafy_session cookie from a response."""
    for header_value in response.headers.get_list("set-cookie"):
        if SESSION_COOKIE in header_value:
            return header_value.split(";")[0].split("=", 1)[1]
    return None


async def do_setup(client: AsyncClient):
    """Perform initial password setup and return (client, session_cookie, csrf_token).

    This is a plain async helper, not a pytest fixture, so it can be called
    directly from any test function.
    """
    # Reset state for each call
    async with STATE_MGR.lock:
        STATE_MGR.state.auth.pass_setup = False
        STATE_MGR.state.auth.password_hash = ""
        STATE_MGR.state.clients.clear()
        STATE_MGR.state.sub_client_subscriptions.clear()
        STATE_MGR.state.settings.clear()
        await STATE_MGR.store.save(STATE_MGR.state)

    # Clear all sessions
    SESSIONS.clear()

    # Call setup with origin header to pass origin check
    resp = await client.post(
        "/api/setup",
        json={"pass": TEST_PASSWORD},
        headers={"Origin": "http://testserver"},
    )
    assert resp.status_code == 200
    assert resp.json()["ok"] is True

    session_cookie = _extract_session_cookie(resp)
    assert session_cookie is not None, "Setup response must set session cookie"

    csrf_token = _csrf_for(session_cookie)
    return client, session_cookie, csrf_token


def _auth_headers(session_cookie: str, csrf_token: str) -> dict:
    """Build headers dict with session cookie and CSRF token."""
    return {
        "Cookie": f"{SESSION_COOKIE}={session_cookie}",
        "X-CSRF-Token": csrf_token,
    }


def _auth_only_headers(session_cookie: str) -> dict:
    """Build headers dict with session cookie but NO CSRF token."""
    return {
        "Cookie": f"{SESSION_COOKIE}={session_cookie}",
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client():
    """Yield an AsyncClient wired to the FastAPI app via ASGI transport."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE) as c:
        yield c


# ===================================================================
# Health endpoints (no auth needed)
# ===================================================================

class TestHealthEndpoints:

    @pytest.mark.asyncio
    async def test_health_check(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "platform" in data
        assert "gateway" in data

    @pytest.mark.asyncio
    async def test_health_head(self, client: AsyncClient):
        resp = await client.head("/health")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_health_ready(self, client: AsyncClient):
        resp = await client.get("/health/ready")
        # May be 200 or 503 depending on socket readiness; just verify structure
        assert resp.status_code in (200, 503)
        data = resp.json()
        assert "status" in data
        assert "checks" in data


# ===================================================================
# Setup endpoint
# ===================================================================

class TestSetup:

    @pytest.mark.asyncio
    async def test_setup_success(self, client: AsyncClient):
        async with STATE_MGR.lock:
            STATE_MGR.state.auth.pass_setup = False
            STATE_MGR.state.auth.password_hash = ""
            await STATE_MGR.store.save(STATE_MGR.state)
        SESSIONS.clear()

        resp = await client.post(
            "/api/setup",
            json={"pass": "mypassword123"},
            headers={"Origin": "http://testserver"},
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert _extract_session_cookie(resp) is not None

    @pytest.mark.asyncio
    async def test_setup_already_done(self, client: AsyncClient):
        async with STATE_MGR.lock:
            STATE_MGR.state.auth.pass_setup = False
            STATE_MGR.state.auth.password_hash = hash_password("pass1234")
            STATE_MGR.state.auth.pass_setup = True
            await STATE_MGR.store.save(STATE_MGR.state)
        SESSIONS.clear()

        resp = await client.post(
            "/api/setup",
            json={"pass": "newpassword"},
            headers={"Origin": "http://testserver"},
        )
        assert resp.status_code == 409
        assert "already" in resp.json()["error"].lower()

    @pytest.mark.asyncio
    async def test_setup_short_password(self, client: AsyncClient):
        async with STATE_MGR.lock:
            STATE_MGR.state.auth.pass_setup = False
            STATE_MGR.state.auth.password_hash = ""
            await STATE_MGR.store.save(STATE_MGR.state)
        SESSIONS.clear()

        resp = await client.post(
            "/api/setup",
            json={"pass": "abc"},  # too short, min_length=4
            headers={"Origin": "http://testserver"},
        )
        assert resp.status_code == 422  # validation error

    @pytest.mark.asyncio
    async def test_setup_cross_origin(self, client: AsyncClient):
        async with STATE_MGR.lock:
            STATE_MGR.state.auth.pass_setup = False
            STATE_MGR.state.auth.password_hash = ""
            await STATE_MGR.store.save(STATE_MGR.state)
        SESSIONS.clear()

        resp = await client.post(
            "/api/setup",
            json={"pass": "validpass123"},
            headers={"Origin": "https://evil.com"},
        )
        assert resp.status_code == 403


# ===================================================================
# Login endpoint
# ===================================================================

class TestLogin:

    @pytest.mark.asyncio
    async def test_login_success(self, client: AsyncClient):
        _, session_cookie, _ = await do_setup(client)
        # Logout first
        headers = _auth_headers(session_cookie, _csrf_for(session_cookie))
        await client.post("/api/logout", headers=headers)
        SESSIONS.clear()

        # Re-setup
        async with STATE_MGR.lock:
            STATE_MGR.state.auth.pass_setup = False
            STATE_MGR.state.auth.password_hash = ""
            await STATE_MGR.store.save(STATE_MGR.state)

        await client.post(
            "/api/setup",
            json={"pass": TEST_PASSWORD},
            headers={"Origin": "http://testserver"},
        )

        resp = await client.post(
            "/api/login",
            json={"pass": TEST_PASSWORD},
            headers={"Origin": "http://testserver"},
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert _extract_session_cookie(resp) is not None

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client: AsyncClient):
        _, _, _ = await do_setup(client)

        resp = await client.post(
            "/api/login",
            json={"pass": "wrongpassword"},
            headers={"Origin": "http://testserver"},
        )
        assert resp.status_code == 401
        assert "invalid" in resp.json()["error"].lower()

    @pytest.mark.asyncio
    async def test_login_no_origin(self, client: AsyncClient):
        _, _, _ = await do_setup(client)

        resp = await client.post(
            "/api/login",
            json={"pass": TEST_PASSWORD},
            # No origin header
        )
        # Without origin, _origin_check returns False -> 403
        assert resp.status_code == 403


# ===================================================================
# Logout endpoint
# ===================================================================

class TestLogout:

    @pytest.mark.asyncio
    async def test_logout_success(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post("/api/logout", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        # Verify session is gone
        resp2 = await client.get("/api/links", headers=_auth_only_headers(session_cookie))
        assert resp2.status_code == 401

    @pytest.mark.asyncio
    async def test_logout_no_auth(self, client: AsyncClient):
        resp = await client.post("/api/logout")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_logout_no_csrf(self, client: AsyncClient):
        _, session_cookie, _ = await do_setup(client)
        headers = _auth_only_headers(session_cookie)

        resp = await client.post("/api/logout", headers=headers)
        assert resp.status_code == 403  # CSRF required


# ===================================================================
# Auth required on protected endpoints (401 without cookie)
# ===================================================================

class TestAuthRequired:

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method,path", [
        ("GET", "/api/state"),
        ("GET", "/api/links"),
        ("GET", "/api/config"),
        ("GET", "/api/sub-link?client=00000000-0000-0000-0000-000000000000"),
        ("GET", "/api/sub/link/00000000-0000-0000-0000-000000000000"),
    ])
    async def test_no_cookie_returns_401(self, client: AsyncClient, method, path):
        resp = await client.request(method, path)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method,path", [
        ("POST", "/api/state"),
        ("POST", "/api/links"),
        ("POST", "/api/action"),
    ])
    async def test_no_cookie_returns_401_post(self, client: AsyncClient, method, path):
        resp = await client.request(method, path, json={})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_expired_session_returns_401(self, client: AsyncClient):
        await do_setup(client)
        # Create an expired session manually
        fake_token = secrets.token_urlsafe(32)
        SESSIONS[fake_token] = {"exp": time.time() - 3600, "created": time.time() - 3600}

        resp = await client.get(
            "/api/links",
            headers=_auth_only_headers(fake_token),
        )
        assert resp.status_code == 401


# ===================================================================
# CSRF protection (403 without CSRF token on mutating endpoints)
# ===================================================================

class TestCSRFProtection:

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method,path,body", [
        ("POST", "/api/state", {"state": {}}),
        ("POST", "/api/action", {"action": "start"}),
        ("POST", "/api/links", {"label": "test"}),
    ])
    async def test_no_csrf_returns_403(self, client: AsyncClient, method, path, body):
        _, session_cookie, _ = await do_setup(client)
        headers = _auth_only_headers(session_cookie)

        resp = await client.request(method, path, json=body, headers=headers)
        assert resp.status_code == 403
        assert "csrf" in resp.json()["error"].lower()

    @pytest.mark.asyncio
    async def test_invalid_csrf_returns_403(self, client: AsyncClient):
        _, session_cookie, _ = await do_setup(client)
        headers = {
            "Cookie": f"{SESSION_COOKIE}={session_cookie}",
            "X-CSRF-Token": "totally-invalid-token",
        }

        resp = await client.post("/api/action", json={"action": "start"}, headers=headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_valid_csrf_passes(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post("/api/action", json={"action": "start"}, headers=headers)
        assert resp.status_code == 200


# ===================================================================
# GET /api/state
# ===================================================================

class TestGetState:

    @pytest.mark.asyncio
    async def test_get_state(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.get("/api/state", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "state" in data
        assert "platform" in data
        assert "telemetry" in data
        assert "gateway" in data
        assert "logs" in data


# ===================================================================
# POST /api/state (update)
# ===================================================================

class TestUpdateState:

    @pytest.mark.asyncio
    async def test_update_state_settings(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/state",
            json={"state": {"settings": {"theme": "dark"}}},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    @pytest.mark.asyncio
    async def test_update_state_clients(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/state",
            json={
                "state": {
                    "clients": [
                        {
                            "id": "11111111-1111-1111-1111-111111111111",
                            "name": "Test Client",
                            "limit": 10.0,
                        }
                    ]
                }
            },
            headers=headers,
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_update_state_settings_too_many_keys(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        big_settings = {f"key{i}": f"value{i}" for i in range(65)}
        resp = await client.post(
            "/api/state",
            json={"state": {"settings": big_settings}},
            headers=headers,
        )
        assert resp.status_code == 400
        assert "too large" in resp.json()["error"].lower()

    @pytest.mark.asyncio
    async def test_update_state_settings_key_too_long(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        long_key = "k" * 257
        resp = await client.post(
            "/api/state",
            json={"state": {"settings": {long_key: "value"}}},
            headers=headers,
        )
        assert resp.status_code == 400
        assert "key" in resp.json()["error"].lower()

    @pytest.mark.asyncio
    async def test_update_state_settings_value_too_long(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        long_value = "v" * 4097
        resp = await client.post(
            "/api/state",
            json={"state": {"settings": {"mykey": long_value}}},
            headers=headers,
        )
        assert resp.status_code == 400
        assert "value" in resp.json()["error"].lower()

    @pytest.mark.asyncio
    async def test_update_state_no_csrf(self, client: AsyncClient):
        _, session_cookie, _ = await do_setup(client)
        headers = _auth_only_headers(session_cookie)

        resp = await client.post(
            "/api/state",
            json={"state": {"settings": {"theme": "dark"}}},
            headers=headers,
        )
        assert resp.status_code == 403


# ===================================================================
# CRUD operations on clients (links)
# ===================================================================

class TestClientCRUD:

    @pytest.mark.asyncio
    async def test_list_links(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.get("/api/links", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "links" in data
        assert isinstance(data["links"], list)

    @pytest.mark.asyncio
    async def test_create_client(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/links",
            json={"label": "New Client", "limit_value": 5.0, "limit_unit": "GB"},
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "uuid" in data
        assert "link" in data

        # Verify it appears in list
        resp2 = await client.get("/api/links", headers=headers)
        assert resp2.status_code == 200
        links = resp2.json()["links"]
        labels = [l["label"] for l in links]
        assert "New Client" in labels

    @pytest.mark.asyncio
    async def test_create_client_with_expiry(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/links",
            json={"label": "Expiring Client", "expiry": "2027-01-15T12:00:00"},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    @pytest.mark.asyncio
    async def test_create_client_active_false(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/links",
            json={"label": "Disabled Client", "active": False},
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        uuid = data["uuid"]

        # Verify in list
        resp2 = await client.get("/api/links", headers=headers)
        for link in resp2.json()["links"]:
            if link["uuid"] == uuid:
                assert link["active"] is False
                break

    @pytest.mark.asyncio
    async def test_create_client_empty_label(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/links",
            json={"label": ""},
            headers=headers,
        )
        assert resp.status_code == 422  # validation error: min_length=1

    @pytest.mark.asyncio
    async def test_create_client_label_too_long(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/links",
            json={"label": "x" * 61},
            headers=headers,
        )
        assert resp.status_code == 422  # max_length=60

    @pytest.mark.asyncio
    async def test_patch_client(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        # Create a client first
        create_resp = await client.post(
            "/api/links",
            json={"label": "Patch Me"},
            headers=headers,
        )
        uuid = create_resp.json()["uuid"]

        # Patch it
        resp = await client.patch(
            f"/api/links/{uuid}",
            json={"label": "Patched Name", "limit_value": 10.0},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        # Verify the change
        resp2 = await client.get("/api/links", headers=headers)
        for link in resp2.json()["links"]:
            if link["uuid"] == uuid:
                assert link["label"] == "Patched Name"
                break

    @pytest.mark.asyncio
    async def test_patch_client_reset_usage(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        create_resp = await client.post(
            "/api/links",
            json={"label": "ResetMe"},
            headers=headers,
        )
        uuid = create_resp.json()["uuid"]

        resp = await client.patch(
            f"/api/links/{uuid}",
            json={"reset_usage": True},
            headers=headers,
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_patch_client_billing_cycle(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        create_resp = await client.post(
            "/api/links",
            json={"label": "Billing Client"},
            headers=headers,
        )
        uuid = create_resp.json()["uuid"]

        resp = await client.patch(
            f"/api/links/{uuid}",
            json={"billing_cycle": "monthly"},
            headers=headers,
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_patch_nonexistent_client_returns_404(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        fake_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        resp = await client.patch(
            f"/api/links/{fake_uuid}",
            json={"label": "Ghost"},
            headers=headers,
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_patch_client_invalid_uuid(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.patch(
            "/api/links/not-a-uuid",
            json={"label": "Bad"},
            headers=headers,
        )
        assert resp.status_code == 400
        assert "invalid" in resp.json()["error"].lower()

    @pytest.mark.asyncio
    async def test_delete_client(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        # Create
        create_resp = await client.post(
            "/api/links",
            json={"label": "Delete Me"},
            headers=headers,
        )
        uuid = create_resp.json()["uuid"]

        # Delete
        resp = await client.delete(f"/api/links/{uuid}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        # Verify gone
        resp2 = await client.get("/api/links", headers=headers)
        uuids = [l["uuid"] for l in resp2.json()["links"]]
        assert uuid not in uuids

    @pytest.mark.asyncio
    async def test_delete_nonexistent_client_returns_404(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        fake_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        resp = await client.delete(f"/api/links/{fake_uuid}", headers=headers)
        assert resp.status_code == 404
        assert "not found" in resp.json()["error"].lower()

    @pytest.mark.asyncio
    async def test_delete_client_invalid_uuid(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.delete("/api/links/bad-uuid", headers=headers)
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_create_limit_mb(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/links",
            json={"label": "MB Client", "limit_value": 500.0, "limit_unit": "MB"},
            headers=headers,
        )
        assert resp.status_code == 200


# ===================================================================
# Token rotation and sub-slug
# ===================================================================

class TestTokenOperations:

    @pytest.mark.asyncio
    async def test_rotate_ws_token(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        create_resp = await client.post(
            "/api/links", json={"label": "Token Test"}, headers=headers
        )
        uuid = create_resp.json()["uuid"]

        resp = await client.post(f"/api/links/{uuid}/token", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "ws_token" in data
        assert len(data["ws_token"]) > 0

    @pytest.mark.asyncio
    async def test_rotate_token_nonexistent(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/links/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/token", headers=headers
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_regenerate_sub_slug(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        create_resp = await client.post(
            "/api/links", json={"label": "Slug Test"}, headers=headers
        )
        uuid = create_resp.json()["uuid"]

        resp = await client.post(f"/api/links/{uuid}/sub-slug", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "sub_slug" in data


# ===================================================================
# Subscription link endpoints
# ===================================================================

class TestSubscriptionLinks:

    @pytest.mark.asyncio
    async def test_get_single_link_sub(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        create_resp = await client.post(
            "/api/links", json={"label": "Sub Test"}, headers=headers
        )
        uuid = create_resp.json()["uuid"]

        resp = await client.get(f"/api/links/{uuid}/sub", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "subscription_url" in data
        assert "config" in data
        assert "label" in data

    @pytest.mark.asyncio
    async def test_get_single_link_sub_nonexistent(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.get(
            "/api/links/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/sub", headers=headers
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_sub_link_url(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        create_resp = await client.post(
            "/api/links", json={"label": "SubURL Test"}, headers=headers
        )
        uuid = create_resp.json()["uuid"]

        resp = await client.get(
            f"/api/sub/link/{uuid}", headers=headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "link" in data
        assert "/sub/" in data["link"]

    @pytest.mark.asyncio
    async def test_get_sub_link_url_nonexistent(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.get(
            "/api/sub/link/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", headers=headers
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_sub_link_url_invalid_uuid(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.get("/api/sub/link/bad-id", headers=headers)
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_get_sub_link_endpoint(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        create_resp = await client.post(
            "/api/links", json={"label": "SubEndpoint Test"}, headers=headers
        )
        uuid = create_resp.json()["uuid"]

        resp = await client.get(
            f"/api/sub-link?client={uuid}",
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "link" in data

    @pytest.mark.asyncio
    async def test_get_sub_link_endpoint_invalid_client(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.get(
            "/api/sub-link?client=not-a-uuid",
            headers=headers,
        )
        assert resp.status_code == 400


# ===================================================================
# Gateway actions
# ===================================================================

class TestGatewayActions:

    @pytest.mark.asyncio
    async def test_action_start(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/action", json={"action": "start"}, headers=headers
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["action"] == "start"

    @pytest.mark.asyncio
    async def test_action_stop(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/action", json={"action": "stop"}, headers=headers
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_action_restart(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/action", json={"action": "restart"}, headers=headers
        )
        assert resp.status_code == 200
        assert resp.json()["action"] == "restart"

    @pytest.mark.asyncio
    async def test_action_clear_logs(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/action", json={"action": "clear_logs"}, headers=headers
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_action_invalid_action(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/action", json={"action": "fly_away"}, headers=headers
        )
        assert resp.status_code == 422  # validation error


# ===================================================================
# Config endpoint
# ===================================================================

class TestConfig:

    @pytest.mark.asyncio
    async def test_config(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.get("/api/config", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "config" in data
        assert "transport" in data["config"]
        assert "protocol" in data["config"]
        assert data["config"]["transport"] == "WebSocket"
        assert data["config"]["protocol"] == "VLESS"


# ===================================================================
# /api/me endpoint
# ===================================================================

class TestMe:

    @pytest.mark.asyncio
    async def test_me_authenticated(self, client: AsyncClient):
        _, session_cookie, _ = await do_setup(client)
        headers = _auth_only_headers(session_cookie)

        resp = await client.get("/api/me", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["authenticated"] is True
        assert data["pass_setup"] is True

    @pytest.mark.asyncio
    async def test_me_unauthenticated(self, client: AsyncClient):
        resp = await client.get("/api/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["authenticated"] is False


# ===================================================================
# Connection kill endpoint
# ===================================================================

class TestConnectionKill:

    @pytest.mark.asyncio
    async def test_kill_nonexistent_connection(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/connections/fake-conn-id/kill", headers=headers
        )
        assert resp.status_code == 404


# ===================================================================
# Body size limit middleware
# ===================================================================

class TestBodySizeLimit:

    @pytest.mark.asyncio
    async def test_large_body_returns_413(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        # Simulate a request with a Content-Length that exceeds MAX_HTTP_BODY_BYTES (1MB)
        headers_with_size = {**headers, "Content-Length": str(2 * 1024 * 1024)}
        resp = await client.post(
            "/api/state",
            headers=headers_with_size,
            content=b"x" * 1024,  # actual body is small but header says big
        )
        # The middleware checks content-length header value, so 413 if > 1MB
        assert resp.status_code == 413


# ===================================================================
# Input validation edge cases
# ===================================================================

class TestInputValidation:

    @pytest.mark.asyncio
    async def test_negative_limit_rejected(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/links",
            json={"label": "Negative", "limit_value": -5.0},
            headers=headers,
        )
        assert resp.status_code == 422  # ge=0

    @pytest.mark.asyncio
    async def test_huge_limit_rejected(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/links",
            json={"label": "Huge", "limit_value": 999_999_999_999},
            headers=headers,
        )
        assert resp.status_code == 422  # le=1_000_000_000

    @pytest.mark.asyncio
    async def test_patch_limit_bounds(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        create_resp = await client.post(
            "/api/links", json={"label": "Bounds"}, headers=headers
        )
        uuid = create_resp.json()["uuid"]

        resp = await client.patch(
            f"/api/links/{uuid}",
            json={"limit_value": -1.0},
            headers=headers,
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_create_client_default_limit(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.post(
            "/api/links",
            json={"label": "Default Limit"},
            headers=headers,
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_patch_client_limit_mb(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        create_resp = await client.post(
            "/api/links", json={"label": "MB Patch"}, headers=headers
        )
        uuid = create_resp.json()["uuid"]

        resp = await client.patch(
            f"/api/links/{uuid}",
            json={"limit_value": 256.0, "limit_unit": "MB"},
            headers=headers,
        )
        assert resp.status_code == 200


# ===================================================================
# Session behavior
# ===================================================================

class TestSessionBehavior:

    @pytest.mark.asyncio
    async def test_login_creates_session(self, client: AsyncClient):
        _, session_cookie, _ = await do_setup(client)
        assert session_cookie is not None
        assert len(session_cookie) > 10

    @pytest.mark.asyncio
    async def test_multiple_logins_create_sessions(self, client: AsyncClient):
        _, session_cookie1, _ = await do_setup(client)

        resp = await client.post(
            "/api/login",
            json={"pass": TEST_PASSWORD},
            headers={"Origin": "http://testserver"},
        )
        session_cookie2 = _extract_session_cookie(resp)
        assert session_cookie2 is not None
        assert session_cookie1 != session_cookie2

    @pytest.mark.asyncio
    async def test_logout_invalidates_session(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)

        resp = await client.post(
            "/api/logout", headers=_auth_headers(session_cookie, csrf)
        )
        assert resp.status_code == 200

        resp2 = await client.get(
            "/api/links", headers=_auth_only_headers(session_cookie)
        )
        assert resp2.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_cookie_returns_401(self, client: AsyncClient):
        await do_setup(client)

        resp = await client.get(
            "/api/links",
            headers=_auth_only_headers("totally-fake-session-token"),
        )
        assert resp.status_code == 401


# ===================================================================
# Security headers middleware
# ===================================================================

class TestSecurityHeaders:

    @pytest.mark.asyncio
    async def test_security_headers_present(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert "Content-Security-Policy" in resp.headers
        assert "X-Content-Type-Options" in resp.headers
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert "X-Frame-Options" in resp.headers
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert "Referrer-Policy" in resp.headers
        assert "Server" in resp.headers
        assert resp.headers["Server"] == "V2Leafy"

    @pytest.mark.asyncio
    async def test_api_cache_control(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        resp = await client.get("/api/links", headers=headers)
        assert resp.status_code == 200
        assert "Cache-Control" in resp.headers


# ===================================================================
# Full CRUD lifecycle
# ===================================================================

class TestFullCRUDLifecycle:
    """Test a complete create-read-update-delete cycle on clients."""

    @pytest.mark.asyncio
    async def test_full_lifecycle(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        # 1. Create
        create_resp = await client.post(
            "/api/links",
            json={
                "label": "Lifecycle Client",
                "limit_value": 10.0,
                "limit_unit": "GB",
                "expiry": "2027-06-01T00:00:00",
            },
            headers=headers,
        )
        assert create_resp.status_code == 200
        uuid = create_resp.json()["uuid"]
        original_link = create_resp.json()["link"]
        assert "vless://" in original_link

        # 2. Read via list
        list_resp = await client.get("/api/links", headers=headers)
        assert list_resp.status_code == 200
        found = [l for l in list_resp.json()["links"] if l["uuid"] == uuid]
        assert len(found) == 1
        assert found[0]["label"] == "Lifecycle Client"
        assert found[0]["limit_bytes"] == int(10.0 * (1024 ** 3))
        assert found[0]["active"] is True

        # 3. Read via sub endpoint
        sub_resp = await client.get(f"/api/links/{uuid}/sub", headers=headers)
        assert sub_resp.status_code == 200
        assert sub_resp.json()["label"] == "Lifecycle Client"

        # 4. Update (patch)
        patch_resp = await client.patch(
            f"/api/links/{uuid}",
            json={
                "label": "Updated Lifecycle",
                "limit_value": 20.0,
                "active": False,
            },
            headers=headers,
        )
        assert patch_resp.status_code == 200

        # 5. Verify update
        list_resp2 = await client.get("/api/links", headers=headers)
        found2 = [l for l in list_resp2.json()["links"] if l["uuid"] == uuid]
        assert len(found2) == 1
        assert found2[0]["label"] == "Updated Lifecycle"
        assert found2[0]["active"] is False

        # 6. Delete
        del_resp = await client.delete(f"/api/links/{uuid}", headers=headers)
        assert del_resp.status_code == 200

        # 7. Confirm gone
        list_resp3 = await client.get("/api/links", headers=headers)
        assert uuid not in [l["uuid"] for l in list_resp3.json()["links"]]


# ===================================================================
# State snapshot after operations
# ===================================================================

class TestStateSnapshot:

    @pytest.mark.asyncio
    async def test_state_reflects_clients(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        create_resp = await client.post(
            "/api/links",
            json={"label": "Snapshot Test"},
            headers=headers,
        )
        uuid = create_resp.json()["uuid"]

        state_resp = await client.get("/api/state", headers=headers)
        state = state_resp.json()["state"]
        assert "clients" in state
        client_ids = [c["id"] for c in state["clients"]]
        assert uuid in client_ids

    @pytest.mark.asyncio
    async def test_state_after_delete(self, client: AsyncClient):
        _, session_cookie, csrf = await do_setup(client)
        headers = _auth_headers(session_cookie, csrf)

        create_resp = await client.post(
            "/api/links", json={"label": "Gone"}, headers=headers
        )
        uuid = create_resp.json()["uuid"]

        await client.delete(f"/api/links/{uuid}", headers=headers)

        state_resp = await client.get("/api/state", headers=headers)
        state = state_resp.json()["state"]
        client_ids = [c["id"] for c in state["clients"]]
        assert uuid not in client_ids
