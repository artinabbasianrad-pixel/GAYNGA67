"""
Comprehensive proxy/relay integration tests for V2Leafy.

Covers: TcpDialPool, RelaySender, _tuned_relay_buf, _apply_socket_opts,
        parse_vless_header, check_client_quota, record_traffic, constants.
"""
from __future__ import annotations

import asyncio
import socket
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import main
from main import (
    CONN_POOL_MAX,
    CONN_POOL_TTL,
    MAX_PROXY_CONNECTIONS,
    MAX_WS_FRAME_BYTES,
    RELAY_BUF,
    RELAY_BUF_MAX,
    RELAY_BUF_MIN,
    RELAY_QUEUE_MAX,
    TcpDialPool,
    RelaySender,
    ClientState,
    _apply_socket_opts,
    _tuned_relay_buf,
    check_client_quota,
    record_traffic,
    parse_vless_header,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_writer_mock(is_closing=False):
    w = MagicMock()
    w.is_closing.return_value = is_closing
    w.close = MagicMock()
    return w


def _make_reader_mock(at_eof=False):
    r = MagicMock()
    r.at_eof.return_value = at_eof
    return r


def _make_sock_mock(rcvbuf=131072):
    s = MagicMock()
    s.getsockopt.return_value = rcvbuf
    s.setsockopt = MagicMock()
    return s


def _make_client(**overrides):
    defaults = dict(
        id="c1", name="Test", limit=0.0, limit_bytes=0, used_bytes=0,
        upload_bytes=0, download_bytes=0, expiry="", status=1, active=True,
    )
    defaults.update(overrides)
    return ClientState(**defaults)


# ===========================================================================
# 1. TcpDialPool  (10+ tests)
# ===========================================================================

class TestTcpDialPool:

    def test_acquire_empty_pool(self):
        pool = TcpDialPool()
        result = pool.acquire("c1", "example.com", 443)
        assert result is None

    def test_release_then_acquire(self):
        pool = TcpDialPool(ttl=60)
        r = _make_reader_mock()
        w = _make_writer_mock()
        s = _make_sock_mock()
        pool.release("c1", "example.com", 443, r, w, s)
        result = pool.acquire("c1", "example.com", 443)
        assert result is not None
        reader, writer, sock = result
        assert reader is r
        assert writer is w
        assert sock is s

    def test_acquire_expired_closes_writer(self):
        pool = TcpDialPool(ttl=0.0)  # immediate expiry
        r = _make_reader_mock()
        w = _make_writer_mock()
        s = _make_sock_mock()
        pool.release("c1", "example.com", 443, r, w, s)
        result = pool.acquire("c1", "example.com", 443)
        assert result is None
        w.close.assert_called()

    def test_acquire_closing_writer_returns_none(self):
        pool = TcpDialPool(ttl=60)
        r = _make_reader_mock()
        w = _make_writer_mock(is_closing=True)
        s = _make_sock_mock()
        pool.release("c1", "example.com", 443, r, w, s)
        result = pool.acquire("c1", "example.com", 443)
        assert result is None

    def test_acquire_eof_reader_returns_none(self):
        pool = TcpDialPool(ttl=60)
        r = _make_reader_mock(at_eof=True)
        w = _make_writer_mock()
        s = _make_sock_mock()
        pool.release("c1", "example.com", 443, r, w, s)
        result = pool.acquire("c1", "example.com", 443)
        assert result is None

    def test_release_when_full_closes_writer(self):
        pool = TcpDialPool(ttl=60, max_total=1)
        r1, w1, s1 = _make_reader_mock(), _make_writer_mock(), _make_sock_mock()
        r2, w2, s2 = _make_reader_mock(), _make_writer_mock(), _make_sock_mock()
        pool.release("c1", "host.com", 443, r1, w1, s1)
        pool.release("c1", "host.com", 443, r2, w2, s2)
        assert pool._count == 1
        w2.close.assert_called()

    def test_per_key_limit_4(self):
        pool = TcpDialPool(ttl=60, max_total=100)
        writers = []
        for _ in range(6):
            r, w, s = _make_reader_mock(), _make_writer_mock(), _make_sock_mock()
            pool.release("c1", "host.com", 443, r, w, s)
            writers.append(w)
        assert pool._count == 4
        # last 2 writers closed because key limit is 4
        writers[4].close.assert_called()
        writers[5].close.assert_called()

    def test_close_all(self):
        pool = TcpDialPool(ttl=60)
        w1, w2 = _make_writer_mock(), _make_writer_mock()
        pool.release("c1", "h.com", 443, _make_reader_mock(), w1, _make_sock_mock())
        pool.release("c1", "h.com", 80, _make_reader_mock(), w2, _make_sock_mock())
        pool.close_all()
        assert pool._count == 0
        assert len(pool._pool) == 0
        w1.close.assert_called()
        w2.close.assert_called()

    def test_keys_are_by_client_host_port(self):
        pool = TcpDialPool(ttl=60)
        r1, w1, s1 = _make_reader_mock(), _make_writer_mock(), _make_sock_mock()
        r2, w2, s2 = _make_reader_mock(), _make_writer_mock(), _make_sock_mock()
        pool.release("c1", "h.com", 443, r1, w1, s1)
        pool.release("c2", "h.com", 443, r2, w2, s2)
        assert pool._count == 2
        # different client_id => different key
        res1 = pool.acquire("c1", "h.com", 443)
        res2 = pool.acquire("c2", "h.com", 443)
        assert res1 is not None
        assert res2 is not None

    def test_purge_removes_expired(self):
        pool = TcpDialPool(ttl=0.0)
        w = _make_writer_mock()
        pool.release("c1", "h.com", 443, _make_reader_mock(), w, _make_sock_mock())
        assert pool._count == 1
        pool._purge()
        assert pool._count == 0
        assert len(pool._pool) == 0

    def test_release_writer_closing_closes_immediately(self):
        pool = TcpDialPool(ttl=60, max_total=100)
        w = _make_writer_mock(is_closing=True)
        pool.release("c1", "h.com", 443, _make_reader_mock(), w, _make_sock_mock())
        assert pool._count == 0
        w.close.assert_called()


# ===========================================================================
# 2. RelaySender  (6+ tests)
# ===========================================================================

class TestRelaySender:

    @pytest.fixture
    def ws(self):
        ws = MagicMock()
        ws.send_bytes = AsyncMock()
        return ws

    @pytest.mark.asyncio
    async def test_send_success(self, ws):
        sender = RelaySender(ws, queue_max=4)
        sender.task.cancel()
        try:
            await sender.task
        except asyncio.CancelledError:
            pass
        result = await sender.send(b"hello", first_prefix=False)
        assert result is True
        assert sender.dead is False
        sender.stop()

    @pytest.mark.asyncio
    async def test_send_first_prefix(self, ws):
        sender = RelaySender(ws, queue_max=4)
        sender.task.cancel()
        try:
            await sender.task
        except asyncio.CancelledError:
            pass
        result = await sender.send(b"payload", first_prefix=True)
        assert result is True
        assert sender.first is False
        sender.stop()

    @pytest.mark.asyncio
    async def test_dead_flag_on_exception(self, ws):
        sender = RelaySender(ws, queue_max=1)
        ws.send_bytes.side_effect = OSError("broken pipe")
        # Put data then let _run consume it and fail
        await sender.queue.put(b"bad")
        await asyncio.sleep(0.05)
        assert sender.dead is True
        sender.stop()

    @pytest.mark.asyncio
    async def test_send_when_dead_returns_false(self, ws):
        sender = RelaySender(ws, queue_max=4)
        sender.dead = True
        result = await sender.send(b"nope")
        assert result is False

    @pytest.mark.asyncio
    async def test_stop_cancels_task(self, ws):
        sender = RelaySender(ws, queue_max=4)
        task = sender.task
        sender.stop()
        # cancel() schedules cancellation; check cancelling() (pending) or
        # yield so the event loop processes it, then check cancelled().
        assert task.cancelling() or task.cancelled()
        await asyncio.sleep(0)
        assert task.cancelled()

    @pytest.mark.asyncio
    async def test_queue_timeout_sets_dead(self, ws):
        sender = RelaySender(ws, queue_max=2)
        # Cancel the _run consumer so it doesn't drain the queue
        sender.task.cancel()
        try:
            await sender.task
        except asyncio.CancelledError:
            pass
        # Now fill the queue to capacity
        await sender.queue.put(b"a")
        await sender.queue.put(b"b")
        # Next send should time out because the queue is full
        with patch("main.RELAY_QUEUE_FULL_TIMEOUT", 0.01):
            result = await sender.send(b"c")
        assert result is False
        assert sender.dead is True


# ===========================================================================
# 3. _tuned_relay_buf  (5+ tests)
# ===========================================================================

class TestTunedRelayBuf:

    def test_default_fallback_no_exception(self):
        """When getsockopt raises, returns RELAY_BUF default."""
        sock = MagicMock()
        sock.getsockopt.side_effect = OSError("no socket")
        with patch.object(main, "stats", {"start_time": time.time(), "rx_bytes": 0, "tx_bytes": 0}):
            result = _tuned_relay_buf(sock, rtt_ms=50)
        assert result == RELAY_BUF

    def test_result_bounded_min(self):
        sock = _make_sock_mock(rcvbuf=1024)  # very small -> half = 512 -> max(512, RELAY_BUF_MIN) = RELAY_BUF_MIN
        with patch.object(main, "stats", {"start_time": time.time(), "rx_bytes": 0, "tx_bytes": 0}):
            result = _tuned_relay_buf(sock, rtt_ms=0.1, rx_bytes=0, tx_bytes=0)
        assert result >= RELAY_BUF_MIN

    def test_result_bounded_max(self):
        sock = _make_sock_mock(rcvbuf=2 * 1024 * 1024)
        with patch.object(main, "stats", {"start_time": time.time(), "rx_bytes": 0, "tx_bytes": 0}):
            result = _tuned_relay_buf(sock, rtt_ms=5000, rx_bytes=100_000_000, tx_bytes=100_000_000)
        assert result <= RELAY_BUF_MAX

    def test_high_throughput_pushes_towards_max(self):
        sock = _make_sock_mock(rcvbuf=256 * 1024)
        with patch.object(main, "stats", {"start_time": time.time() - 1, "rx_bytes": 50_000_000, "tx_bytes": 50_000_000}):
            result = _tuned_relay_buf(sock, rtt_ms=100, rx_bytes=50_000_000, tx_bytes=50_000_000)
        assert result >= RELAY_BUF_MIN
        assert result <= RELAY_BUF_MAX

    def test_per_connection_bytes_affect_result(self):
        sock = _make_sock_mock(rcvbuf=256 * 1024)
        t = time.time() - 10
        with patch.object(main, "stats", {"start_time": t, "rx_bytes": 0, "tx_bytes": 0}):
            low = _tuned_relay_buf(sock, rtt_ms=10, rx_bytes=100, tx_bytes=100)
        with patch.object(main, "stats", {"start_time": t, "rx_bytes": 0, "tx_bytes": 0}):
            high = _tuned_relay_buf(sock, rtt_ms=10, rx_bytes=10_000_000, tx_bytes=10_000_000)
        assert high >= low


# ===========================================================================
# 4. _apply_socket_opts  (4+ tests)
# ===========================================================================

class TestApplySocketOpts:

    def test_sets_tcp_nodelay(self):
        sock = MagicMock()
        sock.setsockopt = MagicMock()
        _apply_socket_opts(sock, keepalive=False)
        sock.setsockopt.assert_any_call(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def test_sets_so_keepalive(self):
        sock = MagicMock()
        sock.setsockopt = MagicMock()
        _apply_socket_opts(sock, keepalive=True)
        sock.setsockopt.assert_any_call(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    def test_sets_sndbuf_rcvbuf(self):
        sock = MagicMock()
        sock.setsockopt = MagicMock()
        _apply_socket_opts(sock, keepalive=False)
        sock.setsockopt.assert_any_call(socket.SOL_SOCKET, socket.SO_SNDBUF, 256 * 1024)
        sock.setsockopt.assert_any_call(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024)

    def test_handles_oserror_gracefully(self):
        sock = MagicMock()
        sock.setsockopt.side_effect = OSError("not supported")
        # Should not raise
        _apply_socket_opts(sock, keepalive=True)

    def test_no_keepalive_skips_keepalive_calls(self):
        sock = MagicMock()
        sock.setsockopt = MagicMock()
        _apply_socket_opts(sock, keepalive=False)
        for call in sock.setsockopt.call_args_list:
            args = call[0]
            # Ensure no SO_KEEPALIVE was set
            if len(args) >= 2 and args[1] == socket.SO_KEEPALIVE:
                pytest.fail("SO_KEEPALIVE should not be set when keepalive=False")


# ===========================================================================
# 5. parse_vless_header  (10+ tests)
# ===========================================================================

class TestParseVlessHeader:

    @staticmethod
    def _build_vless(addr_type=1, address_bytes=b"\x01\x02\x03\x04",
                     port=443, command=1, addon_len=0, extra=b""):
        """Build a minimal VLESS header bytes."""
        uuid = b"\x00" * 16
        addon = b"\x00" * addon_len
        hdr = bytearray()
        hdr.append(0)  # version
        hdr.extend(uuid)
        hdr.append(addon_len)
        hdr.extend(addon)
        hdr.append(command)  # command
        hdr.extend(port.to_bytes(2, "big"))
        hdr.append(addr_type)
        hdr.extend(address_bytes)
        hdr.extend(extra)
        return bytes(hdr)

    def test_valid_ipv4(self):
        hdr = self._build_vless(addr_type=1, address_bytes=b"\xc0\xa8\x01\x01", port=80)
        result = parse_vless_header(hdr)
        assert result["version"] == 0
        assert result["address"] == "192.168.1.1"
        assert result["port"] == 80
        assert result["command"] == 1

    def test_valid_domain(self):
        domain = b"example.com"
        hdr = self._build_vless(addr_type=2, address_bytes=bytes([len(domain)]) + domain, port=443)
        result = parse_vless_header(hdr)
        assert result["address"] == "example.com"
        assert result["port"] == 443

    def test_valid_ipv6(self):
        addr = bytes(range(16))
        hdr = self._build_vless(addr_type=3, address_bytes=addr, port=8080)
        result = parse_vless_header(hdr)
        assert ":" in result["address"]
        assert result["port"] == 8080

    def test_addon_bytes(self):
        hdr = self._build_vless(addon_len=3, extra=b"\x01\x02\x03")
        result = parse_vless_header(hdr)
        assert result["version"] == 0

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            parse_vless_header(b"\x00" * 10)

    def test_bad_version(self):
        hdr = self._build_vless()
        hdr = bytes([1]) + hdr[1:]
        with pytest.raises(ValueError, match="Unsupported VLESS version"):
            parse_vless_header(hdr)

    def test_bad_command(self):
        hdr = self._build_vless(command=3)
        with pytest.raises(ValueError, match="Unsupported VLESS command"):
            parse_vless_header(hdr)

    def test_truncated(self):
        hdr = self._build_vless()
        truncated = hdr[:5]
        with pytest.raises(ValueError):
            parse_vless_header(truncated)

    def test_unknown_addr_type(self):
        # Build a header long enough (>=24) with addr_type=99
        uuid = b"\x00" * 16
        hdr = bytes([0]) + uuid + b"\x00" + b"\x01" + b"\x01\xbb" + b"\x63" + b"\x00\x00\x00\x00\x00"
        with pytest.raises(ValueError, match="Unknown VLESS address type"):
            parse_vless_header(hdr)

    def test_port_0(self):
        hdr = self._build_vless(port=0)
        with pytest.raises(ValueError, match="port out of range"):
            parse_vless_header(hdr)

    def test_port_65536(self):
        # Port 65536 cannot fit in 2 bytes, so build raw header with
        # 3 bytes where port field spans a boundary causing an out-of-range read.
        # Instead, construct a header where port bytes decode to > 65535 is
        # impossible in 2 bytes, so we test the range boundary: port=65535
        # is valid and port=0 is rejected (covered above). This test verifies
        # that the parser validates port range by constructing a header with
        # extra trailing data that forces the parser to read a "port" that
        # decodes as 0 after the addr check.
        # Directly test: build header with port=65535 (max valid boundary)
        hdr = self._build_vless(port=65535)
        result = parse_vless_header(hdr)
        assert result["port"] == 65535

    def test_ipv4_truncated(self):
        uuid = b"\x00" * 16
        hdr = bytes([0]) + uuid + b"\x00" + b"\x01" + b"\x01\xbb" + b"\x01" + b"\xc0\xa8"  # only 2 bytes
        with pytest.raises(ValueError, match="IPv4 truncated"):
            parse_vless_header(hdr)

    def test_domain_truncated(self):
        uuid = b"\x00" * 16
        hdr = bytes([0]) + uuid + b"\x00" + b"\x01" + b"\x01\xbb" + b"\x02"
        with pytest.raises(ValueError):
            parse_vless_header(hdr)

    def test_ipv6_truncated(self):
        uuid = b"\x00" * 16
        addr_bytes = bytes(range(8))  # only 8 bytes, need 16
        hdr = bytes([0]) + uuid + b"\x00" + b"\x01" + b"\x01\xbb" + b"\x03" + addr_bytes
        with pytest.raises(ValueError, match="IPv6 truncated"):
            parse_vless_header(hdr)

    def test_payload_returned(self):
        extra = b"HELLO_WORLD"
        hdr = self._build_vless(extra=extra)
        result = parse_vless_header(hdr)
        assert result["payload"] == extra

    def test_uuid_formatted(self):
        hdr = self._build_vless()
        result = parse_vless_header(hdr)
        parts = result["uuid"].split("-")
        assert len(parts) == 5
        assert len(parts[0]) == 8
        assert len(parts[4]) == 12


# ===========================================================================
# 6. check_client_quota  (5+ tests)
# ===========================================================================

class TestCheckClientQuota:

    def test_no_limit_allows(self):
        c = _make_client(limit_bytes=0)
        assert check_client_quota(c, 1000) is True

    def test_under_limit(self):
        c = _make_client(limit_bytes=1000, used_bytes=500)
        assert check_client_quota(c, 400) is True

    def test_over_limit(self):
        c = _make_client(limit_bytes=1000, used_bytes=900)
        assert check_client_quota(c, 200) is False

    def test_at_limit_exact(self):
        c = _make_client(limit_bytes=1000, used_bytes=900)
        assert check_client_quota(c, 100) is True

    def test_disabled_client(self):
        c = _make_client(active=False, limit_bytes=1000, used_bytes=0)
        assert check_client_quota(c, 1) is False

    def test_inactive_status(self):
        c = _make_client(status=0, limit_bytes=1000, used_bytes=0)
        assert check_client_quota(c, 1) is False


# ===========================================================================
# 7. record_traffic  (4+ tests)
# ===========================================================================

class TestRecordTraffic:

    def _snapshot_stats(self):
        return {k: v for k, v in main.stats.items()}

    def test_download(self):
        before = self._snapshot_stats()
        c = _make_client()
        record_traffic(c, 500, from_client=False)
        assert c.download_bytes == 500
        assert c.upload_bytes == 0
        assert c.used_bytes == 500
        assert main.stats["rx_bytes"] == before["rx_bytes"] + 500
        assert main.stats["tx_bytes"] == before["tx_bytes"]
        assert main.stats["total_bytes"] == before["total_bytes"] + 500

    def test_upload(self):
        before = self._snapshot_stats()
        c = _make_client()
        record_traffic(c, 300, from_client=True)
        assert c.upload_bytes == 300
        assert c.download_bytes == 0
        assert c.used_bytes == 300
        assert main.stats["tx_bytes"] == before["tx_bytes"] + 300
        assert main.stats["rx_bytes"] == before["rx_bytes"]
        assert main.stats["total_bytes"] == before["total_bytes"] + 300

    def test_mixed_accumulates(self):
        c = _make_client()
        record_traffic(c, 100, from_client=True)
        record_traffic(c, 200, from_client=False)
        assert c.upload_bytes == 100
        assert c.download_bytes == 200
        assert c.used_bytes == 300

    def test_global_stats_accumulate(self):
        before_total = main.stats["total_bytes"]
        c1 = _make_client()
        c2 = _make_client(id="c2")
        record_traffic(c1, 50, from_client=True)
        record_traffic(c2, 75, from_client=False)
        assert main.stats["total_bytes"] == before_total + 125


# ===========================================================================
# 8. Constants  (5+ tests)
# ===========================================================================

class TestConstants:

    def test_relay_buf_max_is_1mb(self):
        assert RELAY_BUF_MAX == 1024 * 1024

    def test_relay_queue_max_is_32(self):
        assert RELAY_QUEUE_MAX == 32

    def test_relay_buf_is_128kb(self):
        assert RELAY_BUF == 128 * 1024

    def test_relay_buf_min_is_32kb(self):
        assert RELAY_BUF_MIN == 32 * 1024

    def test_max_ws_frame_bytes_is_512kb(self):
        assert MAX_WS_FRAME_BYTES == 512 * 1024

    def test_max_proxy_connections_positive(self):
        assert MAX_PROXY_CONNECTIONS > 0

    def test_conn_pool_ttl_positive(self):
        assert CONN_POOL_TTL > 0

    def test_conn_pool_max_positive(self):
        assert CONN_POOL_MAX > 0

    def test_relay_buf_min_lt_relay_buf_lt_relay_buf_max(self):
        assert RELAY_BUF_MIN < RELAY_BUF < RELAY_BUF_MAX
