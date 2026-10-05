"""The sidecar (A) side of the A<->B channel.

The channel is how the untrusted-adjacent agent process reaches the sidecar. It
must: serve inputs and accept a stream only to an authorized caller; deliver
events in order; end cleanly on the done sentinel; and -- the property that keeps
a dead B from hanging the run -- synthesize a failure done when the stream drops
without one.
"""

import asyncio
import json

import httpx
import pytest

from andyur.runner.agentchannel import AgentChannel
from andyur.runner.protocol import done_event, encode

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


INPUTS = {"agent": "alice", "run_id": "r1", "prompt": "do it", "run_type": "headless"}


async def _collect(channel):
    out = []
    async for ev in channel.messages():
        out.append(ev)
    return out


async def test_inputs_and_stream_round_trip():
    ch = AgentChannel(INPUTS, token=None)
    url = await ch.start()
    try:
        async with httpx.AsyncClient() as c:
            ready = await c.get(f"{url}/ready")
            assert ready.status_code == 200 and ready.text == "ready"
            got = (await c.get(f"{url}/inputs")).json()
            assert got == INPUTS

            async def feed():
                body = (encode({"kind": "msg", "record": {"i": 0}}) +
                        encode({"kind": "msg", "record": {"i": 1}}) +
                        encode(done_event(0, None)))
                await c.post(f"{url}/stream", content=body)

            feeder = asyncio.create_task(feed())
            events = await _collect(ch)
            await feeder
        assert [e["record"]["i"] for e in events] == [0, 1]
        assert ch.done == {"kind": "done", "exit": 0, "error": None}
    finally:
        await ch.stop()


async def test_token_is_required_when_set():
    ch = AgentChannel(INPUTS, token="sekret")
    url = await ch.start()
    try:
        async with httpx.AsyncClient() as c:
            assert (await c.get(f"{url}/inputs")).status_code == 401
            bad = await c.post(f"{url}/stream", content=b"", headers={"Authorization": "Bearer no"})
            assert bad.status_code == 401
            ok = await c.get(f"{url}/inputs", headers={"Authorization": "Bearer sekret"})
            assert ok.status_code == 200
    finally:
        await ch.stop()


async def test_a_dropped_stream_without_done_synthesizes_a_failure():
    """B crashing mid-forward must not hang the run: the channel closes with an
    error done so the sidecar fails closed instead of blocking on the queue."""
    ch = AgentChannel(INPUTS, token=None)
    url = await ch.start()
    try:
        async with httpx.AsyncClient() as c:
            async def feed():
                # one event, then the body ends with NO done sentinel
                await c.post(f"{url}/stream", content=encode({"kind": "msg", "record": {}}))
            feeder = asyncio.create_task(feed())
            events = await _collect(ch)
            await feeder
        assert len(events) == 1
        assert ch.done["exit"] == -1 and "without completion" in ch.done["error"]
    finally:
        await ch.stop()


async def test_inject_done_unblocks_a_consumer_when_b_never_streamed():
    ch = AgentChannel(INPUTS, token=None)
    await ch.start()
    try:
        async def die():
            await asyncio.sleep(0.05)
            await ch.inject_done(1, "agent process exited before completing")
        asyncio.create_task(die())
        events = await asyncio.wait_for(_collect(ch), timeout=2)
        assert events == []
        assert ch.done["error"].startswith("agent process exited")
    finally:
        await ch.stop()


async def test_a_real_done_wins_over_a_later_inject():
    ch = AgentChannel(INPUTS, token=None)
    url = await ch.start()
    try:
        async with httpx.AsyncClient() as c:
            await c.post(f"{url}/stream", content=encode(done_event(0, None)))
        # B already completed; a late watchdog inject must be a no-op
        await ch.inject_done(1, "too late")
        events = await _collect(ch)
        assert events == [] and ch.done["error"] is None
    finally:
        await ch.stop()


async def test_a_line_that_never_ends_cannot_exhaust_the_sidecars_memory(monkeypatch):
    """The split's own new attack surface. In the in-process path the message
    stream comes from the SDK; here it comes from the half the threat model
    assumes is compromised. Unbounded, 200 MiB of newline-free input took the
    SIDECAR -- the half holding every credential -- to 12.7 GB of resident memory.
    """
    from andyur.runner import agentchannel as mod
    monkeypatch.setattr(mod, "_MAX_LINE", 64 * 1024)
    ch = AgentChannel(INPUTS, token=None)
    url = await ch.start()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10, read=None, write=None)) as c:
            async def body():
                for _ in range(200):
                    yield b"X" * 8192          # 1.6 MB, never a newline
            r = await c.post(f"{url}/stream", content=body())
            assert r.status_code == 413
        events = await _collect(ch)
        assert events == []
        # and it fails CLOSED with a reason, rather than truncating silently
        assert "longer than" in ch.done["error"]
        assert ch.done["exit"] == -1
    finally:
        await ch.stop()


async def test_a_complete_oversized_line_is_refused_before_ingest(monkeypatch):
    """The cap applies to a line, independent of ASGI chunk boundaries."""
    from andyur.runner import agentchannel as mod
    monkeypatch.setattr(mod, "_MAX_LINE", 64 * 1024)
    ch = AgentChannel(INPUTS, token=None)
    url = await ch.start()
    try:
        oversized = encode({"kind": "msg", "record": {"text": "A" * (68 * 1024)}})
        assert oversized.endswith(b"\n")
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(f"{url}/stream", content=oversized)
        assert response.status_code == 413
        assert await _collect(ch) == []
        assert "line longer" in ch.done["error"]
    finally:
        await ch.stop()


async def test_an_endless_event_stream_is_bounded_by_a_byte_budget(monkeypatch):
    """A hostile agent can also exhaust memory with VALID events: every one is
    appended to an in-memory transcript. The per-line cap does not catch this, so
    the whole-stream budget is what bounds it."""
    from andyur.runner import agentchannel as mod
    monkeypatch.setattr(mod, "_MAX_STREAM", 32 * 1024)
    ch = AgentChannel(INPUTS, token=None)
    url = await ch.start()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10, read=None, write=None)) as c:
            async def body():
                for _ in range(100_000):
                    yield encode({"kind": "msg", "record": {"x": "y" * 200}})
            r = await c.post(f"{url}/stream", content=body())
            assert r.status_code == 413
        events = await _collect(ch)
        # some got through -- the point is that it STOPPED, well short of 100k
        assert 0 < len(events) < 1000
        assert "budget" in ch.done["error"]
    finally:
        await ch.stop()


async def test_a_legitimate_large_event_still_gets_through(monkeypatch):
    """The caps must not break a real run: one big tool result is normal. If this
    fails the platform is 'secure' by being broken."""
    from andyur.runner import agentchannel as mod
    monkeypatch.setattr(mod, "_MAX_LINE", 8 * 1024 * 1024)
    ch = AgentChannel(INPUTS, token=None)
    url = await ch.start()
    try:
        big = "z" * (2 * 1024 * 1024)          # a 2 MiB tool result
        async with httpx.AsyncClient(timeout=httpx.Timeout(30, read=None, write=None)) as c:
            await c.post(f"{url}/stream",
                         content=encode({"kind": "msg", "record": {"big": big}})
                         + encode(done_event(0, None)))
        events = await _collect(ch)
        assert len(events) == 1
        assert events[0]["record"]["big"] == big
        assert ch.done["error"] is None
    finally:
        await ch.stop()


async def test_a_second_concurrent_stream_is_refused():
    ch = AgentChannel(INPUTS, token=None)
    url = await ch.start()
    try:
        async with httpx.AsyncClient() as c:
            # hold the first stream open with a slow body
            async def slow():
                yield encode({"kind": "msg", "record": {}})
                await asyncio.sleep(0.3)
                yield encode(done_event(0, None))
            first = asyncio.create_task(c.post(f"{url}/stream", content=slow()))
            await asyncio.sleep(0.1)
            second = await c.post(f"{url}/stream", content=b"")
            assert second.status_code == 409
            await _collect(ch)
            await first
    finally:
        await ch.stop()


async def test_a_taken_channel_port_raises_catchably_not_systemexit():
    """uvicorn calls sys.exit(1) on a bind error, and SystemExit derives from
    BaseException -- so it walks through the `except Exception` guarding the run
    and kills the runner outright: no finalization, run left 'running'. In pod
    mode the port is FIXED, so a leftover pod or co-located service reaches this.

    The first attempt at this fix caught SystemExit AFTER awaiting the serve
    task, which is dead code: CPython's Task.__step re-raises SystemExit and
    tears down the loop before the awaiting frame resumes. The conversion has to
    happen inside the task's own coroutine."""
    import socket
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    port = holder.getsockname()[1]
    holder.listen(1)
    try:
        ch = AgentChannel(INPUTS, token=None, port=port)
        with pytest.raises(RuntimeError, match="could not bind"):
            await ch.start()
    finally:
        holder.close()
