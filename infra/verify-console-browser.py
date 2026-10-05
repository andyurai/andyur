#!/usr/bin/env python3
"""LIVE browser gate for the console: drives the REAL page in Chrome over the
DevTools protocol (no JavaScript toolchain, no Playwright; `websockets` is
already a dependency). Assumes a control plane is up (`./run.sh up`) and
Chrome is installed. Starts a console, then:

  1. loads the launch URL: the session is issued, the agents list renders,
     the DOM carries no inline handler, and Chrome reports no CSP violation;
  2. reloads the tab: the tab's sessionStorage session is reused, the list
     renders again without a launch token;
  3. opens the same launch URL in a SECOND tab: the "already used" panel;
  4. creates an agent, opens its Launch form, starts a run with input, and
     follows the run page until it ends, asserting the transcript or
     captured output rendered and the exchanges card filled;
  5. opens the Runs page (the new run is listed) and the run's workflow Flow
     page (an SVG with the run's node);
  6. provokes each named refusal from outside the page and reads it back
     from the collector by `andyur.console.reason`.

Every assertion and the trace ids land in a JSON artifact
(data/logs/console-browser-gate.json). Exit 1 on any failure.
"""
from __future__ import annotations

import asyncio
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent.parent
# THE INTERPRETER THIS GATE IS ALREADY RUNNING UNDER. It was hard-wired to
# HERE/".venv"/"bin"/"python", so a reviewer re-running the gate from a
# detached worktree at a frozen SHA reached the ORIGINAL checkout's venv rather
# than the one they had just built (ROADMAP.md 31). sys.executable
# is correct in every checkout by construction, including this one.
PY = pathlib.Path(os.environ.get("ANDYUR_PY") or sys.executable)
CHROME_CANDIDATES = [
    os.environ.get("ANDYUR_CHROME", ""),
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    shutil.which("google-chrome") or "", shutil.which("chromium") or "",
]
JAEGER = os.environ.get("ANDYUR_JAEGER_UI", "http://localhost:16686")
RESULT = HERE / "data" / "logs" / "console-browser-gate.json"
EXPECT_REASONS = ["launch_spent", "launch_unknown", "cross_origin", "bad_session",
                  "bad_host", "bad_path", "not_a_console_route", "method_not_allowed"]

results: list[dict] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append({"check": name, "ok": bool(ok), "detail": detail})
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{('  ' + detail) if detail else ''}", flush=True)
    return bool(ok)


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def http(method: str, url: str, body: bytes | None = None, headers: dict | None = None):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


class Chrome:
    """A headless Chrome and one DevTools session per tab."""

    def __init__(self, exe: str):
        self.port = free_port()
        self.targets: list[str] = []
        self.profile = tempfile.mkdtemp(prefix="andyur-console-gate-")
        self.proc = subprocess.Popen(
            [exe, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
             f"--remote-debugging-port={self.port}", f"--user-data-dir={self.profile}",
             "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(60):
            try:
                http("GET", f"http://127.0.0.1:{self.port}/json/version"); break
            except Exception:
                time.sleep(0.25)

    def close(self):
        self.close_targets()
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.profile, ignore_errors=True)

    async def new_tab(self):
        _, _, body = http("PUT", f"http://127.0.0.1:{self.port}/json/new?about:blank")
        info = json.loads(body)
        self.targets.append(info["id"])
        return Tab(info["webSocketDebuggerUrl"])

    def close_targets(self):
        """Close the TARGETS, not just the websockets.

        `Tab.__aexit__` closes the DevTools connection; the tab itself stays
        open in the browser. It happened not to matter only because `close()`
        kills the whole process straight after -- which is exactly the kind of
        accident that stops being true the first time the gate wants to keep a
        browser alive between phases.
        """
        for target in self.targets:
            try:
                http("GET", f"http://127.0.0.1:{self.port}/json/close/{target}")
            except Exception:                                  # noqa: BLE001
                pass
        self.targets.clear()


class Tab:
    def __init__(self, ws_url: str):
        self.ws_url = ws_url
        self.ws = None
        self.n = 0
        self.violations: list[str] = []
        self.errors: list[str] = []

    async def __aenter__(self):
        import websockets
        self.ws = await websockets.connect(self.ws_url, max_size=16 * 1024 * 1024)
        await self.send("Page.enable"); await self.send("Runtime.enable"); await self.send("Log.enable")
        return self

    async def __aexit__(self, *a):
        await self.ws.close()

    # A DevTools command that never answers -- a page blocked on a BFF that
    # stopped responding -- used to hang here forever, so the `finally` that
    # stops Chrome and the console never ran and the gate left both behind.
    SEND_TIMEOUT = float(os.environ.get("ANDYUR_GATE_CDP_TIMEOUT", "60"))

    async def send(self, method: str, **params):
        self.n += 1
        mid = self.n
        await self.ws.send(json.dumps({"id": mid, "method": method, "params": params}))
        deadline = time.monotonic() + self.SEND_TIMEOUT
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"{method}: no DevTools reply within {self.SEND_TIMEOUT:.0f}s")
            msg = json.loads(await asyncio.wait_for(self.ws.recv(), timeout=left))
            if msg.get("method") == "Log.entryAdded":
                e = msg["params"]["entry"]
                if e.get("source") == "security" or "Content Security Policy" in e.get("text", ""):
                    self.violations.append(e.get("text", ""))
            if msg.get("method") == "Runtime.exceptionThrown":
                self.errors.append(json.dumps(msg["params"].get("exceptionDetails", {}).get("exception", {}).get("description", ""))[:200])
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})

    async def drain(self, seconds: float):
        """Let events (CSP violations, exceptions) arrive while nothing is pending."""
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                msg = json.loads(await asyncio.wait_for(self.ws.recv(), timeout=max(0.05, end - time.monotonic())))
            except asyncio.TimeoutError:
                break
            if msg.get("method") == "Log.entryAdded":
                e = msg["params"]["entry"]
                if e.get("source") == "security" or "Content Security Policy" in e.get("text", ""):
                    self.violations.append(e.get("text", ""))
            if msg.get("method") == "Runtime.exceptionThrown":
                self.errors.append(json.dumps(msg["params"].get("exceptionDetails", {}))[:200])

    async def goto(self, url: str):
        await self.send("Page.navigate", url=url)
        await self.drain(1.5)

    async def js(self, expr: str):
        r = await self.send("Runtime.evaluate", expression=expr, returnByValue=True, awaitPromise=True)
        return r.get("result", {}).get("value")

    async def wait_for(self, expr: str, timeout: float = 20, every: float = 0.5):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            v = await self.js(expr)
            if v:
                return v
            await self.drain(every)
        return None


async def main() -> int:
    exe = next((c for c in CHROME_CANDIDATES if c and os.path.exists(c)), None)
    if not exe:
        print("no Chrome found (set ANDYUR_CHROME)"); return 1
    cp = subprocess.run([str(PY), "-c", "from andyur.config import SERVER_URL; print(SERVER_URL)"],
                        capture_output=True, text=True, cwd=HERE).stdout.strip()
    try:
        http("GET", f"{cp}/health")
    except Exception:
        print(f"control plane not up at {cp} -- run ./run.sh up first"); return 1
    # Under user-auth the console blocks on the IdP login before it prints a
    # usable session, and this gate then failed with "console did not print a
    # launch URL" after its timeout -- a true statement about the wrong thing.
    # Name the gate that covers those modes instead of timing out.
    user_auth = subprocess.run(
        [str(PY), "-c", "from andyur import config; print(int(config.USER_AUTH))"],
        capture_output=True, text=True, cwd=HERE).stdout.strip()
    if user_auth == "1":
        print("ANDYUR_USER_AUTH is on: this gate drives the single-operator console.\n"
              "The admin/user modes are proven by ./run.sh console-modes (real Keycloak).")
        return 1

    env = {**os.environ, "ANDYUR_OTEL": "on"}
    log = HERE / "data" / "logs" / "console-browser.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    console = subprocess.Popen([str(HERE / "andyur-cli"), "console", "--no-browser"],
                               stdout=open(log, "w"), stderr=subprocess.STDOUT, env=env, cwd=HERE)
    url = None
    for _ in range(60):
        m = re.search(r"andyur console -> (http://127\.0\.0\.1:\d+/\?launch=[^\s]+)", log.read_text())
        if m:
            url = m.group(1); break
        time.sleep(0.25)
    if not url:
        print("console did not print a launch URL"); console.terminate(); return 1
    base = url.split("/?launch=")[0]
    print(f"== console at {base}; browser {exe}")
    chrome = Chrome(exe)
    agent = f"browser_gate_{os.getpid()}"
    run_id = None
    real_secret = ""
    found: dict = {}
    # Stamped before the first request so the collector read-back at the end can
    # be bounded to spans THIS run produced; a second of slack for clock skew.
    GATE_START_US = int(time.time() * 1_000_000) - 1_000_000
    try:
        async with await chrome.new_tab() as tab:
            print("== 1. launch URL: session issued, list rendered, nothing inline, no CSP violation")
            await tab.goto(url)
            rows = await tab.wait_for("document.querySelectorAll('#list tr.row, #list .empty').length")
            check("agents page rendered from the launch link", bool(rows))
            check("launch token scrubbed from the address bar",
                  await tab.js("location.search") == "", await tab.js("location.search") or "")
            check("session stored for the tab", bool(await tab.js("sessionStorage.getItem('andyur-console-session')")))
            check("no inline handler attribute in the DOM",
                  (await tab.js("document.querySelectorAll('[onclick],[onload],[onsubmit],[onchange]').length")) == 0)
            await tab.drain(1.0)
            check("no CSP violation reported by Chrome", not tab.violations, "; ".join(tab.violations)[:200])
            check("no uncaught page exception", not tab.errors, "; ".join(tab.errors)[:200])

            print("== 2. reload: the tab's session is reused")
            await tab.send("Page.reload")
            await tab.drain(1.5)
            rows = await tab.wait_for("document.querySelectorAll('#list tr.row, #list .empty').length")
            check("agents page rendered again after reload without a launch token", bool(rows))
            check("no 'launch link' panel after reload", (await tab.js("document.querySelectorAll('.blocked').length")) == 0)

            print("== 3. the same launch URL in a second tab")
            async with await chrome.new_tab() as tab2:
                await tab2.goto(url)
                panel = await tab2.wait_for("document.querySelector('.blocked') && document.querySelector('.blocked').textContent")
                check("second tab lands on the 'already used' panel", bool(panel and "already used" in panel), (panel or "")[:120])
            # the first tab went to the background when the second opened; a
            # background tab does not poll (by design), so bring it back
            await tab.send("Page.bringToFront")
            await tab.drain(0.5)

            print("== 4. create -> launch with input -> follow to the end")
            await tab.js(f"document.getElementById('c_name').value = {json.dumps(agent)};"
                         f"document.getElementById('c_desc').value = 'browser gate';")
            await tab.js("document.getElementById('createForm').requestSubmit()")
            ok = await tab.wait_for(f"location.hash === '#/agents/{agent}' && document.getElementById('detailCard') && !document.getElementById('detailCard').hidden")
            check("agent created and its detail opened", bool(ok), await tab.js("location.hash"))
            await tab.js("document.querySelector('#detail [data-href^=\"#/launch/\"]').click()")
            form = await tab.wait_for("document.getElementById('launchForm') !== null")
            check("launch form opened", bool(form))
            await tab.js("document.getElementById('l_reason').value = 'browser gate run';"
                         "document.getElementById('l_input').value = JSON.stringify({question: 'say the word pineapple and stop'});")
            await tab.js("document.getElementById('launchForm').requestSubmit()")
            run_hash = await tab.wait_for("location.hash.startsWith('#/runs/') && location.hash")
            check("run started and the run page opened", bool(run_hash), run_hash or (await tab.js("document.getElementById('l_error') && document.getElementById('l_error').textContent")) or "")
            terminal = "(function(){var p=document.querySelector('#runHeader .pill');return p&&['done','failed','cancelled'].includes(p.textContent)?p.textContent:''})()"
            if run_hash:
                run_id = run_hash.split("/")[-1]
                started = await tab.wait_for(
                    "(function(){var p=document.querySelector('#runHeader .pill');return p&&p.textContent!=='pending'?p.textContent:''})()", timeout=60, every=2)
                if not started:
                    # A run that never leaves pending is a stack with no worker,
                    # not a page that fails to follow it. Reporting the second
                    # when it is the first is how a gate gets disbelieved.
                    workers = await tab.js(
                        "fetch('/api/workers', {headers: {'andyur-console-session': "
                        "sessionStorage.getItem('andyur-console-session')}}).then(r=>r.json())"
                        ".then(j=>Array.isArray(j)?j.filter(w=>w.alive).length:-1)")
                    if workers == 0:
                        check("this stack has a worker to run the gate's run", False,
                              "no live worker: start one with ./run.sh daemon "
                              "(ANDYUR_ALLOW_UNISOLATED_AGENT=on on a host)")
                    else:
                        check("the run page follows the run out of pending", False,
                              f"{workers} live workers, and the run stayed pending")
                else:
                    check("the run page follows the run out of pending", True, started)
                # The model's speed is not the console's property. Give the run a
                # bound, then end it with the in-flight kill switch (halt its
                # workflow; pause only stops new wakes) and assert the page
                # follows it to its terminal state either way.
                state = await tab.wait_for(terminal, timeout=float(os.environ.get("ANDYUR_GATE_RUN_TIMEOUT", "90")), every=2)
                if not state:
                    wf_id = await tab.js(f"fetch('/api/runs/{run_id}', {{headers: {{'andyur-console-session': sessionStorage.getItem('andyur-console-session')}}}}).then(r=>r.json()).then(j=>j.workflow_id||'')")
                    # The halt's OWN status matters: a 403 or 404 here left the
                    # run to time out and the failure was reported as "the page
                    # did not follow the run", which points at the wrong thing.
                    halt_status = await tab.js(f"fetch('/api/workflows/{wf_id}/halt', {{method: 'POST', headers: {{'andyur-console-session': sessionStorage.getItem('andyur-console-session'), 'content-type': 'application/json'}}, body: '{{}}'}}).then(r=>r.status)")
                    check("the halt the gate uses as its kill switch was accepted",
                          halt_status == 200, f"POST /workflows/{wf_id}/halt -> {halt_status}")
                    state = await tab.wait_for(terminal, timeout=90, every=2)
                    # halt destroys a live run: the row ends failed or cancelled
                    check("run ended by the workflow halt and the page followed it", state in ("cancelled", "failed"), state or "still running")
                else:
                    check("run reached a terminal state on the run page", True, state)
                body = await tab.js("document.getElementById('follow').textContent")
                check("the follow panel left the 'Running' state when the run ended", bool(state) and bool(body) and "Running." not in body, (body or "")[:80])
                # The LABEL "trace" is always rendered, so asserting the word
                # cannot fail. Assert the run's actual trace id is on the page.
                trace_id = await tab.js(
                    f"fetch('/api/runs/{run_id}', {{headers: {{'andyur-console-session': "
                    "sessionStorage.getItem('andyur-console-session')}}).then(r=>r.json())"
                    ".then(j=>j.trace_id||'')")
                header_text = await tab.js("document.getElementById('runHeader').textContent") or ""
                if trace_id:
                    check("the run's own trace id is shown on the run page",
                          trace_id[:12] in header_text, f"{trace_id[:12]} in {header_text[:60]}")
                else:
                    check("the run carries a trace id to show", False,
                          "no trace_id on the run: is ANDYUR_OTEL=on for the server?")

            print("== 4b. a finished run's transcript renders as exchanges")
            # NOT simply the newest done run: an exec/v1 run captures stdout and
            # has no transcript, so #exchCount never fills and this timed out
            # against a page that was behaving correctly. The list row carries
            # interface_version, so the gate can pick a run this check applies to.
            done = await tab.js(
                "fetch('/api/runs?state=done&limit=50', {headers: {'andyur-console-session': "
                "sessionStorage.getItem('andyur-console-session')}}).then(r=>r.json())"
                ".then(j=>(j.runs.find(r=>!(r.interface_version||'').startsWith('exec/v1'))||{}).id||'')")
            if done:
                await tab.goto(base + f"/#/runs/{done}")
                exch = await tab.wait_for("(function(){var t=document.getElementById('exchCount');return t&&t.textContent})()", timeout=20)
                follow = await tab.js("document.getElementById('follow').textContent")
                check("a done run's page shows its output and its exchanges", bool(exch) and bool(follow), f"{exch}")
            else:
                check("a native done run exists on this stack to render", False,
                      "none; run a demo first (exec/v1 runs have no transcript to show)")

            print("== 5. runs list and flow page")
            await tab.goto(base + "/#/runs")
            listed = await tab.wait_for(f"[...document.querySelectorAll('#list tr.row')].some(r => r.dataset.href.endsWith({json.dumps(run_id or 'x')}))")
            check("the new run is listed on the Runs page", bool(listed))
            wf = await tab.js(f"fetch('/api/runs/{run_id}', {{headers: {{'andyur-console-session': sessionStorage.getItem('andyur-console-session')}}}}).then(r=>r.json()).then(j=>j.workflow_id||'')") if run_id else ""
            if wf:
                await tab.goto(base + f"/#/workflows/{wf}")
                svg = await tab.wait_for("document.querySelectorAll('#flowSvg svg g.node').length")
                check("flow page draws the run's node", bool(svg), f"{svg} nodes")
                await tab.js("document.querySelector('#flowSvg g[data-key^=\"run:\"]').dispatchEvent(new MouseEvent('click', {bubbles: true}))")
                sel = await tab.wait_for("document.getElementById('exPanel').textContent.includes('woken by')")
                check("selecting a node fills the exchange panel", bool(sel))
            else:
                check("flow page (run has no workflow id)", False, "no workflow_id on the run")
            await tab.drain(0.5)
            check("still no CSP violation after every page", not tab.violations, "; ".join(tab.violations)[:200])
            check("still no uncaught page exception", not tab.errors, "; ".join(tab.errors)[:300])
            # Taken while the tab is still open: section 6 needs the page's own
            # secret to provoke the refusals that live BEHIND the session fence.
            real_secret = await tab.js("sessionStorage.getItem('andyur-console-session')") or ""

        print("== 6. refusals provoked from outside the page, read back from the collector")
        hdr = {"content-type": "application/json"}
        http("POST", f"{base}/session", b'{"launch":"guess"}', hdr)
        http("POST", f"{base}/session", json.dumps({"launch": url.split("launch=")[1]}).encode(), hdr)
        http("GET", f"{base}/api/agents")
        http("GET", f"{base}/api/agents", headers={"andyur-console-session": "x", "origin": "http://evil.example"})
        http("GET", f"{base}/api/agents", headers={"andyur-console-session": "x", "host": "evil.example:1"})
        http("GET", f"{base}/session")
        # bad_path and not_a_console_route need the REAL secret: with a wrong one
        # the session fence answers first and every probe is bad_session. The
        # gate used to send them with "x" and then SKIP both reasons when they
        # did not appear, which is a check that reports itself as covered.
        if real_secret:
            authed = {"andyur-console-session": real_secret, "origin": base,
                      "host": base.split("//", 1)[1]}
            http("GET", f"{base}/api/agents/%2E%2E", headers=authed)
            http("GET", f"{base}/api/not-a-console-route", headers=authed)
        check("the gate holds the page's own session secret to provoke the "
              "post-session refusals", bool(real_secret))

        # BOUND TO THIS RUN. Jaeger IGNORES `lookback` on the HTTP query API --
        # lookback=1h and lookback=1s return the same page of traces -- so this
        # loop was unbounded and passed against spans from an earlier run.
        # Explicit start/end IS honoured; the startTime filter is the second
        # bound, because `limit` applies within the window.
        # BOUND TO THIS CONSOLE PROCESS, not only to a time window:
        # service=andyur-console is shared by every console on the machine.
        instance = ""
        try:
            _, _, hb = http("GET", f"{base}/healthz")
            instance = json.loads(hb).get("instance_id", "")
        except Exception:
            pass
        check("read-back bound to THIS console process", bool(instance), instance[:12])

        # ARM THE NEGATIVE CONTROL: a SECOND console, in the same window,
        # emitting the same kind of refusal from a different process.
        decoy_trace = ""
        decoy = subprocess.Popen(
            [str(HERE / "andyur-cli"), "console", "--no-browser"],
            stdout=open(HERE / "data" / "logs" / "console-browser-decoy.log", "w"),
            stderr=subprocess.STDOUT, env=env, cwd=HERE)
        try:
            decoy_base, decoy_instance = "", ""
            for _ in range(60):
                m = re.search(r"andyur console -> (http://127\.0\.0\.1:\d+/\?launch=[^\s]+)",
                              (HERE / "data" / "logs" / "console-browser-decoy.log").read_text())
                if m:
                    decoy_base = m.group(1).split("/?launch=")[0]
                    break
                time.sleep(0.25)
            if decoy_base:
                _, _, dhb = http("GET", f"{decoy_base}/healthz")
                decoy_instance = json.loads(dhb).get("instance_id", "")
                http("GET", f"{decoy_base}/api/agents",
                     headers={"origin": "http://evil.example"})
                for _ in range(20):
                    try:
                        now_us = int(time.time() * 1_000_000)
                        _, _, b = http("GET", f"{JAEGER}/api/traces?service=andyur-console"
                                              f"&limit=1000&start={GATE_START_US}&end={now_us}")
                        for t in json.loads(b).get("data", []):
                            procs = t.get("processes", {})
                            for sp in t.get("spans", []):
                                tags = procs.get(sp.get("processID"), {}).get("tags", [])
                                if not any(g.get("key") == "service.instance.id"
                                           and g.get("value") == decoy_instance for g in tags):
                                    continue
                                if any(g.get("key") == "andyur.console.reason"
                                       and g.get("value") == "cross_origin"
                                       for g in sp.get("tags", [])):
                                    decoy_trace = t["traceID"]
                    except Exception:
                        pass
                    if decoy_trace:
                        break
                    time.sleep(1)
        finally:
            decoy.terminate()
        check("negative control armed: a second console emitted a real refusal "
              "in this window", bool(decoy_trace), decoy_trace)
        LIMIT = 1000
        saturated = False
        for _ in range(30):
            try:
                now_us = int(time.time() * 1_000_000)
                _, _, body = http("GET", f"{JAEGER}/api/traces?service=andyur-console"
                                         f"&limit={LIMIT}&start={GATE_START_US}&end={now_us}")
                traces = json.loads(body).get("data", [])
                # `limit` keeps the NEWEST traces, so a busy window can return a
                # full page that excludes ours. Reading that as "nothing was
                # exported" is a false RED for reasons that WERE emitted.
                saturated = len(traces) >= LIMIT
                for t in traces:
                    procs = t.get("processes", {})
                    for sp in t.get("spans", []):
                        if int(sp.get("startTime", 0)) < GATE_START_US:
                            continue                 # older than this run: not evidence
                        if instance:
                            tags = procs.get(sp.get("processID"), {}).get("tags", [])
                            if not any(g.get("key") == "service.instance.id"
                                       and g.get("value") == instance for g in tags):
                                continue             # another console on this box
                        for tag in sp.get("tags", []):
                            if tag.get("key") == "andyur.console.reason":
                                found.setdefault(tag["value"], t["traceID"])
            except Exception:
                pass
            if all(r in found for r in EXPECT_REASONS):
                break
            time.sleep(1)
        if saturated and not all(r in found for r in EXPECT_REASONS):
            check("the collector query window was not saturated", False,
                  f"{LIMIT} traces returned: the read-back below is INCONCLUSIVE, not failed")
        for r in EXPECT_REASONS:
            check(f"span andyur.console.reason={r} read back from THIS run", r in found,
                  found.get(r, ""))
        # NEGATIVE CONTROL, and it has to be one that CAN fail. Asserting the
        # absence of `upstream_timeout` proved nothing: nothing in this
        # repository emits it, so its absence held whether or not the read-back
        # bounded anything. The decoy console below emitted a REAL refusal, of
        # the same kind, inside the same window, from a different process --
        # which is the hazard the bound exists for, since `andyur-console` is
        # the service name of every console on the machine.
        if decoy_trace:
            check("another console's refusal in the same window is NOT read back",
                  decoy_trace not in found.values(), decoy_trace)
        else:
            check("the negative control was armed", False,
                  "the decoy console's refusal never reached the collector")
    finally:
        # The artifact is the gate's record, so it is written on the failure
        # path too. It used to be written only after the body completed: an
        # exception (or the DevTools hang above) left no evidence of how far the
        # gate got, which is exactly when the record is worth most.
        try:
            RESULT.parent.mkdir(parents=True, exist_ok=True)
            RESULT.write_text(json.dumps(
                {"gate": "console-browser", "console": base, "run_id": run_id,
                 "checks": results, "traces": found}, indent=1))
        except Exception as exc:                                   # noqa: BLE001
            print(f"  (could not write {RESULT}: {exc})")
        chrome.close()
        # leave nothing behind: the gate's agent (its run was ended above)
        try:
            subprocess.run([str(HERE / "andyur-cli"), "agents", "delete", agent, "--yes", "--force"],
                           capture_output=True, timeout=30, cwd=HERE)
        except Exception:
            pass
        console.terminate()
        try:
            console.wait(10)
        except subprocess.TimeoutExpired:
            console.kill()
    failed = [r for r in results if not r["ok"]]
    print(f"\nconsole browser gate {'GREEN' if not failed else 'RED'} "
          f"({len(results) - len(failed)}/{len(results)} checks); artifact {RESULT}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
