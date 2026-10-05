#!/usr/bin/env python3
"""Demo: does an agent learn across runs, and where does it fail?

An SRE incident agent is run three times to show Andyur's memory graph in action
and, deliberately, one place it falls short:

  1. LEARN  an incident happens; the agent records its root cause.
  2. HIT    the same incident recurs (same wording); the agent recalls the cause.
  3. MISS   the same problem recurs, reworded; keyword recall misses it, so the
            agent does NOT recall the cause. It "should have learned but didn't."

The MISS is the point: our recall is keyword + entity match, not yet semantic,
so a reworded recurrence slips through. That is the gap that motivates vector
retrieval (and, later, self-reflection).

Prereqs:
  ./run.sh graph                      # Neo4j up (memory graph store)
  an LLM backend, one of:
    ANDYUR_LLM=api  + ANTHROPIC_API_KEY   (default; uses claude-haiku-4-5)
    ANDYUR_LLM=subscription
    ANDYUR_LLM=ollaman ANDYUR_AGENT_MODEL=<a tool-capable local model>

Run:
  python demos/incident_recall_demo.py

It starts its own server on a throwaway data dir against the shared Neo4j, runs
the scenario, prints a narrative, and cleans up.
"""

import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent  # repo root

# Re-exec under the project venv so `python3 demos/...` works with any Python:
# Andyur's deps live in .venv, and the server subprocess we spawn inherits it.
# Compare sys.prefix (points at the venv only when running under it); comparing
# the executable path fails because a venv's python is a symlink to the base.
_VENV = HERE / ".venv"
_VENV_PY = _VENV / "bin" / "python"
if _VENV_PY.exists() and Path(sys.prefix).resolve() != _VENV.resolve():
    os.execv(str(_VENV_PY), [str(_VENV_PY), str(Path(__file__).resolve()), *sys.argv[1:]])

sys.path.insert(0, str(HERE))


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# Configure BEFORE importing andyur (config reads the environment at import).
# Own free port + temp data dir + a demo-only agent name, so this runs in full
# isolation even while './run.sh up' is running on the default port.
PORT = _free_port()
os.environ["ANDYUR_DATA_DIR"] = tempfile.mkdtemp(prefix="andyur-demo-")
os.environ["ANDYUR_PORT"] = str(PORT)
os.environ["ANDYUR_SERVER_URL"] = f"http://127.0.0.1:{PORT}"
os.environ.setdefault("ANDYUR_GRAPH", "neo4j")
os.environ.setdefault("ANDYUR_LLM", "api")
os.environ.setdefault("ANDYUR_AGENT_MODEL", "claude-haiku-4-5")
os.environ.setdefault("ANDYUR_MAX_TURNS", "8")

import httpx  # noqa: E402

from andyur import config  # noqa: E402

BASE = os.environ["ANDYUR_SERVER_URL"]
AGENT = "demo-sentinel"

INSTRUCTIONS = """You are an SRE incident responder. On every run:
- First read the "Relevant memory (recalled from your knowledge graph)" section
  if it is present. If the current issue resembles a past incident there, say so
  explicitly and cite the earlier root cause by name.
- Then investigate the reported issue, state the most likely cause, and record
  what you found in your short-term memory.

Rules:
- State only facts you were given in the wakeup or recalled from memory. Do NOT
  invent specifics such as config values, numbers, or timestamps. If a detail is
  unknown, write "unknown".
- Do NOT create tasks or delegate to other agents. If action is needed, put it
  in your summary as a recommendation.
- Finish with a FINAL REPORT of at most 5 lines: root cause, impact, recommended
  action. Be concise; prefer citing prior knowledge over re-deriving it.
"""

RULE = "=" * 74


def wait_health(proc):
    for _ in range(60):
        try:
            if httpx.get(f"{BASE}/health", timeout=2).status_code == 200:
                return
        except Exception:
            pass
        if proc.poll() is not None:
            raise SystemExit("server exited early; check its output")
        time.sleep(0.5)
    raise SystemExit("server did not come up")


def clear_graph():
    """Wipe this demo agent's prior graph so re-runs start clean."""
    from neo4j import GraphDatabase
    d = GraphDatabase.driver(config.NEO4J_URL,
                             auth=(config.NEO4J_USER, config.NEO4J_PASSWORD))
    with d.session() as s:
        s.run("MATCH (n) WHERE n.agent = $a DETACH DELETE n", a=AGENT)
    d.close()


def recall_section(prompt_md: str) -> str:
    m = re.search(r"## Relevant memory.*?(?=\n## )", prompt_md, re.DOTALL)
    if not m:
        return "(nothing recalled from memory)"
    # keep just the bullet lines, drop the markdown header
    body = "\n".join(ln for ln in m.group(0).splitlines() if ln.strip()
                     and not ln.startswith("## "))
    return body or "(nothing recalled from memory)"


def scenario(c, step, title, reason, expect_recall):
    print(f"\n{RULE}\nSTEP {step}: {title}\n{RULE}")
    print(f"Wakeup: {reason}")
    print("  ...the agent is working (chatter hidden)...", flush=True)
    rid = c.post(f"/agents/{AGENT}/trigger", json={"reason": reason}).json()["run_id"]
    # Run the agent as a fully detached subprocess with all output sent to
    # /dev/null and no controlling terminal, so none of the framework's chatter
    # (or the claude CLI's tty progress) can leak into this demo's output.
    subprocess.run(
        [sys.executable, "-m", "andyur.runner", "--agent", AGENT, "--run-id", rid],
        cwd=str(HERE), env=os.environ.copy(),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    prompt = c.get(f"/agents/{AGENT}/files/runs/{rid}/prompt.md").json()["content"]
    run = c.get(f"/runs/{rid}").json()
    summary = (run.get("summary") or "(no summary)").strip()

    section = recall_section(prompt)
    print(f"\nRecalled from memory:\n{section}")
    print(f"\nFinal answer:\n{summary}")

    # Measure recall from the INJECTED section, not the summary: the summary
    # echoes wakeup terms, but "redis" only appears if memory actually surfaced
    # the prior root cause.
    recalled = bool(re.search(r"redis", section, re.IGNORECASE))
    verdict = "RECALLED the prior root cause" if recalled else "did NOT recall it"
    tag = "as expected" if recalled == expect_recall else "!! UNEXPECTED !!"
    print(f"\nVERDICT: memory {verdict}  ({tag})")
    return recalled


def main():
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "andyur.server.app:app",
         "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
        cwd=str(HERE), env=os.environ.copy(),
    )
    try:
        wait_health(server)
        clear_graph()
        c = httpx.Client(base_url=BASE, timeout=30)
        c.post("/agents", json={
            "name": AGENT,
            "description": "SRE incident responder that remembers past incidents",
            "scope": "service, host, deploy, datastore, incident, root_cause",
        })
        c.put(f"/agents/{AGENT}/files/instructions.md",
              json={"content": INSTRUCTIONS, "actor": "operator"})

        print(f"\nLLM backend: {config.GRAPH and os.environ['ANDYUR_LLM']} "
              f"({os.environ['ANDYUR_AGENT_MODEL']}); graph: {config.GRAPH}")

        scenario(c, 1, "LEARN a new incident", (
            "INCIDENT: the checkout-service is returning HTTP 500s. You "
            "investigate and confirm the root cause is a misconfigured redis "
            "connection pool that was shipped in deploy-31. Record your findings."
        ), expect_recall=False)

        scenario(c, 2, "SAME incident, same wording (recall should HIT)", (
            "The checkout-service is returning HTTP 500s again. What do you "
            "already know about this? Diagnose it."
        ), expect_recall=True)

        scenario(c, 3, "Reworded but shares the word 'checkout' (still HITs)", (
            "Users report the payment checkout flow is failing intermittently "
            "for some customers. Investigate what might be going wrong."
        ), expect_recall=True)

        scenario(c, 4, "Same issue, NO shared words (recall MISS: the real gap)", (
            "Some customers are complaining they cannot complete their purchases "
            "and the buy button throws an error at the final step. Look into it."
        ), expect_recall=False)

        print(f"\n{RULE}\nGRAPH AFTER THE SCENARIO\n{RULE}")
        print("counts:", c.get(f"/agents/{AGENT}/graph/counts").json())
        print("types :", c.get(f"/agents/{AGENT}/graph/types").json())
        print("\nTakeaway:")
        print("- Step 2: same wording  -> recall HITs, the agent learned.")
        print("- Step 3: reworded but shares 'checkout' -> keyword recall still HITs.")
        print("- Step 4: same problem, no shared words -> recall MISSES. The root")
        print("  cause was IN the graph, but the wakeup did not lexically match, so")
        print("  the agent 'should have learned but didn't'. That is exactly the")
        print("  case semantic (vector) retrieval and self-reflection will address.")
    finally:
        server.terminate()


if __name__ == "__main__":
    main()
