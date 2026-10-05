#!/usr/bin/env python3
"""Seed a small, diverse andyur so you can SEE the whole platform at once.

Creates four agents with distinct purposes, seeds each one's memory graph, and
adds a few tasks, messages, and a schedule, all through the API with NO LLM
calls, so it is instant and free. Then watch it with:

    andyur status         # one-shot overview
    andyur watch          # live-refreshing overview

Prereqs (leave the server running so you can watch it):
    ./run.sh graph                         # Neo4j (for the graph seeding)
    ANDYUR_GRAPH=neo4j ./run.sh server &   # the control plane

Run:
    python demos/seed_andyur.py

Point at a non-default server with ANDYUR_SERVER_URL.
"""

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent  # repo root

# Re-exec under the project venv so `python3 demos/...` works with any Python
# (compare sys.prefix, not the executable: a venv's python symlinks to the base).
_VENV = HERE / ".venv"
_VENV_PY = _VENV / "bin" / "python"
if _VENV_PY.exists() and Path(sys.prefix).resolve() != _VENV.resolve():
    os.execv(str(_VENV_PY), [str(_VENV_PY), str(Path(__file__).resolve()), *sys.argv[1:]])

sys.path.insert(0, str(HERE))
import httpx  # noqa: E402

BASE = os.environ.get("ANDYUR_SERVER_URL", "http://127.0.0.1:8642")

AGENTS = [
    ("sentinel", "SRE incident responder that remembers past incidents",
     "service, host, deploy, datastore, incident, root_cause"),
    ("logwarden", "security-log triage agent",
     "user, source_ip, auth_event, alert, rule"),
    ("scribe", "release-notes and changelog writer",
     "release, feature, fix, pull_request, author"),
    ("scout", "competitive and news monitor",
     "company, product, launch, article, topic"),
]

# a few entities + facts per agent (name, type) and (subject, predicate, object)
GRAPH = {
    "sentinel": {
        "entities": [("checkout-service", "service"), ("redis", "datastore"),
                     ("deploy-31", "deploy"), ("checkout-500", "incident")],
        "facts": [("checkout-service", "depends_on", "redis"),
                  ("checkout-service", "had_incident", "checkout-500"),
                  ("checkout-500", "caused_by", "redis")],
    },
    "logwarden": {
        "entities": [("admin", "user"), ("10.0.0.9", "source_ip"),
                     ("brute-force", "alert")],
        "facts": [("brute-force", "targeted", "admin"),
                  ("brute-force", "from", "10.0.0.9")],
    },
    "scribe": {
        "entities": [("v2.3", "release"), ("dark-mode", "feature")],
        "facts": [("v2.3", "includes", "dark-mode")],
    },
    "scout": {
        "entities": [("acme-ai", "company"), ("acme-copilot", "product")],
        "facts": [("acme-ai", "launched", "acme-copilot")],
    },
}


def main():
    c = httpx.Client(base_url=BASE, timeout=15)
    try:
        c.get("/health").raise_for_status()
    except Exception:
        sys.exit(f"cannot reach the server at {BASE}; start it with "
                 f"ANDYUR_GRAPH=neo4j ./run.sh server")

    graph_on = None
    for name, desc, scope in AGENTS:
        r = c.post("/agents", json={"name": name, "description": desc, "scope": scope})
        status = "created" if r.status_code == 201 else "exists"
        # seed the graph (skip cleanly if the graph is off)
        g = GRAPH.get(name, {})
        for ename, etype in g.get("entities", []):
            gr = c.post(f"/agents/{name}/graph/entities",
                        json={"name": ename, "type": etype})
            if gr.status_code == 503:
                graph_on = False
                break
            graph_on = True
        if graph_on:
            for s, p, o in g.get("facts", []):
                c.post(f"/agents/{name}/graph/facts",
                       json={"subject": s, "predicate": p, "object": o})
        print(f"  {name:<12} {status}"
              + (f", graph seeded" if graph_on else ""))

    # a bit of collaboration to look at
    c.post("/tasks", json={"assignee": "logwarden", "creator": "sentinel",
                           "title": "check auth logs around deploy-31",
                           "detail": "correlate the checkout-500 incident with any auth anomalies"})
    c.post("/tasks", json={"assignee": "scribe", "creator": "operator",
                           "title": "draft release notes for v2.3"})
    c.post("/messages", json={"recipient": "operator", "sender": "scout",
                              "body": "acme-ai launched acme-copilot today, worth a look."})
    c.post("/messages", json={"recipient": "scribe", "sender": "operator",
                              "body": "please include the dark-mode feature in v2.3 notes."})
    c.post("/agents/scout/schedules",
           json={"cron": "*/15 * * * *", "reason": "scan for competitor news"})

    print("\nseeded 4 agents, 2 tasks, 2 messages, 1 schedule"
          + ("" if graph_on else " (graph off: no graph data)"))
    print("now see it all with:  andyur status   (or:  andyur watch)")


if __name__ == "__main__":
    main()
