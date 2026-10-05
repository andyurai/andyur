"""The simulated ads app as a standalone HTTP service: the shared, dynamic world
that BOTH sides act on. The Andyur support agent (the SUT) reaches it through its
MCP toolserver; the standalone customer simulator reaches it directly. Making the
environment a real service is the faithful τ²-bench shape and is what lets two
separate processes share one authoritative state.

Endpoints:
  POST /seed   {scenario}                 -> {ctx ids}     (build/reset the world)
  POST /call   {actor, tool, args}        -> tool result   (dual-control dispatch)
  GET  /snapshot                          -> full state
  GET  /goal                              -> {resolved: bool}
"""

from fastapi import FastAPI
from pydantic import BaseModel

from .app import dispatch
from .scenarios import SCENARIOS

app = FastAPI(title="adsupport-sim")

# one world per server; an episode seeds it, both parties then act on it
_state: dict = {"app": None, "scenario": None, "ctx": None}


class SeedBody(BaseModel):
    scenario: str


class CallBody(BaseModel):
    actor: str            # "agent" | "advertiser"
    tool: str
    args: dict = {}


@app.post("/seed")
def seed(body: SeedBody) -> dict:
    s = SCENARIOS[body.scenario]
    world, ctx = s.build()
    _state.update(app=world, scenario=body.scenario, ctx=ctx)
    return {"scenario": body.scenario, "ctx": ctx, "summary": s.summary}


@app.post("/call")
def call(body: CallBody) -> dict:
    world = _state["app"]
    if world is None:
        return {"ok": False, "error": "no world seeded"}
    return dispatch(world, body.actor, body.tool, body.args)


@app.get("/snapshot")
def snapshot() -> dict:
    world = _state["app"]
    return world.snapshot() if world else {}


@app.get("/goal")
def goal() -> dict:
    world, key, ctx = _state["app"], _state["scenario"], _state["ctx"]
    if world is None:
        return {"resolved": False}
    return {"resolved": bool(SCENARIOS[key].goal(world, ctx)),
            "dual_control": SCENARIOS[key].dual_control}
