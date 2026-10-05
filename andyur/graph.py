"""Associative memory graph (Phase 6, slice 1).

A per-agent knowledge graph in Neo4j: entities as nodes, facts as edges between
them, and episodes as raw provenance. Only the server imports this; runners and
the CLI reach the graph over HTTP, so it stays behind the same server-owns-
storage boundary as the mind.

This is a deliberately thin layer behind one interface. It captures Graphiti's
model (entities, temporal-triplet facts, episodes as ground truth) without the
dependency, and keeps the door open to swap a real engine in later (see
docs/DESIGN.md D6). Enabled by ANDYUR_GRAPH=neo4j; a no-op when off.

Schema (Neo4j Community safe, no composite constraints):
  (:Entity  {id, agent, name, type, summary, created_at, updated_at, run_id})
  (:Episode {id, agent, run_id, text, created_at})
  (:Entity)-[:REL {predicate, valid_from, superseded_at, confidence,
                   run_id, created_at}]->(:Entity)
Entity identity is id = "<agent>::<name>", so per-agent namespacing and
deduplication of exact names happen at write time. Fuzzy resolution by embedding
comes in a later slice.
"""

import math
import re
import uuid
from datetime import datetime, timezone

from . import config

ENABLED = config.GRAPH == "neo4j"

_driver = None


def enabled() -> bool:
    return ENABLED


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _get_driver():
    """Lazily open one shared Neo4j driver. Imported here (not at module top)
    so `import andyur.graph` works even without the neo4j package when the
    graph is off, mirroring how db.py imports psycopg lazily."""
    global _driver
    if _driver is None:
        from neo4j import GraphDatabase

        _driver = GraphDatabase.driver(
            config.NEO4J_URL,
            auth=(config.NEO4J_USER, config.NEO4J_PASSWORD),
        )
    return _driver


def _run(cypher: str, **params):
    with _get_driver().session() as s:
        return list(s.run(cypher, **params))


def _eid(agent: str, name: str) -> str:
    return f"{agent}::{name}"


def init() -> None:
    """Create constraints and the full-text index. Idempotent."""
    if not ENABLED:
        return
    _run("CREATE CONSTRAINT entity_id IF NOT EXISTS "
         "FOR (e:Entity) REQUIRE e.id IS UNIQUE")
    _run("CREATE CONSTRAINT episode_id IF NOT EXISTS "
         "FOR (ep:Episode) REQUIRE ep.id IS UNIQUE")
    _run("CREATE FULLTEXT INDEX entity_fts IF NOT EXISTS "
         "FOR (n:Entity) ON EACH [n.name, n.summary]")


def upsert_entity(agent: str, name: str, type: str = "entity",
                  summary: str | None = None, run_id: str | None = None,
                  embedding: list[float] | None = None) -> dict:
    """Create or update an entity. Keyed on (agent, name), so writing the same
    name twice updates the one node rather than duplicating it. The embedding
    (computed by the runner from a local model) is stored on the node for later
    mechanical consolidation; it is left untouched when not provided."""
    now = _utcnow()
    rows = _run(
        "MERGE (e:Entity {id: $id}) "
        "ON CREATE SET e.agent=$agent, e.name=$name, e.created_at=$now, "
        "              e.run_id=$run_id "
        "SET e.type=$type, e.updated_at=$now "
        "SET e.summary = CASE WHEN $summary IS NULL THEN e.summary ELSE $summary END "
        "SET e.embedding = CASE WHEN $embedding IS NULL THEN e.embedding ELSE $embedding END "
        "RETURN e.id AS id, e.name AS name, e.type AS type",
        id=_eid(agent, name), agent=agent, name=name, type=type,
        summary=summary, run_id=run_id, embedding=embedding, now=now,
    )
    return dict(rows[0])


def add_fact(agent: str, subject: str, predicate: str, object: str,
             subject_type: str = "entity", object_type: str = "entity",
             valid_from: str | None = None, run_id: str | None = None,
             confidence: float = 1.0) -> dict:
    """Add a fact: subject -[predicate]-> object. Endpoints are upserted as
    entities so a fact can be stated without declaring its entities first. The
    predicate is stored as a property (not a Neo4j relationship type) so the
    free-text, emergent vocabulary needs no dynamic Cypher."""
    now = _utcnow()
    # Ensure both endpoints exist, but set their type only ON CREATE so a fact
    # never downgrades a specific type a dedicated entity write already set (the
    # types here are just fallbacks for entities seen only inside a fact).
    for nm, ty in ((subject, subject_type), (object, object_type)):
        _run(
            "MERGE (e:Entity {id:$id}) "
            "ON CREATE SET e.agent=$agent, e.name=$name, e.type=$type, "
            "              e.created_at=$now, e.updated_at=$now, e.run_id=$run_id",
            id=_eid(agent, nm), agent=agent, name=nm, type=ty, now=now,
            run_id=run_id,
        )
    rows = _run(
        "MATCH (s:Entity {id:$sid}), (o:Entity {id:$oid}) "
        "MERGE (s)-[r:REL {predicate:$predicate}]->(o) "
        "ON CREATE SET r.created_at=$now, r.valid_from=$valid_from, "
        "              r.run_id=$run_id, r.confidence=$confidence, "
        "              r.superseded_at=null "
        "RETURN s.name AS subject, r.predicate AS predicate, o.name AS object",
        sid=_eid(agent, subject), oid=_eid(agent, object), predicate=predicate,
        valid_from=valid_from or now, run_id=run_id, confidence=confidence, now=now,
    )
    return dict(rows[0])


def add_episode(agent: str, run_id: str | None, text: str) -> dict:
    """Record a raw episode: the ground-truth source a run saw, that entities
    and facts are derived from. Provenance for everything else in the graph."""
    ep_id = uuid.uuid4().hex[:12]
    _run(
        "CREATE (ep:Episode {id:$id, agent:$agent, run_id:$run_id, "
        "text:$text, created_at:$now})",
        id=ep_id, agent=agent, run_id=run_id, text=text, now=_utcnow(),
    )
    return {"id": ep_id}


def _lucene_clean(q: str) -> str:
    """Reduce arbitrary text (a wakeup context) to plain terms so it is safe to
    hand the Lucene full-text index (which chokes on its special characters)."""
    return " ".join(re.findall(r"[A-Za-z0-9_\-]+", q or ""))


def forget_agent(agent: str) -> int:
    """Delete every node this agent owns, and the relationships attached to them.

    A no-op when the graph is off, so agent deletion works the same whether or not
    Neo4j is configured -- otherwise deleting an agent would leave its memory
    behind on graph-enabled deployments only, which is the kind of difference
    nobody discovers until it matters.

    DETACH is required: Neo4j refuses to delete a node that still has
    relationships, so a plain DELETE would fail on exactly the agents that have
    memory worth deleting."""
    if not ENABLED:
        return 0
    rows = _run(
        "MATCH (n) WHERE n.agent = $agent "
        "WITH n, count(*) AS _ DETACH DELETE n RETURN count(_) AS gone",
        agent=agent,
    )
    return int(rows[0]["gone"]) if rows else 0


def search(agent: str, query: str, limit: int = 10) -> list[dict]:
    """Full-text search over this agent's entities (name + summary)."""
    q = _lucene_clean(query)
    if not q:
        return []
    rows = _run(
        "CALL db.index.fulltext.queryNodes('entity_fts', $q) YIELD node, score "
        "WHERE node.agent = $agent "
        "RETURN node.name AS name, node.type AS type, node.summary AS summary, "
        "score ORDER BY score DESC LIMIT $limit",
        q=q, agent=agent, limit=limit,
    )
    return [dict(r) for r in rows]


def recall(agent: str, query: str, limit: int = 5, per_entity: int = 8) -> list[dict]:
    """The subgraph relevant to a wakeup context: full-text match for seed
    entities, then each seed with its immediate facts. This is what the runner
    injects into a run's prompt so the agent recalls what it learned before."""
    out = []
    for s in search(agent, query, limit):
        nb = neighbors(agent, s["name"], per_entity)
        out.append({"name": s["name"], "type": s["type"],
                    "score": s["score"], "facts": nb["facts"]})
    return out


def known_types(agent: str, limit: int = 40) -> list[str]:
    """The entity types this agent has already coined, fed back into extraction
    so its emergent ontology converges instead of sprouting near-duplicates."""
    rows = _run(
        "MATCH (e:Entity {agent:$agent}) WHERE e.type IS NOT NULL "
        "RETURN DISTINCT e.type AS type LIMIT $limit",
        agent=agent, limit=limit,
    )
    return [r["type"] for r in rows]


def neighbors(agent: str, name: str, limit: int = 25) -> dict:
    """The entity and its immediate facts, both directions."""
    rows = _run(
        "MATCH (e:Entity {id:$id})-[r:REL]-(m:Entity) "
        "RETURN e.name AS entity, "
        "       CASE WHEN startNode(r)=e THEN 'out' ELSE 'in' END AS dir, "
        "       r.predicate AS predicate, m.name AS other, "
        "       r.valid_from AS valid_from, r.confidence AS confidence "
        "LIMIT $limit",
        id=_eid(agent, name), limit=limit,
    )
    return {"entity": name, "facts": [dict(r) for r in rows]}


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _merge_entities(keep_id: str, drop_id: str) -> None:
    """Fold drop into keep: re-home its edges onto keep (no duplicate edges,
    no self-loops), then delete it. No APOC needed."""
    _run("MATCH (d:Entity {id:$drop})-[r:REL]->(x) WHERE x.id <> $keep "
         "MATCH (k:Entity {id:$keep}) "
         "MERGE (k)-[nr:REL {predicate:r.predicate}]->(x) "
         "ON CREATE SET nr = properties(r) DELETE r", drop=drop_id, keep=keep_id)
    _run("MATCH (x)-[r:REL]->(d:Entity {id:$drop}) WHERE x.id <> $keep "
         "MATCH (k:Entity {id:$keep}) "
         "MERGE (x)-[nr:REL {predicate:r.predicate}]->(k) "
         "ON CREATE SET nr = properties(r) DELETE r", drop=drop_id, keep=keep_id)
    _run("MATCH (d:Entity {id:$drop}) DETACH DELETE d", drop=drop_id)


def _prune_orphans(agent: str) -> int:
    n = _run("MATCH (e:Entity {agent:$agent}) WHERE NOT (e)-[:REL]-() "
             "RETURN count(e) AS n", agent=agent)[0]["n"]
    if n:
        _run("MATCH (e:Entity {agent:$agent}) WHERE NOT (e)-[:REL]-() "
             "DETACH DELETE e", agent=agent)
    return n


def consolidate(agent: str, threshold: float | None = None,
                prune: bool = True) -> dict:
    """Consolidation A: mechanical, no LLM. Merge near-identical entities by
    cosine over the embeddings the runner already computed, then prune orphans.
    Pure vector math + graph ops, so it runs in the control plane without
    touching a model. Keeps the higher-degree node of each merged pair."""
    threshold = config.GRAPH_MERGE_THRESHOLD if threshold is None else threshold
    before = counts(agent)["entities"]
    rows = _run(
        "MATCH (e:Entity {agent:$agent}) WHERE e.embedding IS NOT NULL "
        "OPTIONAL MATCH (e)-[r:REL]-() "
        "WITH e, count(r) AS degree "
        "RETURN e.id AS id, e.name AS name, degree, e.embedding AS embedding",
        agent=agent,
    )
    ents = [dict(r) for r in rows]
    pairs = []
    for i in range(len(ents)):
        for j in range(i + 1, len(ents)):
            sim = _cosine(ents[i]["embedding"], ents[j]["embedding"])
            if sim >= threshold:
                pairs.append((sim, i, j))
    pairs.sort(reverse=True)  # merge the most similar first
    dropped, merged = set(), 0
    for _sim, i, j in pairs:
        a, b = ents[i], ents[j]
        if a["id"] in dropped or b["id"] in dropped:
            continue
        keep, drop = (a, b) if a["degree"] >= b["degree"] else (b, a)
        _merge_entities(keep["id"], drop["id"])
        dropped.add(drop["id"])
        merged += 1
    pruned = _prune_orphans(agent) if prune else 0
    return {"entities_before": before, "merged": merged, "pruned": pruned,
            "entities_after": counts(agent)["entities"]}


def counts(agent: str) -> dict:
    """Node/edge tallies for one agent. Handy for verification and reporting."""
    e = _run("MATCH (e:Entity {agent:$agent}) RETURN count(e) AS n", agent=agent)
    f = _run("MATCH (:Entity {agent:$agent})-[r:REL]->(:Entity {agent:$agent}) "
             "RETURN count(r) AS n", agent=agent)
    ep = _run("MATCH (ep:Episode {agent:$agent}) RETURN count(ep) AS n", agent=agent)
    return {"entities": e[0]["n"], "facts": f[0]["n"], "episodes": ep[0]["n"]}
