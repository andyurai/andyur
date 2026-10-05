"""Authenticated HTTP adapter over the registry's locked read contract."""

from dataclasses import asdict
from fastapi import APIRouter, Depends, HTTPException

from ..server import auth
from .models import (AgentCatalog, AgentNotFound, InvalidAgentManifest,
                     RegistryUnavailable)
from .service import configured_registry

router = APIRouter(prefix="/v1/registry", tags=["agent-registry"])


def registry_provider() -> AgentCatalog:
    """Dependency seam for an enterprise-backed registry adapter."""
    try:
        return configured_registry()
    except (InvalidAgentManifest, RegistryUnavailable) as exc:
        raise HTTPException(503, f"agent registry is unavailable: {exc}") from exc


def _card_dict(card) -> dict | None:
    """The card as the catalogue serves it. `None` stays `None`: an agent
    without a card is a different thing from one whose card says nothing."""
    if card is None:
        return None
    return {
        "summary": card.summary,
        "category": card.category,
        "requires": None if card.requires is None else list(card.requires),
    }


def _resolution_dict(resolution) -> dict:
    return {
        "agent_id": resolution.agent_id,
        "name": resolution.name,
        "bundle": resolution.bundle,
        "card": _card_dict(resolution.card),
        "instructions": resolution.instructions,
        "model": resolution.model,
        "tools": [{key: value for key, value in asdict(tool).items()
                   if value is not None} for tool in resolution.tools],
        "ceiling": {
            "actions": (None if resolution.ceiling.actions is None
                        else list(resolution.ceiling.actions)),
            "resources": (None if resolution.ceiling.resources is None
                          else list(resolution.ceiling.resources)),
        },
        # Governed mode stamps the snapshot digest; manifest mode has none.
        "registry_digest": resolution.registry_digest,
        # What a catalog shows about HOW the agent runs; None for a
        # resolution without a runtime block (an older artifact).
        "runtime": None if resolution.runtime is None else {
            "interface_version": resolution.runtime.interface_version,
            "image_ref": resolution.runtime.image_ref,
            "image_digest": resolution.runtime.image_digest,
            "command": (None if resolution.runtime.command is None
                        else list(resolution.runtime.command)),
        },
    }


@router.get("/agents")
def list_agents(
    _id: str = auth.require(auth.OPERATOR, auth.CONTROL_PLANE),
    registry: AgentCatalog = Depends(registry_provider),
) -> dict:
    try:
        agents = registry.list_agents()
    except (InvalidAgentManifest, RegistryUnavailable) as exc:
        raise HTTPException(503, f"agent registry is unavailable: {exc}")
    # The listing carries the CARD, not just the identifiers. Choosing an agent
    # from a catalogue that prints only ids means resolving every one of them to
    # find out what any of them is for.
    return {"agents": [
        {"agent_id": agent.agent_id, "name": agent.name,
         "bundle": agent.bundle, "card": _card_dict(agent.card)}
        for agent in sorted(agents, key=lambda item: (item.bundle or "", item.name))
    ]}


@router.get("/agents/{agent_id}/resolve")
def resolve_agent(
    agent_id: str,
    _id: str = auth.require(auth.OPERATOR, auth.CONTROL_PLANE),
    registry: AgentCatalog = Depends(registry_provider),
) -> dict:
    # NO USER TOKEN AND NO OWNER FILTER, deliberately: the registry is a shared
    # catalog of approved definitions and every authenticated operator may read
    # every one of them. See andyur/registry/__init__.py for the decision and
    # what does NOT follow from it. This route is authenticated -- no bearer is
    # 401 and a run token is 403 -- it is simply not tenant-scoped.
    try:
        return _resolution_dict(registry.resolve(agent_id))
    except AgentNotFound:
        raise HTTPException(404, f"no registry agent with id '{agent_id}'")
    except (InvalidAgentManifest, RegistryUnavailable) as exc:
        raise HTTPException(503, f"agent registry is unavailable: {exc}")
