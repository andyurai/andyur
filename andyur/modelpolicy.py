"""The model-call policy every model path enforces: which endpoints a run may
reach, and that every request names the model the run was granted.

Two enforcement points share it (R HIGH-1, PR #22): the api-mode ToolSidecar's
`/llm` (`proxy/app.py`, Anthropic shapes via LiteLLM) and the exec/v1 sidecar's
front (`runner/execfront.py`, forwarding to the platform's model leg -- in
local-model mode the shared Ollama daemon). One function backs both, so a path
the sidecar refuses cannot be reachable through the front, and a model the
sidecar pins cannot be un-pinned there. Without it the front forwarded the
ENTIRE Ollama HTTP API (`/api/tags`, `/api/ps`, `/api/delete`, `/api/pull`,
`/api/create`, web fetch) with no model check: a stock workload could list,
delete or fetch models on the developer's daemon, and break memory capture for
every later run.

ONE REASON VOCABULARY (observability-exit-criteria.md 1; R must-have on the
observability plan): every refusal is a `Refusal` whose `code` is the SAME
string the error body carries, the span attribute records, the log line names
and the live gates assert -- so "why was this refused" is answerable by
grepping one name across trace, log and artifact. `REFUSAL_CODES` is the
closed set; `observability._REFUSALS` mirrors it as a metric bound.

Deliberately dependency-free (json only), like mcpwire.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

# The api-mode sidecar fronts LiteLLM's Anthropic surface.
SIDECAR_LLM_PATHS = frozenset({"/v1/messages", "/v1/messages/count_tokens"})
# The exec/v1 front fronts whatever model leg the run has: the OpenAI-compatible
# chat surface (what OpenSRE's Ollama provider calls at investigate time) and
# Ollama's own chat/generate. Model listing, management and fetch endpoints are
# not a run's business and are refused BY NAME.
FRONT_LLM_PATHS = frozenset({"/v1/chat/completions", "/api/chat", "/api/generate"})


@dataclass(frozen=True)
class Refusal:
    """Why a request may not reach the model leg: a bounded code, the HTTP
    status the enforcement point answers with, and the human message."""
    code: str
    status: int
    message: str

    def body(self) -> dict:
        """The error body every exec/v1 listener answers with."""
        return {"error": self.code, "detail": self.message}


# The closed set, by the decision that emits each (tests pin the mapping).
REFUSAL_CODES = frozenset({
    "path_not_model_call",     # method/path outside the allowed model calls (404)
    "no_model_granted",        # the run was granted no model at all (403)
    "duplicate_model_key",     # a JSON object key repeated (400)
    "body_not_json",           # the body is not a JSON document (400)
    "model_missing",           # no object, or no key spells "model" (403)
    "model_key_variant",       # keys case-folding to "model" beyond the one (403)
    "model_not_granted",       # a model other than the granted one (403)
    # emitted by the exec/v1 front alone
    "path_refused",            # dot/empty segments under /llm (400)
    "body_too_large",          # beyond the per-run model call bound (413)
    "no_model_proxy",          # this run has no model leg to forward to (503)
    "upstream_unreachable",    # the model leg did not answer (502)
    # emitted by the tool service alone
    "bearer_rejected",         # /mcp without the declared bearer (401)
})


def path_refusal(method: str, path: str, allowed: frozenset[str]) -> Refusal | None:
    """Why this (method, path) may not reach the model leg, or None."""
    clean = path.split("?", 1)[0]
    if method.upper() != "POST" or clean not in allowed:
        return Refusal("path_not_model_call", 404,
                       f"{method} {clean} is not a model call this run may make; "
                       f"allowed: POST {sorted(allowed)}")
    return None


class _Duplicate(ValueError):
    pass


def _no_duplicate_keys(pairs):
    """object_pairs_hook: a JSON object with a repeated key is refused, not
    resolved by "last wins" -- Python's json and Go's encoding/json both keep
    the last, but the point is that two decoders may not agree."""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise _Duplicate(key)
        obj[key] = value
    return obj


def validate_model_request(body: bytes, enforced_model: str | None, *,
                           require_model: bool = False
                           ) -> tuple[bytes | None, Refusal | None]:
    """(canonical_body, None) when the request names the granted model and
    NOTHING ELSE that an upstream could read as the model; (None, Refusal)
    otherwise.

    The upstream is not this decoder. Go's encoding/json (Ollama) matches
    field names CASE-INSENSITIVELY and takes the last match, so a body carrying
    {"model": "<granted>", "MODEL": "<other>"} passes a naive `payload["model"]`
    check here and runs <other> there (R HIGH on PR #22/#23, reproduced live).
    Re-serialising the parsed dict does not help: both keys survive. So the
    rule is: exactly one top-level key case-folds to "model", it is spelled
    "model", it names the granted model, no key is duplicated -- and what is
    forwarded is the VALIDATED object re-serialised, never the raw bytes, so the
    upstream decodes exactly what was checked. Absent or different is refused,
    never rewritten: a rewrite hides that the run tried. With no enforced model
    (a legacy/unbound run) the body passes through unchanged -- unless
    ``require_model`` says this run MUST have a grant (exec/v1: the workload
    cannot fetch a context to learn one, and a default would be a model the
    policy never approved -- R MED-1), in which case no grant refuses every
    model call.
    """
    if not enforced_model:
        if require_model:
            return None, Refusal("no_model_granted", 403,
                                 "this run was granted no model; every model call is refused")
        return body, None
    try:
        payload = json.loads(body or b"{}", object_pairs_hook=_no_duplicate_keys)
    except _Duplicate as dup:
        return None, Refusal("duplicate_model_key", 400,
                             f"model request repeats the key {str(dup)!r}")
    except ValueError:
        return None, Refusal("body_not_json", 400, "malformed model request body")
    if not isinstance(payload, dict):
        return None, Refusal("model_missing", 403,
                             f"this run may call only its granted model {enforced_model!r}, "
                             "and the request names none")
    model_keys = [key for key in payload if isinstance(key, str) and key.casefold() == "model"]
    if model_keys != ["model"]:
        if not model_keys:
            return None, Refusal("model_missing", 403,
                                 f"this run may call only its granted model {enforced_model!r}, "
                                 "and the request names none")
        return None, Refusal("model_key_variant", 403,
                             f"model request carries {model_keys!r}: exactly one key spelled "
                             "\"model\" is allowed (an upstream may match it case-insensitively)")
    requested = payload["model"]
    if requested != enforced_model:
        return None, Refusal("model_not_granted", 403,
                             f"this run may call only its granted model {enforced_model!r}, "
                             f"not {requested!r}")
    return json.dumps(payload, separators=(",", ":")).encode("utf-8"), None


def model_refusal(body: bytes, enforced_model: str | None, *,
                  require_model: bool = False) -> Refusal | None:
    """The refusal half of validate_model_request, or None."""
    return validate_model_request(body, enforced_model, require_model=require_model)[1]
