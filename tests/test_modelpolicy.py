"""One model-call policy for both enforcement points (R HIGH-1, PR #22)."""
from andyur import modelpolicy as mp


def test_only_post_to_the_model_call_endpoints_passes():
    assert mp.path_refusal("POST", "/v1/chat/completions", mp.FRONT_LLM_PATHS) is None
    assert mp.path_refusal("POST", "/api/chat?x=1", mp.FRONT_LLM_PATHS) is None
    assert mp.path_refusal("POST", "/api/generate", mp.FRONT_LLM_PATHS) is None
    for method, path in (("GET", "/api/tags"), ("GET", "/api/ps"), ("DELETE", "/api/delete"),
                         ("POST", "/api/pull"), ("POST", "/api/create"), ("POST", "/api/copy"),
                         ("POST", "/api/blobs/sha256:x"), ("POST", "/api/experimental/web_fetch"),
                         ("GET", "/v1/chat/completions"), ("POST", "/v1/models"), ("GET", "/api/version")):
        assert mp.path_refusal(method, path, mp.FRONT_LLM_PATHS), (method, path)
    # the api-mode sidecar keeps its own (Anthropic) set
    assert mp.path_refusal("POST", "/v1/messages", mp.SIDECAR_LLM_PATHS) is None
    assert mp.path_refusal("POST", "/api/chat", mp.SIDECAR_LLM_PATHS)


def test_the_model_pin_refuses_absent_wrong_and_malformed_never_rewrites():
    assert mp.model_refusal(b'{"model": "granted"}', "granted") is None
    assert mp.model_refusal(b'{"model": "other"}', "granted").status == 403
    assert mp.model_refusal(b'{"messages": []}', "granted").status == 403      # absent is refused
    assert mp.model_refusal(b'not json', "granted").status == 400
    assert mp.model_refusal(b'{"model": "anything"}', None) is None         # unbound run


def test_a_case_variant_or_duplicate_model_key_is_refused_and_only_the_validated_object_is_forwarded():
    """R HIGH (PR #22/#23), reproduced live against Ollama: Go's encoding/json
    matches field names case-insensitively and takes the LAST match, so
    {"model": granted, "MODEL": other} passed a naive check and ran `other`.
    Re-serialising does not help (both keys survive); the rule refuses any
    extra key that case-folds to "model", and any repeated key."""
    ok, refusal = mp.validate_model_request(b'{"model": "granted", "messages": []}', "granted")
    assert refusal is None and ok == b'{"model":"granted","messages":[]}'      # canonical, validated
    for body in (b'{"model": "granted", "MODEL": "other"}',
                 b'{"model": "granted", "Model": "other"}',
                 b'{"MODEL": "granted"}',
                 b'{"model": "granted", "model": "other"}',                  # duplicate: last wins in Go
                 b'{"messages": [], "model": "granted", "mOdEl": "other"}'):
        canonical, refusal = mp.validate_model_request(body, "granted")
        assert canonical is None and refusal is not None and refusal.status in (400, 403), body
    # a nested "MODEL" is not a top-level field and is left alone
    ok, refusal = mp.validate_model_request(b'{"model": "granted", "options": {"MODEL": "x"}}', "granted")
    assert refusal is None and b'"MODEL":"x"' in ok
    # unbound run: passthrough of the raw bytes, whatever they are
    assert mp.validate_model_request(b'{"MODEL": "anything"}', None) == (b'{"MODEL": "anything"}', None)


def test_require_model_refuses_every_call_when_nothing_was_granted():
    assert mp.validate_model_request(b'{"model": "qwen3:8b"}', None, require_model=True)[1].status == 403
    assert mp.validate_model_request(b'{"model": "qwen3:8b"}', "", require_model=True)[1].status == 403
    assert mp.validate_model_request(b'{"model": "qwen3:8b"}', None)[1] is None       # unbound legacy run



def test_every_refusal_code_is_emitted_by_exactly_the_decision_it_names():
    """ONE reason vocabulary (observability-exit-criteria.md 1; R must-have 3
    on the observability plan): the code is the string the error body
    carries, the span records, the log names and the gate asserts. Each code
    maps to one decision; the closed set is exactly what the module emits plus
    the front's and the tool service's own codes."""
    emitted = {
        "path_not_model_call": mp.path_refusal("GET", "/api/tags", mp.FRONT_LLM_PATHS),
        "no_model_granted": mp.model_refusal(b'{"model": "x"}', None, require_model=True),
        "duplicate_model_key": mp.model_refusal(b'{"model": "g", "model": "o"}', "g"),
        "body_not_json": mp.model_refusal(b"not json", "g"),
        "model_missing": mp.model_refusal(b'{"messages": []}', "g"),
        "model_key_variant": mp.model_refusal(b'{"model": "g", "MODEL": "o"}', "g"),
        "model_not_granted": mp.model_refusal(b'{"model": "o"}', "g"),
    }
    for code, refusal in emitted.items():
        assert isinstance(refusal, mp.Refusal) and refusal.code == code, code
        assert refusal.body() == {"error": code, "detail": refusal.message}
        assert code in mp.REFUSAL_CODES
    assert mp.model_refusal(b"[1, 2]", "g").code == "model_missing"      # not an object: names none
    front_only = {"path_refused", "body_too_large", "no_model_proxy", "upstream_unreachable"}
    tool_only = {"bearer_rejected"}
    assert mp.REFUSAL_CODES == set(emitted) | front_only | tool_only
    # the metric bound mirrors the vocabulary (plus "none" for a forwarded call)
    from andyur import observability
    assert observability._REFUSALS == mp.REFUSAL_CODES | {"none"}
