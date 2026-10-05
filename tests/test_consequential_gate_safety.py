"""Execute the real gate entry point without cluster or import-time side effects."""
import ast
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("created", [False, True])
def test_fixture_failure_never_deletes_an_uncreated_or_unbound_namespace(created):
    path = Path(__file__).resolve().parents[1] / "infra/kubernetes/verify-consequential-action.py"
    tree = ast.parse(path.read_text())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                and node.name == "main")
    deletion = []
    unsafe = []

    def create(*args, **kwargs):
        if not created:
            raise RuntimeError("create refused: preexisting namespace")
        return SimpleNamespace(metadata=SimpleNamespace(uid="owned-uid"))

    def fixture(*args):
        raise RuntimeError("fixture failed after namespace creation")

    core = SimpleNamespace(create_namespace=create,
                           delete_namespace=lambda *args: unsafe.append(args))
    tracer = SimpleNamespace(start_as_current_span=lambda *args, **kwargs: nullcontext())
    scope = {
        "secrets": SimpleNamespace(token_hex=lambda n: "a" * (2 * n)),
        "DEPLOYMENT": "checkout", "GOOD_IMAGE": "good", "BAD_IMAGE": "bad",
        "otel": SimpleNamespace(setup_tracing=lambda name: tracer,
                                context_from=lambda value: None),
        "kube": lambda: (core, object(), SimpleNamespace(
            get_code=lambda: SimpleNamespace(git_version="v1.fixture"))),
        "platform": SimpleNamespace(platform=lambda: "test"),
        "time": SimpleNamespace(time=lambda: 0),
        "db": SimpleNamespace(init_db=lambda: None),
        "actionrequests": SimpleNamespace(),
        "say": lambda *args: None, "create_fixture": fixture,
        "delete_owned": lambda *args: deletion.append(args),
    }
    exec(compile(ast.Module(body=[main], type_ignores=[]), str(path), "exec"), scope)
    with pytest.raises(RuntimeError, match="fixture failed|create refused"):
        scope["main"]()
    assert unsafe == []
    assert deletion == ([(core, "andyur-action-" + "a" * 16, "owned-uid")]
                        if created else [])
