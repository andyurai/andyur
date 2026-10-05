"""Choosing a provider. Configuration, never a branch in business code.

`ANDYUR_WORKFLOW_PROVIDER` selects one. Nothing above this module may ask which
provider it got and behave differently -- the whole point of the interface is
that callers do not know. A module containing `if provider == "temporal"` has
reintroduced the coupling the seam exists to remove, and the architecture tests
look for exactly that.

## There is no fallback, and that is the entire design

The tempting behaviour is that an unreachable or unknown provider degrades to
the local one so the platform keeps serving. It must not, for a reason specific
to what this platform is: the providers do not offer the same guarantees. Work
admitted under a durable provider and silently continued by a single-node one
has quietly lost the durability it was accepted on the strength of -- and the
first anyone learns of it is an approval that never came back after a restart.

Refusing is louder and safer. An operator who wants the local provider says so.
"""

from __future__ import annotations

import os

from .provider import WorkflowProvider

DEFAULT = "local"

ENV_VAR = "ANDYUR_WORKFLOW_PROVIDER"


class UnknownProvider(ValueError):
    """The configured provider name is not one this build has.

    A ValueError rather than an OrchestrationError: this is a configuration
    mistake caught at construction, not a failure of orchestration, and it must
    stop the process rather than surface as a runtime error some caller might
    handle.
    """


def _temporal() -> WorkflowProvider:
    # Lazy for the same reason as the local one, and more so: the Temporal SDK
    # is an OPTIONAL extra, so importing this package eagerly would make an
    # installation without it unable to construct the provider it does have.
    from .temporal import TemporalWorkflowProvider

    return TemporalWorkflowProvider()


def _local() -> WorkflowProvider:
    # Imported lazily so that selecting a different provider does not import
    # this one, and -- more importantly -- so that a provider whose SDK is not
    # installed cannot break construction of the one that is.
    from .local import LocalWorkflowProvider

    return LocalWorkflowProvider()


# Name -> constructor for the BUILT-IN providers. A built-in provider is added
# here and nowhere else. The only other source is an extension the operator
# named in ANDYUR_EXTENSIONS (see andyur/extensions.py): there is still no scan,
# and an installed extension nobody enabled is never imported, so the complete
# set is this dict plus that one variable. An implicit provider is one nobody
# reviewed.
BUILDERS = {
    "local": _local,
    "temporal": _temporal,
}


def known_builders() -> dict:
    """Built-in providers plus those offered by enabled extensions. An extension
    cannot take a built-in name; `extensions.Registrar` refuses it."""
    from .. import extensions

    return {**BUILDERS, **extensions.loaded().workflow_providers}


def configured_name() -> str:
    return (os.environ.get(ENV_VAR) or DEFAULT).strip().lower()


def build_workflow_provider(name: str | None = None) -> WorkflowProvider:
    """Construct the configured provider, or refuse.

    Refuses by NAME before constructing anything, so a typo is reported as a
    typo -- "'temporel' is not a known provider" -- rather than as whatever the
    default happens to do next.
    """
    chosen = (name or configured_name()).strip().lower()
    builders = known_builders()
    try:
        builder = builders[chosen]
    except KeyError:
        known = ", ".join(sorted(builders))
        raise UnknownProvider(
            f"{ENV_VAR}='{chosen}' is not a known workflow provider "
            f"(known: {known}). There is deliberately no fallback: providers do "
            "not offer the same guarantees, so continuing under a different one "
            "than was asked for would silently change what the platform promises."
        ) from None
    provider = builder()
    # The name a provider reports is what a run is BOUND to and later claimed
    # by, so it has to be the name it was selected under. Reserving the
    # registry key alone left the other half open: a provider registered as
    # `cadence` that reports itself as `temporal` would be handed runs bound to
    # the built-in engine.
    reported = getattr(provider, "name", None)
    if reported != chosen:
        raise UnknownProvider(
            f"workflow provider '{chosen}' reports its name as {reported!r}. "
            "A provider is bound to runs by the name it reports, so it must be "
            "the name it was selected under.")
    return provider
