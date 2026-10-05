"""The native engine, behind the provider interface.

Andyur's own coordinator, worker daemon and server heartbeat loop, presented as
a `WorkflowProvider`. This is a wrapper and nothing more: it adds no behaviour,
owns no state of its own, and every operation below delegates to code that was
already there.
"""

from .provider import LocalWorkflowProvider

__all__ = ["LocalWorkflowProvider"]
