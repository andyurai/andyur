"""Temporal as an Andyur workflow provider.

The ONLY directory in which the Temporal SDK may be imported. Everything above
this package speaks the provider interface and does not know which engine it
has -- an architecture test enforces that.

Nothing here is imported unless this provider is selected: `registry.py`
constructs providers lazily so that an installation without the Temporal extra
is unaffected by this package existing.
"""

from .config import TemporalConfig
from .provider import TemporalWorkflowProvider

__all__ = ["TemporalConfig", "TemporalWorkflowProvider"]
