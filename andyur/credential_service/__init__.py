"""Trusted credential-service components; never import these into agent code."""

from .openbao import OpenBaoClient, OpenBaoError

__all__ = ["OpenBaoClient", "OpenBaoError"]
