"""Reviewable development-tenant provisioning for authorization servers."""

from .model import ProvisionSpec, load_spec
from .terraform import render

__all__ = ["ProvisionSpec", "load_spec", "render"]
