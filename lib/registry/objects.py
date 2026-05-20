"""Shared imports for registry consumers.

This module re-exports the same BaseNode / ConfigRoot / ScopeCtx
primitives that live in lib.core, so existing downstream code can
import from either location without divergence.
"""

from lib.core import BaseNode, ConfigRoot, ScopeCtx

__all__ = ["BaseNode", "ConfigRoot", "ScopeCtx"]
