"""Environment-variable lookup with the pre-rename name as a fallback.

The project was renamed from ``AutoSec`` to ``P2Patch``, and its knobs went
with it (``AUTOSEC_AGENT_NETWORK`` -> ``P2PATCH_AGENT_NETWORK``, and so on).
Operators export those in shell profiles, systemd units and CI configs that
this repository cannot reach, so reading only the new name would silently
change behaviour on every machine already configured: a run host that had
opted its builds back onto the network would go isolated again and its builds
would start failing for no visible reason.

So every read goes through :func:`get_env`, which prefers the new name and
falls back to the legacy one. The fallback is deliberately one-way — nothing
here writes the old name back — so a machine can migrate at its own pace and
setting the new name always wins.
"""
from __future__ import annotations

import os
from typing import Optional

ENV_PREFIX = "P2PATCH_"
LEGACY_ENV_PREFIX = "AUTOSEC_"


def legacy_name(name: str) -> Optional[str]:
    """The pre-rename spelling of ``name``, or None if it isn't ours."""
    if name.startswith(ENV_PREFIX):
        return LEGACY_ENV_PREFIX + name[len(ENV_PREFIX):]
    return None


def get_env(name: str, default: Optional[str] = None) -> Optional[str]:
    """``os.environ.get(name)``, falling back to the pre-rename spelling.

    An explicitly empty value still counts as set — ``P2PATCH_AGENT_NETWORK=""``
    means "isolated", which is a real choice and must not fall through to a
    legacy variable that says otherwise.
    """
    value = os.environ.get(name)
    if value is not None:
        return value
    legacy = legacy_name(name)
    if legacy is not None:
        value = os.environ.get(legacy)
        if value is not None:
            return value
    return default
