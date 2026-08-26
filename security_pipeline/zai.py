"""Z.ai (GLM) provider wiring for the agent runner.

Claude Code can be pointed at any Anthropic-API-compatible endpoint through a
handful of environment variables, so running the pipeline's agents on Z.ai's GLM
models is a matter of injecting the right ``env`` block rather than of teaching
the runner about a second provider. The operator keeps the credentials in
``~/.claude/settings-zai.json`` (the file Z.ai's own setup instructions produce);
this module reads that file and turns it into the env a run needs.

Two design points worth stating, because both were choices:

* **The global ``~/.claude/settings.json`` is never touched.** Agents run with
  ``--setting-sources ""`` (see ``claude_agents.build_command``), so the user
  settings file is not read by them at all — rewriting it would change nothing
  for the pipeline while silently repointing the operator's own interactive
  sessions at Z.ai. It would also be a process-global mutation, and the
  dashboard runs several launches concurrently, potentially on different models.
  The config is therefore applied **per run**: merged into the pipeline-owned
  ``--settings`` file and into the ``claude`` subprocess environment.
* **Secrets stay out of run artifacts.** The per-agent ``settings.json`` is
  persisted under ``agent_io/`` and read by the dashboard, so ``zai_settings_env``
  drops anything that looks like a credential (``*_TOKEN``/``*_KEY``/…); the real
  token reaches the CLI only through ``zai_process_env``, which is passed to
  ``subprocess`` and never written down. Redacting in place is not an option —
  the CLI reads that same file, so a redacted value would override the real one.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional

from .env import get_env
from .models import JsonDict


class ZaiConfigError(RuntimeError):
    """Raised when a GLM model is requested but the Z.ai config is unusable."""


# Models the launcher may select to route a run through Z.ai. Values are passed
# verbatim to ``claude --model`` (Z.ai's Anthropic-compatible endpoint resolves
# them) *and* substituted into the alias slots below. Add a row to expose more.
ZAI_MODELS = ("glm-5.1", "glm-5.2", "glm-5.3")

# Env var that overrides where the Z.ai settings file lives, for tests and for
# hosts that keep it somewhere other than the default.
ZAI_SETTINGS_PATH_ENV = "P2PATCH_ZAI_SETTINGS"
DEFAULT_ZAI_SETTINGS_PATH = Path("~/.claude/settings-zai.json")

# The alias slots retargeted at the selected model — all three, including haiku.
# Z.ai's stock file points haiku at a cheap "air" model, which would leave the
# CLI's background/summarization turns on a different model than the run is
# labelled with; pinning every slot keeps a GLM run single-model, the same
# property ``--model`` being always-pinned gives a Claude run.
ALIAS_SLOTS_FOR_SELECTED_MODEL = (
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
)

# Required before a run is allowed to start: without a base URL the request goes
# to Anthropic on a GLM model name, which fails late and confusingly.
REQUIRED_KEYS = ("ANTHROPIC_BASE_URL",)
# One of these must carry a real credential.
CREDENTIAL_KEYS = ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY")
# Values that mean "the operator has not filled this in yet".
PLACEHOLDER_VALUES = frozenset(
    {"", "your_zai_api_key", "your-zai-api-key", "sk-your-key", "changeme", "todo"}
)

# Substrings that mark an env key as a credential, kept out of the persisted
# per-agent settings file.
_SECRET_KEY_MARKERS = ("TOKEN", "KEY", "SECRET", "PASSWORD", "CREDENTIAL")


def is_zai_model(model: Optional[str]) -> bool:
    """True when ``model`` selects a Z.ai-hosted GLM model."""
    return bool(model) and model.strip().lower() in ZAI_MODELS


def zai_settings_path() -> Path:
    override = get_env(ZAI_SETTINGS_PATH_ENV)
    raw = Path(override) if override else DEFAULT_ZAI_SETTINGS_PATH
    return raw.expanduser()


def load_zai_settings(path: Optional[Path] = None) -> JsonDict:
    """Read the operator's Z.ai settings file.

    Raises ``ZaiConfigError`` rather than returning a partial config: every
    caller here is about to spend Docker build time and agent turns on a run that
    would otherwise fail against the wrong endpoint.
    """
    target = path or zai_settings_path()
    try:
        raw = target.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ZaiConfigError(
            f"Z.ai settings file not found: {target}. Create it with your Z.ai "
            "API key (ANTHROPIC_AUTH_TOKEN) and base URL, or pick a Claude model."
        ) from None
    except OSError as exc:
        raise ZaiConfigError(f"cannot read Z.ai settings file {target}: {exc}") from None

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ZaiConfigError(f"Z.ai settings file {target} is not valid JSON: {exc}") from None
    if not isinstance(parsed, dict):
        raise ZaiConfigError(f"Z.ai settings file {target} must contain a JSON object")
    return parsed


def zai_env(model: str, path: Optional[Path] = None) -> Dict[str, str]:
    """The full env a GLM run needs, with the alias slots pointed at ``model``.

    This is the Z.ai file's ``env`` block, validated, with every
    ``ANTHROPIC_DEFAULT_*_MODEL`` slot overridden to the selected model so an
    agent that resolves an alias — including the haiku one the CLI uses for
    background turns — lands on the model the run is labelled with.
    """
    model = model.strip().lower()
    if not is_zai_model(model):
        raise ZaiConfigError(f"{model!r} is not a Z.ai model (known: {', '.join(ZAI_MODELS)})")

    settings = load_zai_settings(path)
    env_block = settings.get("env")
    if not isinstance(env_block, dict):
        raise ZaiConfigError(
            f"Z.ai settings file {path or zai_settings_path()} has no 'env' object"
        )

    env = {str(k): str(v) for k, v in env_block.items() if v is not None}

    missing = [key for key in REQUIRED_KEYS if not env.get(key, "").strip()]
    if missing:
        raise ZaiConfigError(
            f"Z.ai settings file is missing {', '.join(missing)} — cannot route "
            f"{model} anywhere."
        )
    if not any(_is_real_value(env.get(key)) for key in CREDENTIAL_KEYS):
        raise ZaiConfigError(
            "Z.ai settings file has no usable API key: set ANTHROPIC_AUTH_TOKEN "
            f"in {path or zai_settings_path()} (it still holds a placeholder)."
        )

    for slot in ALIAS_SLOTS_FOR_SELECTED_MODEL:
        env[slot] = model
    return env


def _is_real_value(value: Optional[str]) -> bool:
    return bool(value) and value.strip().lower() not in PLACEHOLDER_VALUES


def _is_secret_key(key: str) -> bool:
    upper = key.upper()
    return any(marker in upper for marker in _SECRET_KEY_MARKERS)


def zai_settings_env(model: str, path: Optional[Path] = None) -> Dict[str, str]:
    """The subset of :func:`zai_env` safe to write into a persisted settings file.

    Credentials are omitted entirely rather than redacted: the CLI applies this
    file's ``env`` over the process environment, so a placeholder here would
    clobber the real token supplied by :func:`zai_process_env`.
    """
    return {k: v for k, v in zai_env(model, path).items() if not _is_secret_key(k)}


def zai_process_env(model: str, path: Optional[Path] = None, base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """``os.environ`` plus the Z.ai config, for the ``claude`` subprocess.

    Any ``ANTHROPIC_*`` endpoint/credential var already present on the launching
    machine is dropped first, so a host that exports ``ANTHROPIC_API_KEY`` for
    normal Claude use cannot half-authenticate a GLM run.
    """
    env = dict(os.environ if base is None else base)
    for key in list(env):
        if key.startswith("ANTHROPIC_") or key == "API_TIMEOUT_MS":
            del env[key]
    env.update(zai_env(model, path))
    return env


def describe_zai_config(model: str, path: Optional[Path] = None) -> JsonDict:
    """Non-secret summary of the routing in effect, for run state/logs."""
    env = zai_settings_env(model, path)
    return {
        "provider": "zai",
        "model": model.strip().lower(),
        "base_url": env.get("ANTHROPIC_BASE_URL", ""),
        "settings_file": str(path or zai_settings_path()),
    }
