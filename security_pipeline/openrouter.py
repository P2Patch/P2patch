"""OpenRouter provider wiring for Claude Code-based pipeline agents.

OpenRouter exposes an Anthropic Messages-compatible endpoint, so the existing
``claude`` runner can use an OpenRouter model without a proxy or a second agent
implementation.  The integration is deliberately per run: provider variables
are injected into the pipeline-owned settings file and subprocess environment,
and the operator's normal Claude Code configuration is never rewritten.

The credential may come from ``OPENROUTER_API_KEY`` or from
``~/.claude/settings-openrouter.json`` (override with
``P2PATCH_OPENROUTER_SETTINGS``).  It is only passed in the subprocess
environment.  The settings file persisted under ``agent_io/`` contains the
endpoint and model aliases but no key.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

from .env import get_env
from .logging_io import write_json
from .models import JsonDict


class OpenRouterConfigError(RuntimeError):
    """Raised when an OpenRouter model is selected without a usable key."""


# Keep this explicit: selecting an arbitrary provider/model slug should not
# silently repoint a run just because it happens to contain a slash.
#
# ``:floor`` is normally OpenRouter's price-sorted routing variant.  For GLM 5.2
# we retain that launcher id for compatibility but resolve it to a preset that
# permits only StreamLake's FP8 endpoint.  Claude Code owns the Anthropic-shaped
# request body and cannot add OpenRouter's top-level ``provider`` object itself;
# a preset is OpenRouter's supported way to apply that routing policy server-side.
# See ``openrouter_request_model`` and the one-time preset setup in README.md.
OPENROUTER_MODELS = (
    "deepseek/deepseek-v4-flash",
    "openai/gpt-5.6-luna",
    "z-ai/glm-5.2",
    "z-ai/glm-5.2:floor",
    "z-ai/glm-5.3",
    "z-ai/glm-5.3:floor",
)
GLM52_STREAMLAKE_MODEL = "z-ai/glm-5.2:floor"
GLM52_STREAMLAKE_PRESET = "autosec-glm52-streamlake"
GLM52_STREAMLAKE_ENDPOINT = "streamlake/fp8"
GLM52_STREAMLAKE_REQUEST_MODEL = (
    f"z-ai/glm-5.2@preset/{GLM52_STREAMLAKE_PRESET}"
)
OPENROUTER_BASE_URL = "https://openrouter.ai/api"
OPENROUTER_GENERATION_URL = "https://openrouter.ai/api/v1/generation"
OPENROUTER_COST_FILENAME = "provider_cost.json"

OPENROUTER_SETTINGS_PATH_ENV = "P2PATCH_OPENROUTER_SETTINGS"
DEFAULT_OPENROUTER_SETTINGS_PATH = Path("~/.claude/settings-openrouter.json")

# Pin every Claude Code model class at the requested OpenRouter model.  The
# runner already disallows sub-agent tools, but the explicit sub-agent slot also
# prevents future CLI behavior from creating an unlabelled mixed-model run.
ALIAS_SLOTS_FOR_SELECTED_MODEL = (
    "ANTHROPIC_DEFAULT_FABLE_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    "CLAUDE_CODE_SUBAGENT_MODEL",
)

CREDENTIAL_KEYS = ("OPENROUTER_API_KEY", "ANTHROPIC_AUTH_TOKEN")
PLACEHOLDER_VALUES = frozenset(
    {
        "",
        "your_openrouter_api_key",
        "your-openrouter-api-key",
        "sk-or-your-key",
        "sk-your-key",
        "changeme",
        "todo",
    }
)
_SECRET_KEY_MARKERS = ("TOKEN", "KEY", "SECRET", "PASSWORD", "CREDENTIAL")
_GENERATION_ID_RE = re.compile(r"^gen-[A-Za-z0-9_-]{8,}$")
_GENERATION_ID_FIELDS = frozenset({"id", "request_id", "generation_id"})


def is_openrouter_model(model: Optional[str]) -> bool:
    """True when ``model`` selects a model routed through OpenRouter."""
    return bool(model) and model.strip().lower() in OPENROUTER_MODELS


def openrouter_request_model(model: str) -> str:
    """Return the model id Claude Code must send to OpenRouter.

    The public launcher id remains stable in run metadata and saved dashboard
    configurations.  Only the request-facing alias changes for the GLM 5.2
    cheapest arm, where the preset supplies the provider policy Claude Code
    cannot express in its Anthropic request body.
    """
    normalized = model.strip().lower()
    if normalized == GLM52_STREAMLAKE_MODEL:
        return GLM52_STREAMLAKE_REQUEST_MODEL
    return normalized


def openrouter_provider_endpoint(model: str) -> Optional[str]:
    """Return the exact endpoint forced by P2Patch, if this arm pins one."""
    if model.strip().lower() == GLM52_STREAMLAKE_MODEL:
        return GLM52_STREAMLAKE_ENDPOINT
    return None


def openrouter_settings_path() -> Path:
    override = get_env(OPENROUTER_SETTINGS_PATH_ENV)
    raw = Path(override) if override else DEFAULT_OPENROUTER_SETTINGS_PATH
    return raw.expanduser()


def load_openrouter_settings(path: Path) -> JsonDict:
    """Read one explicit OpenRouter settings file."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise OpenRouterConfigError(f"OpenRouter settings file not found: {path}") from None
    except OSError as exc:
        raise OpenRouterConfigError(
            f"cannot read OpenRouter settings file {path}: {exc}"
        ) from None

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OpenRouterConfigError(
            f"OpenRouter settings file {path} is not valid JSON: {exc}"
        ) from None
    if not isinstance(parsed, dict):
        raise OpenRouterConfigError(
            f"OpenRouter settings file {path} must contain a JSON object"
        )
    return parsed


def _is_real_value(value: Optional[str]) -> bool:
    return bool(value) and value.strip().lower() not in PLACEHOLDER_VALUES


def _is_secret_key(key: str) -> bool:
    upper = key.upper()
    return any(marker in upper for marker in _SECRET_KEY_MARKERS)


def _source_env(path: Optional[Path] = None) -> Tuple[Dict[str, str], str]:
    """Load provider values and return them with a non-secret source label."""
    explicit = path
    if explicit is None:
        override = get_env(OPENROUTER_SETTINGS_PATH_ENV)
        if override:
            explicit = Path(override).expanduser()

    if explicit is None:
        key = os.environ.get("OPENROUTER_API_KEY")
        if _is_real_value(key):
            return {"OPENROUTER_API_KEY": str(key)}, "OPENROUTER_API_KEY"

        default_path = DEFAULT_OPENROUTER_SETTINGS_PATH.expanduser()
        if default_path.exists():
            explicit = default_path

    if explicit is None:
        raise OpenRouterConfigError(
            "OpenRouter API key not found: export OPENROUTER_API_KEY or create "
            f"{DEFAULT_OPENROUTER_SETTINGS_PATH} with an env object containing "
            "OPENROUTER_API_KEY."
        )

    settings = load_openrouter_settings(explicit)
    env_block = settings.get("env")
    if not isinstance(env_block, dict):
        raise OpenRouterConfigError(
            f"OpenRouter settings file {explicit} has no 'env' object"
        )
    env = {str(k): str(v) for k, v in env_block.items() if v is not None}
    return env, str(explicit)


def openrouter_env(model: str, path: Optional[Path] = None) -> Dict[str, str]:
    """Build the full Claude Code environment for an OpenRouter model."""
    model = model.strip().lower()
    if not is_openrouter_model(model):
        raise OpenRouterConfigError(
            f"{model!r} is not an OpenRouter model "
            f"(known: {', '.join(OPENROUTER_MODELS)})"
        )

    configured, source = _source_env(path)
    key = next(
        (configured.get(name) for name in CREDENTIAL_KEYS if _is_real_value(configured.get(name))),
        None,
    )
    if not key:
        raise OpenRouterConfigError(
            "OpenRouter configuration has no usable API key: set "
            f"OPENROUTER_API_KEY in {source} (it is missing or still a placeholder)."
        )

    env = dict(configured)
    # Force the official Anthropic-compatible endpoint and bearer-auth path.
    # ANTHROPIC_API_KEY must be explicitly empty or Claude Code may try direct
    # Anthropic authentication instead of the gateway token.
    env.pop("OPENROUTER_API_KEY", None)
    env["ANTHROPIC_BASE_URL"] = OPENROUTER_BASE_URL
    env["ANTHROPIC_AUTH_TOKEN"] = key
    env["ANTHROPIC_API_KEY"] = ""
    request_model = openrouter_request_model(model)
    for slot in ALIAS_SLOTS_FOR_SELECTED_MODEL:
        env[slot] = request_model
    return env


def openrouter_settings_env(model: str, path: Optional[Path] = None) -> Dict[str, str]:
    """Non-secret provider env safe to persist in ``agent_io/settings.json``."""
    return {
        key: value
        for key, value in openrouter_env(model, path).items()
        if not _is_secret_key(key)
    }


def openrouter_process_env(
    model: str,
    path: Optional[Path] = None,
    base: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """``os.environ`` plus isolated OpenRouter routing for ``claude``."""
    env = dict(os.environ if base is None else base)
    for key in list(env):
        if key.startswith("ANTHROPIC_") or key in {"OPENROUTER_API_KEY", "API_TIMEOUT_MS"}:
            del env[key]
    env.update(openrouter_env(model, path))
    return env


def describe_openrouter_config(model: str, path: Optional[Path] = None) -> JsonDict:
    """Return the non-secret routing summary shown before a run starts."""
    _, source = _source_env(path)
    # Validate the source as well as describing it.
    openrouter_env(model, path)
    return {
        "provider": "openrouter",
        "model": model.strip().lower(),
        "request_model": openrouter_request_model(model),
        "provider_endpoint": openrouter_provider_endpoint(model),
        "base_url": OPENROUTER_BASE_URL,
        "credential_source": source,
    }


def openrouter_generation_ids(stream_path: Path) -> Tuple[str, ...]:
    """Ordered unique OpenRouter generation IDs in a Claude stream artifact.

    Claude Code preserves OpenRouter's ``gen-*`` ID in structured message and
    request fields, even though it drops OpenRouter's billed ``usage.cost`` when
    it normalizes the terminal result.  Inspect only ID-shaped JSON fields: a
    model mentioning a fake ``gen-*`` string in prose must not create an API
    lookup or inflate the run's cost.
    """
    try:
        lines = stream_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ()

    found: Dict[str, None] = {}

    def visit(value) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if (
                    key in _GENERATION_ID_FIELDS
                    and isinstance(item, str)
                    and _GENERATION_ID_RE.fullmatch(item)
                ):
                    found.setdefault(item, None)
                if isinstance(item, (dict, list)):
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, (dict, list)):
                    visit(item)

    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        visit(event)
    return tuple(found)


def _generation_ids_hash(generation_ids: Tuple[str, ...]) -> str:
    return hashlib.sha256("\n".join(generation_ids).encode("utf-8")).hexdigest()


def _numeric_cost(value) -> float:
    if isinstance(value, bool):
        raise ValueError("generation total_cost is not numeric")
    try:
        cost = float(value)
    except (TypeError, ValueError):
        raise ValueError("generation total_cost is not numeric") from None
    if not math.isfinite(cost) or cost < 0:
        raise ValueError("generation total_cost is negative or non-finite")
    return cost


def openrouter_generation_cost(
    generation_id: str,
    auth_token: str,
    *,
    attempts: int = 6,
    timeout: float = 15.0,
) -> float:
    """Fetch the amount OpenRouter actually charged for one generation.

    Generation accounting can lag the terminal stream very briefly, so 404 is
    retried alongside rate-limit and server errors.  The bearer token exists
    only in the request header; neither it nor the full response is persisted.
    """
    if not _GENERATION_ID_RE.fullmatch(generation_id):
        raise ValueError("invalid OpenRouter generation ID")
    if not _is_real_value(auth_token):
        raise OpenRouterConfigError(
            "OpenRouter API key is missing for cost reconciliation"
        )

    url = OPENROUTER_GENERATION_URL + "?" + urllib.parse.urlencode(
        {"id": generation_id}
    )
    retryable_statuses = {404, 408, 409, 425, 429, 500, 502, 503, 504, 524, 529}
    last_error: Optional[Exception] = None
    for attempt in range(max(1, attempts)):
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {auth_token}",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.load(response)
            data = payload.get("data") if isinstance(payload, dict) else None
            if not isinstance(data, dict):
                raise ValueError("OpenRouter generation response has no data object")
            return _numeric_cost(data.get("total_cost"))
        except urllib.error.HTTPError as exc:
            last_error = RuntimeError(
                f"OpenRouter generation lookup returned HTTP {exc.code}"
            )
            if exc.code not in retryable_statuses or attempt + 1 >= max(1, attempts):
                break
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            last_error = exc
            if attempt + 1 >= max(1, attempts):
                break
        # OpenRouter can return 404 for a freshly completed generation while
        # its accounting record is still being indexed.  The previous three
        # attempts covered less than one second in total, which was too short
        # for the final generation of every agent in a real run.  Exponential
        # backoff covers about 15 seconds without hammering the endpoint.
        time.sleep(min(0.5 * (2**attempt), 8.0))
    raise RuntimeError(str(last_error or "OpenRouter generation lookup failed"))


def reconcile_openrouter_cost(
    stream_path: Path,
    output_path: Path,
    model: str,
    *,
    auth_token: Optional[str] = None,
    fetch_cost: Optional[Callable[[str], float]] = None,
    max_workers: int = 8,
) -> JsonDict:
    """Resolve and cache exact billed cost for one OpenRouter agent stream.

    The cache is used only when every unique generation was resolved. Partial
    sums are retained for diagnosis but are never presented as the run total.
    Supplying ``fetch_cost`` is primarily useful for deterministic unit tests.
    """
    model = model.strip().lower()
    if not is_openrouter_model(model):
        raise OpenRouterConfigError(f"{model!r} is not a configured OpenRouter model")

    generation_ids = openrouter_generation_ids(stream_path)
    ids_hash = _generation_ids_hash(generation_ids)
    try:
        cached = json.loads(output_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        cached = None
    if (
        isinstance(cached, dict)
        and cached.get("complete") is True
        and cached.get("model") == model
        and cached.get("generation_ids_hash") == ids_hash
        and cached.get("generation_count") == len(generation_ids)
    ):
        return cached

    if fetch_cost is None:
        token = auth_token or openrouter_env(model).get("ANTHROPIC_AUTH_TOKEN")
        fetch_cost = lambda generation_id: openrouter_generation_cost(
            generation_id, str(token or "")
        )

    costs: Dict[str, float] = {}
    errors: Dict[str, str] = {}
    if generation_ids:
        workers = max(1, min(max_workers, len(generation_ids)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            pending = {
                pool.submit(fetch_cost, generation_id): generation_id
                for generation_id in generation_ids
            }
            for future in as_completed(pending):
                generation_id = pending[future]
                try:
                    costs[generation_id] = _numeric_cost(future.result())
                except Exception as exc:  # accounting must never fail the agent run
                    errors[generation_id] = str(exc)[:240]

    complete = bool(generation_ids) and len(costs) == len(generation_ids)
    result: JsonDict = {
        "schema_version": 1,
        "provider": "openrouter",
        "model": model,
        "source": "openrouter_generation_api",
        "complete": complete,
        "generation_count": len(generation_ids),
        "resolved_count": len(costs),
        "generation_ids_hash": ids_hash,
        "cost_usd": round(math.fsum(costs.values()), 12) if costs else None,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    if errors:
        # IDs are already present in stream.jsonl; keeping a bounded subset here
        # makes a partial reconciliation debuggable without bloating artifacts.
        result["errors"] = [
            {"generation_id": generation_id, "error": errors[generation_id]}
            for generation_id in list(generation_ids)
            if generation_id in errors
        ][:20]
    elif not generation_ids:
        result["errors"] = [{"error": "no OpenRouter generation IDs found in stream"}]
    write_json(output_path, result)
    return result


def reconcile_openrouter_agent_dir(
    agent_dir: Path,
    model: str,
    *,
    auth_token: Optional[str] = None,
    fetch_cost: Optional[Callable[[str], float]] = None,
) -> JsonDict:
    """Reconcile one ``agent_io/<name>`` directory."""
    return reconcile_openrouter_cost(
        agent_dir / "stream.jsonl",
        agent_dir / OPENROUTER_COST_FILENAME,
        model,
        auth_token=auth_token,
        fetch_cost=fetch_cost,
    )


def reconcile_openrouter_run_costs(
    run_dir: Path,
    model: str,
    *,
    auth_token: Optional[str] = None,
    fetch_cost: Optional[Callable[[str], float]] = None,
) -> Dict[str, JsonDict]:
    """Backfill billed-cost caches for every streamed agent in a run."""
    agent_root = run_dir / "agent_io"
    if not agent_root.is_dir():
        return {}
    results: Dict[str, JsonDict] = {}
    for agent_dir in sorted(agent_root.iterdir()):
        if agent_dir.is_dir() and (agent_dir / "stream.jsonl").is_file():
            results[agent_dir.name] = reconcile_openrouter_agent_dir(
                agent_dir,
                model,
                auth_token=auth_token,
                fetch_cost=fetch_cost,
            )
    return results
