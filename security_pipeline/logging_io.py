from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_text(path: Path, content: str) -> Path:
    ensure_dir(path.parent)
    # newline="" so the bytes written are the bytes given. The default (None)
    # rewrites every "\n" to os.linesep, which on Windows would turn a CRLF diff
    # into a CRCRLF one — the mirror of the universal-newline translation on the
    # read side that made zip4j's recorded diff unappliable.
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(content)
    return path


def write_json(path: Path, data: Any) -> Path:
    ensure_dir(path.parent)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def relative_to_or_absolute(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)
