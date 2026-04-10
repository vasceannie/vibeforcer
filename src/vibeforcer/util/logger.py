from __future__ import annotations

import json
import sys
from datetime import datetime, timezone


def _emit(level: str, message: str, **fields: object) -> None:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "message": message,
        **fields,
    }
    sys.stderr.write(json.dumps(payload, sort_keys=True, default=str) + "\n")


def debug(message: str, **fields: object) -> None:
    _emit("debug", message, **fields)


def info(message: str, **fields: object) -> None:
    _emit("info", message, **fields)


def warning(message: str, **fields: object) -> None:
    _emit("warning", message, **fields)


def error(message: str, **fields: object) -> None:
    _emit("error", message, **fields)
