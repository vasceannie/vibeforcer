from __future__ import annotations

from collections.abc import Mapping, Sequence

ObjectDict = dict[str, object]
ObjectMapping = Mapping[str, object]


def object_dict(value: object) -> ObjectDict:
    if not isinstance(value, Mapping):
        return {}
    result: ObjectDict = {}
    for raw_key, item in value.items():
        if isinstance(raw_key, str):
            result[raw_key] = item
    return result


def object_list(value: object) -> list[object]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def string_value(value: object) -> str | None:
    return value if isinstance(value, str) else None


def bool_value(value: object) -> bool | None:
    return value if isinstance(value, bool) else None
