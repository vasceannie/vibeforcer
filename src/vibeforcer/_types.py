from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TypeGuard, cast

ObjectDict = dict[str, object]
ObjectMapping = Mapping[str, object]


def is_object_dict(value: object) -> TypeGuard[ObjectDict]:
    if not isinstance(value, dict):
        return False
    raw_dict = cast(dict[object, object], value)
    return all(isinstance(key, str) for key in raw_dict)


def object_dict(value: object) -> ObjectDict:
    if not isinstance(value, Mapping):
        return {}
    raw_mapping = cast(Mapping[object, object], value)
    result: ObjectDict = {}
    for raw_key, item in raw_mapping.items():
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
