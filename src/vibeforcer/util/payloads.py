from __future__ import annotations

import fnmatch
import re
from functools import cached_property
from pathlib import Path
from typing import Any, Iterable

from vibeforcer.constants import EDIT_TOOL_NAMES, LANGUAGE_BY_SUFFIX
from vibeforcer.models import ContentTarget, RuntimeConfig


def normalize_path(value: str) -> str:
    return value.replace("\\", "/").strip()


def lower_path(value: str) -> str:
    return normalize_path(value).lower()


def first_present(mapping: dict[str, Any], keys: Iterable[str], *, strip: bool = True) -> str:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip() if strip else value
    return ""


def extract_path_from_mapping(mapping: dict[str, Any]) -> str:
    return first_present(
        mapping,
        (
            "resolved_file_path",
            "original_file_path",
            "file_path",
            "filePath",
            "path",
            "relative_path",
            "relativePath",
            "target_file",
            "target_filepath",
            "targetPath",
            "notebook_path",
            "notebookPath",
            "filePath",
        ),
    )


def extract_content_from_mapping(mapping: dict[str, Any]) -> str:
    return first_present(
        mapping,
        (
            "new_string",
            "newString",
            "newText",
            "new_text",
            "code_edit",
            "codeEdit",
            "body",
            "new_body",
            "newBody",
            "text",
            "content",
        ),
        strip=False,
    )


def parse_patch_candidate_paths(patch_blob: str) -> list[str]:
    paths: list[str] = []
    for line in patch_blob.splitlines():
        value = ""
        if line.startswith("*** Update File: "):
            value = line.replace("*** Update File: ", "", 1)
        elif line.startswith("*** Add File: "):
            value = line.replace("*** Add File: ", "", 1)
        elif line.startswith("+++ b/"):
            value = line.replace("+++ b/", "", 1)
        elif line.startswith("--- a/"):
            value = line.replace("--- a/", "", 1)
        value = value.strip()
        if value and value != "/dev/null" and value not in paths:
            paths.append(value)
    return paths


def extract_added_patch_content(patch_blob: str) -> str:
    added: list[str] = []
    for line in patch_blob.splitlines():
        if line.startswith("+++") or line.startswith("***"):
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
    return "\n".join(added)


def is_edit_like_tool(tool_name: str) -> bool:
    lowered = tool_name.lower()
    if lowered in EDIT_TOOL_NAMES:
        return True
    if "edit_file" in lowered or "editfile" in lowered:
        return True
    if "serena" in lowered:
        return True
    if "morph" in lowered and ("edit" in lowered or "apply" in lowered):
        return True
    if lowered.endswith("_edit"):
        return True
    return False


def is_bash_tool(tool_name: str) -> bool:
    return tool_name.lower() == "bash"


def detect_language(path_value: str) -> str | None:
    suffix = Path(path_value).suffix.lower()
    return LANGUAGE_BY_SUFFIX.get(suffix)


def path_matches_glob(path_value: str, pattern: str) -> bool:
    normalized_path = lower_path(path_value)
    normalized_pattern = lower_path(pattern)
    basename = Path(normalized_path).name
    if normalized_pattern.endswith("/") and "*" not in normalized_pattern:
        return normalized_path.startswith(normalized_pattern)
    if "/" not in normalized_pattern:
        return fnmatch.fnmatch(basename, normalized_pattern)
    return fnmatch.fnmatch(normalized_path, normalized_pattern)


def any_path_matches(path_value: str, patterns: list[str]) -> bool:
    if not patterns:
        return True
    return any(path_matches_glob(path_value, pattern) for pattern in patterns)


def shell_command_paths(command: str) -> list[str]:
    pattern = re.compile(r'([~./A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+\.[A-Za-z0-9]+')
    seen: list[str] = []
    for match in pattern.finditer(command):
        value = match.group(0)
        if value and value not in seen:
            seen.append(value)
    return seen


class HookPayload:
    def __init__(self, payload: dict[str, Any], config: RuntimeConfig) -> None:
        self.payload = payload
        self.config = config

    @cached_property
    def event_name(self) -> str:
        return str(self.payload.get("hook_event_name", "")).strip()

    @cached_property
    def tool_name(self) -> str:
        value = self.payload.get("tool_name")
        if isinstance(value, str) and value.strip():
            return value.strip()
        fallback = self.payload.get("tool")
        if isinstance(fallback, str):
            return fallback.strip()
        return ""

    @cached_property
    def tool_input(self) -> dict[str, Any]:
        value = self.payload.get("tool_input")
        return value if isinstance(value, dict) else {}

    @cached_property
    def cwd(self) -> Path:
        value = self.payload.get("cwd")
        if isinstance(value, str) and value.strip():
            return Path(value).resolve()
        return self.config.root

    @cached_property
    def session_id(self) -> str:
        value = self.payload.get("session_id")
        return str(value).strip() if value is not None else ""

    @cached_property
    def user_prompt(self) -> str:
        value = self.payload.get("prompt")
        return str(value) if isinstance(value, str) else ""

    @cached_property
    def bash_command(self) -> str:
        if not is_bash_tool(self.tool_name):
            return ""
        value = self.tool_input.get("command")
        return str(value) if isinstance(value, str) else ""

    @cached_property
    def content_targets(self) -> list[ContentTarget]:
        targets: list[ContentTarget] = []

        merged = dict(self.tool_input)
        merged.setdefault("resolved_file_path", self.payload.get("resolved_file_path"))
        merged.setdefault("original_file_path", self.payload.get("original_file_path"))
        path_value = extract_path_from_mapping(merged)
        content_value = extract_content_from_mapping(merged)
        if path_value and content_value:
            targets.append(ContentTarget(path=path_value, content=content_value, source="tool_input"))

        raw_edits = self.tool_input.get("edits")
        if isinstance(raw_edits, list):
            for item in raw_edits:
                if not isinstance(item, dict):
                    continue
                path_item = extract_path_from_mapping(item)
                content_item = extract_content_from_mapping(item)
                if path_item and content_item:
                    targets.append(ContentTarget(path=path_item, content=content_item, source="multi_edit"))

        patch_blob = first_present(self.tool_input, ("patch", "patchText", "patch_text"))
        if patch_blob:
            patch_paths = parse_patch_candidate_paths(patch_blob)
            patch_content = extract_added_patch_content(patch_blob) or patch_blob
            for path_item in patch_paths or ["patch.diff"]:
                targets.append(ContentTarget(path=path_item, content=patch_content, source="patch"))

        unique: list[ContentTarget] = []
        seen: set[tuple[str, str, str]] = set()
        for target in targets:
            key = (target.path, target.content, target.source)
            if key in seen:
                continue
            seen.add(key)
            unique.append(target)
        return unique

    @cached_property
    def candidate_paths(self) -> list[str]:
        values: list[str] = []
        for source in (self.payload, self.tool_input):
            if isinstance(source, dict):
                path_value = extract_path_from_mapping(source)
                if path_value:
                    values.append(path_value)
        raw_edits = self.tool_input.get("edits")
        if isinstance(raw_edits, list):
            for item in raw_edits:
                if isinstance(item, dict):
                    path_item = extract_path_from_mapping(item)
                    if path_item:
                        values.append(path_item)
        patch_blob = first_present(self.tool_input, ("patch", "patchText", "patch_text"))
        if patch_blob:
            values.extend(parse_patch_candidate_paths(patch_blob))
        tool_response = self.payload.get("tool_response")
        if isinstance(tool_response, dict):
            path_value = extract_path_from_mapping(tool_response)
            if path_value:
                values.append(path_value)
        if self.bash_command:
            values.extend(shell_command_paths(self.bash_command))
        result: list[str] = []
        for item in values:
            if item and item not in result:
                result.append(item)
        return result

    @cached_property
    def languages(self) -> set[str]:
        languages: set[str] = set()
        for path_value in self.candidate_paths:
            language = detect_language(path_value)
            if language:
                languages.add(language)
        return languages
