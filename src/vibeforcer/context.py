from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from vibeforcer._types import ObjectDict, ObjectMapping
from vibeforcer.config import load_config
from vibeforcer.models import ContentTarget, RuntimeConfig
from vibeforcer.state import HookStateStore
from vibeforcer.trace import TraceWriter
from vibeforcer.util.payloads import HookPayload


@dataclass(slots=True)
class HookContext:
    payload: HookPayload
    config: RuntimeConfig
    trace: TraceWriter
    state: HookStateStore

    @property
    def event_name(self) -> str:
        return self.payload.event_name

    @property
    def tool_name(self) -> str:
        return self.payload.tool_name

    @property
    def tool_input(self) -> ObjectDict:
        return self.payload.tool_input

    @property
    def bash_command(self) -> str:
        return self.payload.bash_command

    @property
    def user_prompt(self) -> str:
        return self.payload.user_prompt

    @property
    def content_targets(self) -> list[ContentTarget]:
        return self.payload.content_targets

    @property
    def candidate_paths(self) -> list[str]:
        return self.payload.candidate_paths

    @property
    def cwd(self) -> Path:
        return self.payload.cwd

    @property
    def session_id(self) -> str:
        return self.payload.session_id

    @property
    def languages(self) -> set[str]:
        return self.payload.languages


def build_context(payload_dict: ObjectMapping) -> HookContext:
    config = load_config()
    trace = TraceWriter(config.trace_dir)
    payload = HookPayload(payload_dict, config)
    state = HookStateStore(config.trace_dir)
    return HookContext(payload=payload, config=config, trace=trace, state=state)
