"""Tests for LangGraph rules: LG-STATE-001, LG-NODE-001, LG-API-001.

These rules are PostToolUse-only and advisory (context, not deny/block).
Test payloads simulate Write events with LangGraph-flavored Python files.
"""
from __future__ import annotations

from pathlib import Path

from vibeforcer.engine import evaluate_payload
from conftest import finding_ids


def _post_write(
    cwd: Path,
    file_path: str,
    content: str,
) -> dict[str, object]:
    """Build a PostToolUse Write payload and write the file to disk."""
    full = cwd / file_path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(content, encoding="utf-8")
    return {
        "session_id": "t",
        "cwd": str(cwd),
        "hook_event_name": "PostToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": file_path, "content": content},
        "tool_response": {"filePath": file_path, "success": True},
    }


class TestStateReducerRule:
    """LG-STATE-001: bare list fields in TypedDict state without reducers."""

    def test_bare_list_flagged(self, langgraph_project: Path) -> None:
        code = (
            "from typing import TypedDict\n"
            "from langgraph.graph import StateGraph\n\n"
            "class AgentState(TypedDict):\n"
            "    messages: list[str]\n"
            "    docs: list[str]\n"
        )
        payload = _post_write(langgraph_project, "src/state.py", code)
        result = evaluate_payload(payload)
        assert "LG-STATE-001" in finding_ids(result), "bare list fields must trigger reducer warning"

    def test_annotated_list_ok(self, langgraph_project: Path) -> None:
        code = (
            "import operator\n"
            "from typing import Annotated, TypedDict\n"
            "from langgraph.graph import StateGraph\n\n"
            "class AgentState(TypedDict):\n"
            "    messages: Annotated[list[str], operator.add]\n"
        )
        payload = _post_write(langgraph_project, "src/state.py", code)
        result = evaluate_payload(payload)
        assert "LG-STATE-001" not in finding_ids(result), "annotated list must not trigger"

    def test_non_langgraph_project_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "logs").mkdir()
        (tmp_path / "logs" / "async").mkdir()
        code = (
            "from typing import TypedDict\n\n"
            "class MyState(TypedDict):\n"
            "    items: list[str]\n"
        )
        payload = _post_write(tmp_path, "src/state.py", code)
        result = evaluate_payload(payload)
        assert "LG-STATE-001" not in finding_ids(result), "non-langgraph projects must not trigger"


class TestStateMutationRule:
    """LG-NODE-001: detect direct state mutation in node functions."""

    def test_direct_assignment_flagged(self, langgraph_project: Path) -> None:
        code = (
            "from langgraph.graph import StateGraph\n\n"
            'def my_node(state):\n'
            '    state["counter"] = 1\n'
            '    return state\n'
        )
        payload = _post_write(langgraph_project, "src/nodes.py", code)
        result = evaluate_payload(payload)
        assert "LG-NODE-001" in finding_ids(result), "state assignment must trigger mutation warning"

    def test_append_flagged(self, langgraph_project: Path) -> None:
        code = (
            "from langgraph.graph import StateGraph\n\n"
            'def my_node(state):\n'
            '    state["items"].append("x")\n'
            '    return state\n'
        )
        payload = _post_write(langgraph_project, "src/nodes.py", code)
        result = evaluate_payload(payload)
        assert "LG-NODE-001" in finding_ids(result), "state append must trigger mutation warning"

    def test_return_dict_ok(self, langgraph_project: Path) -> None:
        code = (
            "from langgraph.graph import StateGraph\n\n"
            'def my_node(state):\n'
            '    return {"counter": state["counter"] + 1}\n'
        )
        payload = _post_write(langgraph_project, "src/nodes.py", code)
        result = evaluate_payload(payload)
        assert "LG-NODE-001" not in finding_ids(result), "returning dict must not trigger"


class TestDeprecatedAPIRule:
    """LG-API-001: flag deprecated LangGraph API usage."""

    def test_set_entry_point_flagged(self, langgraph_project: Path) -> None:
        code = (
            "from langgraph.graph import StateGraph\n\n"
            "graph = StateGraph(dict)\n"
            'graph.set_entry_point("start")\n'
        )
        payload = _post_write(langgraph_project, "src/graph.py", code)
        result = evaluate_payload(payload)
        assert "LG-API-001" in finding_ids(result), "set_entry_point must trigger deprecated warning"

    def test_add_edge_ok(self, langgraph_project: Path) -> None:
        code = (
            "from langgraph.graph import StateGraph, START\n\n"
            "graph = StateGraph(dict)\n"
            'graph.add_edge(START, "start")\n'
        )
        payload = _post_write(langgraph_project, "src/graph.py", code)
        result = evaluate_payload(payload)
        assert "LG-API-001" not in finding_ids(result), "add_edge(START, ..) must not trigger"
