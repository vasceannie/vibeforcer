from __future__ import annotations

import unittest
from pathlib import Path

from vibeforcer._types import ObjectDict, object_dict, string_value
from vibeforcer.engine import evaluate_payload
from vibeforcer.models import EngineResult

BUNDLE_ROOT = Path(__file__).resolve().parents[1]


def _assert_denied_by(
    result: EngineResult,
    rule_id: str,
) -> None:
    assert result.output is not None, "expected output, got None"
    spec = object_dict(result.output.get("hookSpecificOutput"))
    decision = string_value(spec.get("permissionDecision"))
    if decision is None:
        inner = object_dict(spec.get("decision"))
        decision = string_value(inner.get("behavior"))
        reason = string_value(inner.get("message")) or ""
    else:
        reason = string_value(spec.get("permissionDecisionReason")) or ""
    assert decision == "deny", f"expected deny, got {decision!r}"
    assert rule_id in reason, f"expected {rule_id!r} in reason: {reason!r}"


def _assert_not_denied(result: EngineResult) -> None:
    if result.output is None:
        return
    spec = object_dict(result.output.get("hookSpecificOutput"))
    decision = string_value(spec.get("permissionDecision"))
    assert decision != "deny", f"expected no deny, got {decision!r}"


class TestLongLines(unittest.TestCase):
    def test_long_line_blocked(self) -> None:
        long_line = "x" * 130 + chr(10)
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": long_line},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_denied_by(result, "PY-CODE-010")

    def test_long_line_blocked_for_top_level_path_edit_shape(self) -> None:
        long_line = "x" * 400 + chr(10)
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {
                "path": "src/main.py",
                "edits": [{"oldText": "x = 1\n", "newText": long_line}],
            },
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_denied_by(result, "PY-CODE-010")

    def test_120_ok(self) -> None:
        line = "x" * 120 + chr(10)
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": line},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_not_denied(result)

    def test_url_exempt(self) -> None:
        line = 'x = "https://example.com/very/long/path/that/exceeds/limit"' + chr(10)
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": line},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_not_denied(result)


class TestDeepNesting(unittest.TestCase):
    def test_deep_blocked(self) -> None:
        code = (
            "def f():\n"
            "    if a:\n"
            "        if b:\n"
            "            if c:\n"
            "                if d:\n"
            "                    if e:\n"
            "                        return 1\n"
            "    return 0"
        )
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_denied_by(result, "PY-CODE-011")

    def test_depth_4_ok(self) -> None:
        code = (
            "def f():\n"
            "    if a:\n"
            "        if b:\n"
            "            if c:\n"
            "                if d:\n"
            "                    return 1\n"
            "    return 0"
        )
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_not_denied(result)


class TestFeatureEnvy(unittest.TestCase):
    def test_param_exempt(self) -> None:
        """Accessing attributes of a function parameter is not feature envy."""
        code = (
            "def f(order):\n"
            "    a = order.total\n"
            "    b = order.items\n"
            "    c = order.status\n"
            "    d = order.customer\n"
            "    e = order.address\n"
            "    f = order.created\n"
            "    return a"
        )
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_not_denied(result)

    def test_envy_nonparam_context(self) -> None:
        """Accessing a non-param object heavily should produce context, not deny."""
        code = (
            "def f():\n"
            "    import db\n"
            "    a = db.total\n"
            "    b = db.items\n"
            "    c = db.status\n"
            "    d = db.customer\n"
            "    e = db.address\n"
            "    f = db.created\n"
            "    return a"
        )
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        # Should NOT be denied (decision is now context, not deny)
        _assert_not_denied(result)

    def test_self_exempt(self) -> None:
        code = (
            "def f(self):\n    a = self.x\n    b = self.y\n    c = self.z\n    return a"
        )
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_not_denied(result)


class TestThinWrapper(unittest.TestCase):
    def test_thin_blocked(self) -> None:
        code = "def get_value(obj):\n    return get_value(obj)"
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_denied_by(result, "PY-CODE-013")

    def test_dunder_exempt(self) -> None:
        code = "def __str__(self):\n    return str(self.value)"
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_not_denied(result)

    def test_decorated_exempt(self) -> None:
        code = "@cached\ndef get_value(obj):\n    return get_value(obj)"
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_not_denied(result)


class TestGodClass(unittest.TestCase):
    def test_god_blocked(self) -> None:
        methods = chr(10).join([f"    def m{i}(self): pass" for i in range(1, 12)])
        code = f"class C:\n{methods}"
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_denied_by(result, "PY-CODE-014")

    def test_10_methods_ok(self) -> None:
        methods = chr(10).join([f"    def m{i}(self): pass" for i in range(1, 11)])
        code = f"class C:\n{methods}"
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_not_denied(result)


class TestCyclomaticComplexity(unittest.TestCase):
    def test_complex_blocked(self) -> None:
        conds = chr(10).join([f"    if a{i}: return {i}" for i in range(1, 13)])
        code = f"def f():\n{conds}\n    return 0"
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_denied_by(result, "PY-CODE-015")

    def test_complexity_10_ok(self) -> None:
        conds = chr(10).join([f"    if a{i}: return {i}" for i in range(1, 10)])
        code = f"def f():\n{conds}\n    return 0"
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_not_denied(result)


class TestDeadCode(unittest.TestCase):
    def test_dead_blocked(self) -> None:
        code = 'def f(x):\n    if x:\n        return 1\n        print("dead")\n    return 0'
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_denied_by(result, "PY-CODE-016")

    def test_return_at_end_ok(self) -> None:
        code = "def f(x):\n    if x:\n        return 1\n    return 0"
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }
        result = evaluate_payload(payload)
        _assert_not_denied(result)


class TestImportFanout(unittest.TestCase):
    def _make_payload(self, code: str) -> ObjectDict:
        return {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }

    def test_at_threshold_ok(self) -> None:
        """Exactly 5 imports from one module -- at threshold, not flagged."""
        code = "from mymodule import a, b, c, d, e"
        result = evaluate_payload(self._make_payload(code))
        _assert_not_denied(result)
        rule_ids = {f.rule_id for f in result.findings}
        assert "PY-IMPORT-001" not in rule_ids, "at-threshold import must not be flagged"

    def test_over_threshold_context_only(self) -> None:
        """6 imports from one module -- fires context finding, does NOT deny."""
        code = "from mymodule import a, b, c, d, e, f"
        result = evaluate_payload(self._make_payload(code))
        _assert_not_denied(result)
        rule_ids = {f.rule_id for f in result.findings}
        assert "PY-IMPORT-001" in rule_ids, "over-threshold import must fire PY-IMPORT-001"

    def test_family_prefix_detected(self) -> None:
        """Shared parse_ prefix family elevates severity to MEDIUM."""
        from vibeforcer.models import Severity

        code = (
            "from myparser import "
            "parse_user, parse_order, parse_product, "
            "parse_invoice, parse_shipment, parse_address"
        )
        result = evaluate_payload(self._make_payload(code))
        _assert_not_denied(result)
        fanout_findings = [f for f in result.findings if f.rule_id == "PY-IMPORT-001"]
        assert len(fanout_findings) > 0, "family prefix must produce PY-IMPORT-001 finding"
        assert fanout_findings[0].severity == Severity.MEDIUM, (
            "family prefix must elevate severity to MEDIUM"
        )

    def test_bare_import_not_flagged(self) -> None:
        """import module (not from-import) is never flagged."""
        code = "import os\nimport sys\nimport json\nimport re\nimport ast\nimport abc"
        result = evaluate_payload(self._make_payload(code))
        rule_ids = {f.rule_id for f in result.findings}
        assert "PY-IMPORT-001" not in rule_ids, "bare import must not trigger PY-IMPORT-001"

    def test_multiple_modules_each_under_threshold_ok(self) -> None:
        """Many imports spread across multiple modules -- each under threshold."""
        code = "\n".join(
            [
                "from mod_a import x, y, z",
                "from mod_b import p, q, r",
                "from mod_c import i, j, k",
            ]
        )
        result = evaluate_payload(self._make_payload(code))
        rule_ids = {f.rule_id for f in result.findings}
        assert "PY-IMPORT-001" not in rule_ids, (
            "imports spread across modules must not trigger PY-IMPORT-001"
        )


if __name__ == "__main__":
    _ = unittest.main()
