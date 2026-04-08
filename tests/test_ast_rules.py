from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

from vibeforcer.engine import evaluate_payload
from vibeforcer.models import EngineResult

BUNDLE_ROOT = Path(__file__).resolve().parents[1]


def _assert_denied_by(
    test: unittest.TestCase, result: EngineResult, rule_id: str, msg: str = "",
) -> None:
    test.assertIsNotNone(result.output)
    assert result.output is not None
    spec: dict[str, Any] = result.output.get("hookSpecificOutput", {})
    decision = spec.get("permissionDecision")
    if decision is None:
        inner: dict[str, Any] = spec.get("decision", {})
        decision = inner.get("behavior")
        reason: str = str(inner.get("message", ""))
    else:
        reason = str(spec.get("permissionDecisionReason", ""))
    test.assertEqual(decision, "deny")
    test.assertIn(rule_id, reason)


def _assert_not_denied(test: unittest.TestCase, result: EngineResult) -> None:
    if result.output is None:
        return
    spec: dict[str, Any] = result.output.get("hookSpecificOutput", {})
    decision = spec.get("permissionDecision")
    test.assertNotEqual(decision, "deny")


class TestLongLines(unittest.TestCase):
    def test_long_line_blocked(self):
        long_line = "x" * 130 + chr(10)
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": long_line},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_denied_by(self, result, "PY-CODE-010")

    def test_120_ok(self):
        line = "x" * 120 + chr(10)
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": line},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_not_denied(self, result)

    def test_url_exempt(self):
        line = 'x = "https://example.com/very/long/path/that/exceeds/limit"' + chr(10)
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": line},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_not_denied(self, result)


class TestDeepNesting(unittest.TestCase):
    def test_deep_blocked(self):
        code = "def f():\n    if a:\n        if b:\n            if c:\n                if d:\n                    if e:\n                        return 1\n    return 0"
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_denied_by(self, result, "PY-CODE-011")

    def test_depth_4_ok(self):
        code = "def f():\n    if a:\n        if b:\n            if c:\n                if d:\n                    return 1\n    return 0"
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_not_denied(self, result)


class TestFeatureEnvy(unittest.TestCase):
    def test_param_exempt(self):
        """Accessing attributes of a function parameter is not feature envy."""
        code = "def f(order):\n    a = order.total\n    b = order.items\n    c = order.status\n    d = order.customer\n    e = order.address\n    f = order.created\n    return a"
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_not_denied(self, result)

    def test_envy_nonparam_context(self):
        """Accessing a non-param object heavily should produce context, not deny."""
        code = "def f():\n    import db\n    a = db.total\n    b = db.items\n    c = db.status\n    d = db.customer\n    e = db.address\n    f = db.created\n    return a"
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        # Should NOT be denied (decision is now context, not deny)
        _assert_not_denied(self, result)

    def test_self_exempt(self):
        code = "def f(self):\n    a = self.x\n    b = self.y\n    c = self.z\n    return a"
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_not_denied(self, result)


class TestThinWrapper(unittest.TestCase):
    def test_thin_blocked(self):
        code = "def get_value(obj):\n    return get_value(obj)"
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_denied_by(self, result, "PY-CODE-013")

    def test_dunder_exempt(self):
        code = "def __str__(self):\n    return str(self.value)"
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_not_denied(self, result)

    def test_decorated_exempt(self):
        code = "@cached\ndef get_value(obj):\n    return get_value(obj)"
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_not_denied(self, result)


class TestGodClass(unittest.TestCase):
    def test_god_blocked(self):
        methods = chr(10).join([f"    def m{i}(self): pass" for i in range(1, 12)])
        code = f"class C:\n{methods}"
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_denied_by(self, result, "PY-CODE-014")

    def test_10_methods_ok(self):
        methods = chr(10).join([f"    def m{i}(self): pass" for i in range(1, 11)])
        code = f"class C:\n{methods}"
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_not_denied(self, result)


class TestCyclomaticComplexity(unittest.TestCase):
    def test_complex_blocked(self):
        conds = chr(10).join([f"    if a{i}: return {i}" for i in range(1, 13)])
        code = f"def f():\n{conds}\n    return 0"
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_denied_by(self, result, "PY-CODE-015")

    def test_complexity_10_ok(self):
        conds = chr(10).join([f"    if a{i}: return {i}" for i in range(1, 10)])
        code = f"def f():\n{conds}\n    return 0"
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_not_denied(self, result)


class TestDeadCode(unittest.TestCase):
    def test_dead_blocked(self):
        code = "def f(x):\n    if x:\n        return 1\n        print(\"dead\")\n    return 0"
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_denied_by(self, result, "PY-CODE-016")

    def test_return_at_end_ok(self):
        code = "def f(x):\n    if x:\n        return 1\n    return 0"
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT)}
        result = evaluate_payload(payload)
        _assert_not_denied(self, result)


class TestImportFanout(unittest.TestCase):
    def _make_payload(self, code: str) -> dict[str, Any]:
        return {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": "src/main.py", "new_string": code},
            "cwd": str(BUNDLE_ROOT),
        }

    def test_at_threshold_ok(self):
        """Exactly 5 imports from one module -- at threshold, not flagged."""
        code = "from mymodule import a, b, c, d, e"
        result = evaluate_payload(self._make_payload(code))
        _assert_not_denied(self, result)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertNotIn("PY-IMPORT-001", rule_ids)

    def test_over_threshold_context_only(self):
        """6 imports from one module -- fires context finding, does NOT deny."""
        code = "from mymodule import a, b, c, d, e, f"
        result = evaluate_payload(self._make_payload(code))
        _assert_not_denied(self, result)
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("PY-IMPORT-001", rule_ids)

    def test_family_prefix_detected(self):
        """Shared parse_ prefix family elevates severity to MEDIUM."""
        code = (
            "from myparser import "
            "parse_user, parse_order, parse_product, "
            "parse_invoice, parse_shipment, parse_address"
        )
        result = evaluate_payload(self._make_payload(code))
        _assert_not_denied(self, result)
        fanout_findings = [f for f in result.findings if f.rule_id == "PY-IMPORT-001"]
        self.assertTrue(len(fanout_findings) > 0)
        from vibeforcer.models import Severity
        self.assertEqual(fanout_findings[0].severity, Severity.MEDIUM)

    def test_bare_import_not_flagged(self):
        """import module (not from-import) is never flagged."""
        code = "import os\nimport sys\nimport json\nimport re\nimport ast\nimport abc"
        result = evaluate_payload(self._make_payload(code))
        rule_ids = {f.rule_id for f in result.findings}
        self.assertNotIn("PY-IMPORT-001", rule_ids)

    def test_multiple_modules_each_under_threshold_ok(self):
        """Many imports spread across multiple modules -- each under threshold."""
        code = "\n".join([
            "from mod_a import x, y, z",
            "from mod_b import p, q, r",
            "from mod_c import i, j, k",
        ])
        result = evaluate_payload(self._make_payload(code))
        rule_ids = {f.rule_id for f in result.findings}
        self.assertNotIn("PY-IMPORT-001", rule_ids)


if __name__ == "__main__":
    unittest.main()
