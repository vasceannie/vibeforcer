from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from vibeforcer.engine import evaluate_payload

BUNDLE_ROOT = Path(__file__).resolve().parents[1]


def _assert_denied_by(test, result, rule_id, msg=""):
    test.assertIsNotNone(result.output)
    spec = result.output.get("hookSpecificOutput", {})
    decision = spec.get("permissionDecision")
    if decision is None:
        inner = spec.get("decision", {})
        decision = inner.get("behavior")
        reason = inner.get("message", "")
    else:
        reason = spec.get("permissionDecisionReason", "")
    test.assertEqual(decision, "deny")
    test.assertIn(rule_id, reason)


def _assert_not_denied(test, result):
    if result.output is None:
        return
    spec = result.output.get("hookSpecificOutput", {})
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


if __name__ == "__main__":
    unittest.main()
