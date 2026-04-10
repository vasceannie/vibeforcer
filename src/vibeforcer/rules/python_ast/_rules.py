from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, final
from typing_extensions import override

from vibeforcer.models import RuleFinding, Severity
from vibeforcer.rules.base import Rule, is_rule_enabled
from vibeforcer.util.payloads import is_bash_tool, is_edit_like_tool

from ._helpers import (
    decision_for_context,
    detect_family_prefix,
    evaluate_common,
    parse_module,
)

if TYPE_CHECKING:
    from vibeforcer.context import HookContext


def _parse_strict(source: str, max_chars: int) -> ast.Module | None:
    """Parse source into a module; return None when too large or syntactically invalid."""
    if len(source) > max_chars:
        return None
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


@final
class PythonLongMethodRule(Rule):
    rule_id = "PY-CODE-008"
    title = "Block long Python methods"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    @staticmethod
    def _worst_function(module: ast.Module, limit: int) -> tuple[str, int] | None:
        """Return (name, span) of the longest over-limit function, or None."""
        worst: tuple[str, int] | None = None
        for node in ast.walk(module):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.end_lineno is None:
                continue
            span = node.end_lineno - node.lineno + 1
            if span > limit and (worst is None or span > worst[1]):
                worst = (node.name, span)
        return worst

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        """Return findings for any too-long functions in source."""
        module = _parse_strict(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []
        worst = self._worst_function(module, ctx.config.python_long_method_lines)
        if worst is None:
            return []
        name, span = worst
        limit = ctx.config.python_long_method_lines
        decision = (
            "deny" if ctx.event_name in ("PreToolUse", "PermissionRequest") else "block"
        )
        return [RuleFinding(
            rule_id=self.rule_id,
            title=self.title,
            severity=Severity.HIGH,
            decision=decision,
            message=(
                f"Python function `{name}` in `{path_value}` is {span} lines long. "
                f"Keep functions under {limit} lines or split them into helpers."
            ),
            metadata={"path": path_value, "function": name, "lines": span},
        )]

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


@final
class PythonLongParameterRule(Rule):
    rule_id = "PY-CODE-009"
    title = "Block long Python parameter lists"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    @staticmethod
    def _worst_param_count(module: ast.Module, limit: int) -> tuple[str, int] | None:
        """Return (name, count) of the function with the most over-limit params."""
        worst: tuple[str, int] | None = None
        for node in ast.walk(module):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = (
                list(node.args.posonlyargs)
                + list(node.args.args)
                + list(node.args.kwonlyargs)
            )
            names = [arg.arg for arg in args]
            if names and names[0] in {"self", "cls"}:
                names = names[1:]
            if len(names) > limit and (worst is None or len(names) > worst[1]):
                worst = (node.name, len(names))
        return worst

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        """Return findings for any too-long parameter lists in source."""
        module = _parse_strict(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []
        worst = self._worst_param_count(module, ctx.config.python_long_parameter_limit)
        if worst is None:
            return []
        name, count = worst
        limit = ctx.config.python_long_parameter_limit
        decision = (
            "deny" if ctx.event_name in ("PreToolUse", "PermissionRequest") else "block"
        )
        return [RuleFinding(
            rule_id=self.rule_id,
            title=self.title,
            severity=Severity.MEDIUM,
            decision=decision,
            message=(
                f"Python function `{name}` in `{path_value}` declares {count} parameters. "
                f"Keep functions at or below {limit} parameters or group inputs into objects."
            ),
            metadata={"path": path_value, "function": name, "parameter_count": count},
        )]

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


# ---------------------------------------------------------------------------
# New rules (PY-CODE-010 through PY-CODE-016)
# ---------------------------------------------------------------------------


@final
class PythonLongLineRule(Rule):
    """PY-CODE-010: Block files containing lines over 120 characters."""

    rule_id = "PY-CODE-010"
    title = "Block long lines"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    @staticmethod
    def _toggle_docstring(stripped: str, in_docstring: bool) -> bool:
        """Return updated docstring-tracking state after processing stripped."""
        for marker in ('"""', "'''"):
            if stripped.count(marker) % 2 == 1:
                in_docstring = not in_docstring
        return in_docstring

    def _find_worst_line(self, source: str, max_length: int) -> tuple[int, int]:
        """Scan source and return (lineno, length) of the longest offending line."""
        in_docstring = False
        worst_lineno = 0
        worst_length = 0
        for lineno, raw_line in enumerate(source.splitlines(), start=1):
            stripped = raw_line.strip()
            in_docstring = self._toggle_docstring(stripped, in_docstring)
            if in_docstring or stripped.startswith("#"):
                continue
            if "http://" in raw_line or "https://" in raw_line:
                continue
            if len(raw_line) > max_length and len(raw_line) > worst_length:
                worst_lineno = lineno
                worst_length = len(raw_line)
        return worst_lineno, worst_length

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        max_length = ctx.config.python_max_line_length
        if len(source) > ctx.config.python_ast_max_parse_chars:
            return []
        worst_lineno, worst_length = self._find_worst_line(source, max_length)
        if worst_length <= max_length:
            return []
        return [RuleFinding(
            rule_id=self.rule_id,
            title=self.title,
            severity=Severity.MEDIUM,
            decision=decision_for_context(ctx),
            message=(
                f"Line {worst_lineno} in `{path_value}` is {worst_length} characters long. "
                f"Keep lines at or below {max_length} characters."
            ),
            metadata={"path": path_value, "line": worst_lineno, "length": worst_length},
        )]

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


@final
class PythonDeepNestingRule(Rule):
    """PY-CODE-011: Block functions with nesting depth > 4."""

    rule_id = "PY-CODE-011"
    title = "Block deep nesting"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    _NESTING_TYPES = (
        ast.If,
        ast.For,
        ast.While,
        ast.AsyncFor,
        ast.With,
        ast.AsyncWith,
        ast.Try,
        ast.ExceptHandler,
    )

    def _max_nesting(self, node: ast.AST, depth: int = 0) -> int:
        """Return the maximum nesting depth below node."""
        max_d = depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, self._NESTING_TYPES):
                max_d = max(max_d, self._max_nesting(child, depth + 1))
            else:
                max_d = max(max_d, self._max_nesting(child, depth))
        return max_d

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []
        worst_name = ""
        worst_depth = 0
        for node in ast.walk(module):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                depth = self._max_nesting(node, 0)
                if depth > ctx.config.python_max_nesting_depth and depth > worst_depth:
                    worst_name = node.name
                    worst_depth = depth
        if not worst_name:
            return []
        limit = ctx.config.python_max_nesting_depth
        return [RuleFinding(
            rule_id=self.rule_id,
            title=self.title,
            severity=Severity.HIGH,
            decision=decision_for_context(ctx),
            message=(
                f"Function `{worst_name}` in `{path_value}` has nesting depth {worst_depth}. "
                f"Keep nesting at or below {limit} levels."
            ),
            metadata={"path": path_value, "function": worst_name, "depth": worst_depth},
        )]

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


@final
class PythonFeatureEnvyRule(Rule):
    """PY-CODE-012: Detect functions where >60% of attribute accesses target one external object."""

    rule_id = "PY-CODE-012"
    title = "Block feature envy"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    _IGNORE_NAMES = frozenset({
        "os", "sys", "re", "io", "abc", "ast", "csv", "json", "math", "time",
        "uuid", "enum", "copy", "gzip", "html", "http", "shutil", "signal",
        "socket", "string", "struct", "typing", "base64", "codecs", "hashlib",
        "logging", "pathlib", "secrets", "sqlite3", "urllib", "asyncio",
        "collections", "contextlib", "dataclasses", "datetime", "functools",
        "importlib", "itertools", "multiprocessing", "operator", "platform",
        "pprint", "random", "subprocess", "tempfile", "textwrap", "threading",
        "traceback", "unittest", "warnings", "np", "pd", "plt", "tf", "torch",
        "sk", "Path", "Enum", "Optional", "Union", "List", "Dict", "Set", "Tuple",
    })

    @staticmethod
    def _root_name(node: ast.Attribute) -> str | None:
        """Walk down the Attribute chain to find the root Name."""
        current: ast.AST = node.value
        while isinstance(current, ast.Attribute):
            current = current.value
        if isinstance(current, ast.Name):
            return current.id
        return None

    @staticmethod
    def _param_names(
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> frozenset[str]:
        """Collect all parameter names from a function signature."""
        names: list[str] = []
        for arg in (
            func_node.args.args + func_node.args.posonlyargs + func_node.args.kwonlyargs
        ):
            names.append(arg.arg)
        if func_node.args.vararg:
            names.append(func_node.args.vararg.arg)
        if func_node.args.kwarg:
            names.append(func_node.args.kwarg.arg)
        return frozenset(names)

    def _count_envy_accesses(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        param_ns: frozenset[str],
    ) -> tuple[dict[str, int], int]:
        """Count attribute accesses per external object in node."""
        counts: dict[str, int] = {}
        total = 0
        for child in ast.walk(node):
            if not isinstance(child, ast.Attribute):
                continue
            root = self._root_name(child)
            if root is None or root in ("self", "cls") or root in self._IGNORE_NAMES:
                continue
            if root in param_ns:
                continue
            counts[root] = counts.get(root, 0) + 1
            total += 1
        return counts, total

    def _check_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        path_value: str,
        ctx: HookContext,
    ) -> RuleFinding | None:
        """Return a finding if node exhibits feature envy, else None."""
        param_ns = self._param_names(node)
        counts, total = self._count_envy_accesses(node, param_ns)
        if total < ctx.config.python_feature_envy_min_accesses:
            return None
        for obj_name, count in counts.items():
            if count / total > ctx.config.python_feature_envy_threshold:
                return RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.LOW,
                    decision="context",
                    message=(
                        f"Function `{node.name}` in `{path_value}` has feature envy: "
                        f"{count}/{total} attribute accesses target `{obj_name}`. "
                        f"Consider moving this logic to {obj_name}'s class."
                    ),
                    metadata={
                        "path": path_value,
                        "function": node.name,
                        "envied_object": obj_name,
                        "accesses": count,
                        "total": total,
                    },
                )
        return None

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []
        findings: list[RuleFinding] = []
        for node in ast.walk(module):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            finding = self._check_function(node, path_value, ctx)
            if finding is not None:
                findings.append(finding)
        return findings

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


@final
class PythonThinWrapperRule(Rule):
    """PY-CODE-013: Detect functions whose body is a single delegating call."""

    rule_id = "PY-CODE-013"
    title = "Block thin wrappers"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    @staticmethod
    def _extract_single_call(stmt: ast.stmt) -> ast.Call | None:
        """Return the Call node if stmt is a single-statement Return/Expr call."""
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
            return stmt.value
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            return stmt.value
        return None

    @staticmethod
    def _call_target_name(call_node: ast.Call) -> str:
        func = call_node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return ast.dump(func)
        return "<unknown>"

    @staticmethod
    def _is_wrapper_candidate(
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        """Return True when node is a non-dunder, undecorated single-statement function."""
        if node.name.startswith("__") and node.name.endswith("__"):
            return False
        if node.decorator_list:
            return False
        return len(node.body) == 1

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []
        findings: list[RuleFinding] = []
        for node in ast.walk(module):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not self._is_wrapper_candidate(node):
                continue
            call_node = self._extract_single_call(node.body[0])
            if call_node is None:
                continue
            wrapped = self._call_target_name(call_node)
            findings.append(RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.MEDIUM,
                decision=decision_for_context(ctx),
                message=(
                    f"Function `{node.name}` in `{path_value}` is a thin wrapper "
                    f"around `{wrapped}`. Consider calling the wrapped function directly."
                ),
                metadata={"path": path_value, "function": node.name, "wraps": wrapped},
            ))
        return findings

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


@final
class PythonGodClassRule(Rule):
    """PY-CODE-014: Block classes with more than 10 non-dunder methods."""

    rule_id = "PY-CODE-014"
    title = "Block god class"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    @staticmethod
    def _non_dunder_method_count(node: ast.ClassDef) -> int:
        """Return count of non-dunder methods in a class body."""
        count = 0
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not (child.name.startswith("__") and child.name.endswith("__")):
                    count += 1
        return count

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []
        findings: list[RuleFinding] = []
        limit = ctx.config.python_max_god_class_methods
        for node in ast.walk(module):
            if not isinstance(node, ast.ClassDef):
                continue
            method_count = self._non_dunder_method_count(node)
            if method_count > limit:
                findings.append(RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.HIGH,
                    decision=decision_for_context(ctx),
                    message=(
                        f"Class `{node.name}` in `{path_value}` has {method_count}"
                        f" non-dunder methods. Keep classes at or below {limit}"
                        f" methods or split responsibilities."
                    ),
                    metadata={
                        "path": path_value,
                        "class": node.name,
                        "method_count": method_count,
                    },
                ))
        return findings

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


# Node types that each add 1 to cyclomatic complexity
_CC_BRANCH_TYPES = (
    ast.If,
    ast.IfExp,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.ExceptHandler,
    ast.With,
    ast.AsyncWith,
    ast.Assert,
    ast.comprehension,
)


@final
class PythonCyclomaticComplexityRule(Rule):
    """PY-CODE-015: Block functions with cyclomatic complexity > 10."""

    rule_id = "PY-CODE-015"
    title = "Block cyclomatic complexity"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    @staticmethod
    def _complexity(node: ast.AST) -> int:
        """Compute cyclomatic complexity for a function body."""
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, _CC_BRANCH_TYPES):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []
        worst_name = ""
        worst_cc = 0
        for node in ast.walk(module):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                cc = self._complexity(node)
                if cc > ctx.config.python_max_complexity and cc > worst_cc:
                    worst_name = node.name
                    worst_cc = cc
        if not worst_name:
            return []
        limit = ctx.config.python_max_complexity
        return [RuleFinding(
            rule_id=self.rule_id,
            title=self.title,
            severity=Severity.HIGH,
            decision=decision_for_context(ctx),
            message=(
                f"Function `{worst_name}` in `{path_value}` has cyclomatic complexity {worst_cc}. "
                f"Keep complexity at or below {limit}."
            ),
            metadata={"path": path_value, "function": worst_name, "complexity": worst_cc},
        )]

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


@final
class PythonDeadCodeRule(Rule):
    """PY-CODE-016: Detect unreachable code after return/raise/break/continue."""

    rule_id = "PY-CODE-016"
    title = "Block dead code after return"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    _TERMINAL = (ast.Return, ast.Raise, ast.Break, ast.Continue)

    def _scan_block(self, stmts: list[ast.stmt]) -> tuple[str | None, int]:
        """Return (description, lineno) of first dead statement, or (None, 0)."""
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, self._TERMINAL) and i < len(stmts) - 1:
                dead_stmt = stmts[i + 1]
                return (type(stmt).__name__.lower(), getattr(dead_stmt, "lineno", 0))
        return (None, 0)

    @staticmethod
    def _collect_blocks(child: ast.AST) -> list[list[ast.stmt]]:
        """Return all statement blocks owned by child that should be scanned."""
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return [child.body]
        if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While)):
            blocks: list[list[ast.stmt]] = [child.body]
            if child.orelse:
                blocks.append(child.orelse)
            return blocks
        if isinstance(child, ast.Try):
            blocks = [child.body]
            for handler in child.handlers:
                blocks.append(handler.body)
            if child.orelse:
                blocks.append(child.orelse)
            if child.finalbody:
                blocks.append(child.finalbody)
            return blocks
        if isinstance(child, (ast.With, ast.AsyncWith, ast.ExceptHandler)):
            return [child.body]
        return []

    def _find_dead_code(self, node: ast.AST) -> list[tuple[str, int]]:
        """Walk all statement blocks and collect dead code locations."""
        results: list[tuple[str, int]] = []
        for child in ast.walk(node):
            for block in self._collect_blocks(child):
                cause, lineno = self._scan_block(block)
                if cause is not None:
                    results.append((cause, lineno))
        return results

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []
        findings: list[RuleFinding] = []
        for node in ast.walk(module):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            dead = self._find_dead_code(node)
            if not dead:
                continue
            cause, lineno = dead[0]
            findings.append(RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.HIGH,
                decision=decision_for_context(ctx),
                message=(
                    f"Function `{node.name}` in `{path_value}` has unreachable code "
                    f"after `{cause}` at line {lineno}."
                ),
                metadata={
                    "path": path_value,
                    "function": node.name,
                    "dead_line": lineno,
                    "cause": cause,
                },
            ))
        return findings

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)


# ---------------------------------------------------------------------------
# PY-CODE-017: Detect _prefix_* flat-file sprawl (PostToolUse only)
# ---------------------------------------------------------------------------


@final
class PythonFlatFileSiblingsRule(Rule):
    """After a .py write, check if the parent dir has 3+ files sharing a
    _prefix_ naming pattern -- a sign the module should be a sub-package.
    """

    rule_id = "PY-CODE-017"
    title = "Block flat _prefix_* sibling file sprawl"
    events = ("PostToolUse",)

    _MIN_SIBLINGS = 3  # trigger threshold

    @staticmethod
    def _prefix_groups(directory: Path) -> dict[str, list[str]]:
        """Group _prefix_*.py files by their shared prefix."""
        import re as _re

        groups: dict[str, list[str]] = {}
        pat = _re.compile(r"^_([a-z]+)_[a-z_]+\.py$")
        for child in directory.iterdir():
            if not child.is_file():
                continue
            m = pat.match(child.name)
            if m:
                groups.setdefault(m.group(1), []).append(child.name)
        return groups

    @staticmethod
    def _build_pkg_block(files: list[str], prefix: str) -> str:
        """Return indented stem lines for the suggested sub-package layout."""
        tag = "_" + prefix + "_"
        return "\n".join("        " + f.removeprefix(tag) for f in sorted(files)[:5])

    def _finding_for_prefix(
        self, parent: Path, prefix: str, files: list[str]
    ) -> RuleFinding:
        files_str = ", ".join(sorted(files)[:5])
        pkg_block = self._build_pkg_block(files, prefix)
        nl = "\n"
        msg = (
            f"Directory `{parent.name}/` has {len(files)} "
            f"`_{prefix}_*.py` sibling files ({files_str}). "
            f"Convert to a sub-package instead:{nl}{nl}"
            f"    {parent.name}/{prefix}/{nl}"
            f"        __init__.py   (re-export public API){nl}"
            f"{pkg_block}{nl}{nl}"
            f"The __init__.py should re-export so external imports don't change."
        )
        return RuleFinding(
            rule_id=self.rule_id,
            title=self.title,
            severity=Severity.HIGH,
            decision="block",
            message=msg,
            metadata={
                "directory": str(parent),
                "prefix": prefix,
                "count": len(files),
                "files": sorted(files),
            },
        )

    def _findings_for_directory(self, parent: Path) -> list[RuleFinding]:
        findings: list[RuleFinding] = []
        for prefix, files in self._prefix_groups(parent).items():
            if len(files) >= self._MIN_SIBLINGS:
                findings.append(self._finding_for_prefix(parent, prefix, files))
        return findings

    def _resolve_candidate_dirs(self, ctx: HookContext) -> list[Path]:
        seen: set[Path] = set()
        dirs: list[Path] = []
        for path_value in ctx.candidate_paths:
            if not path_value.lower().endswith((".py", ".pyi")):
                continue
            full = (
                (Path(ctx.cwd) / path_value).resolve()
                if not Path(path_value).is_absolute()
                else Path(path_value)
            )
            parent = full.parent
            if parent not in seen and parent.is_dir():
                seen.add(parent)
                dirs.append(parent)
        return dirs

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        if ctx.event_name not in self.events:
            return []
        if not (is_edit_like_tool(ctx.tool_name) or is_bash_tool(ctx.tool_name)):
            return []
        findings: list[RuleFinding] = []
        for parent in self._resolve_candidate_dirs(ctx):
            findings.extend(self._findings_for_directory(parent))
        return findings


# ---------------------------------------------------------------------------
# PY-IMPORT-001: Import fanout suggests facade opportunity
# ---------------------------------------------------------------------------


@final
class PythonImportFanoutRule(Rule):
    """PY-IMPORT-001: Detect when too many names are imported from one module.

    A high import count from a single module signals that the caller should
    either use a namespace import or that the source module needs a facade.
    """

    rule_id = "PY-IMPORT-001"
    title = "Import fanout suggests facade opportunity"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    @staticmethod
    def _collect_names_by_module(module: ast.Module) -> dict[str, list[str]]:
        """Return mapping of source-module name -> imported names (top-level only)."""
        names_by_module: dict[str, list[str]] = defaultdict(list)
        for node in module.body:
            if not isinstance(node, ast.ImportFrom) or node.module is None:
                continue
            for alias in node.names:
                imported_name = alias.asname if alias.asname else alias.name
                names_by_module[node.module].append(imported_name)
        return names_by_module

    def _fanout_finding(
        self, path_value: str, mod_name: str, names: list[str], limit: int
    ) -> RuleFinding | None:
        """Return a finding when import count exceeds limit, else None."""
        if len(names) <= limit:
            return None
        family_prefix = detect_family_prefix(names)
        names_preview = ", ".join(names[:6]) + (", ..." if len(names) > 6 else "")
        if family_prefix is not None:
            severity = Severity.MEDIUM
            family_msg = (
                f" Several names share the `{family_prefix}` prefix"
                " \u2014 strong signal for a service class or facade."
            )
        else:
            severity = Severity.LOW
            family_msg = ""
        message = (
            f"`{path_value}` imports {len(names)} names from `{mod_name}` "
            f"({names_preview}).{family_msg} "
            f"Consider `import {mod_name}` and access via namespace, "
            f"or introduce a facade/service class to reduce coupling."
        )
        return RuleFinding(
            rule_id=self.rule_id,
            title=self.title,
            severity=severity,
            decision="context",
            message=message,
            metadata={
                "path": path_value,
                "module": mod_name,
                "import_count": len(names),
                "names": names,
                "family_prefix": family_prefix,
            },
        )

    def _check_source(
        self,
        source: str,
        path_value: str,
        ctx: HookContext,
    ) -> list[RuleFinding]:
        module = parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []
        limit = ctx.config.python_import_fanout_limit
        names_by_module = self._collect_names_by_module(module)
        findings: list[RuleFinding] = []
        for mod_name, names in names_by_module.items():
            finding = self._fanout_finding(path_value, mod_name, names, limit)
            if finding is not None:
                findings.append(finding)
        return findings

    @override
    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        return evaluate_common(self, ctx, self._check_source)
