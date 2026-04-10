from __future__ import annotations

import ast
from collections import Counter, defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, final

from vibeforcer.models import RuleFinding, Severity
from vibeforcer.rules.base import Rule, is_rule_enabled
from vibeforcer.util.payloads import is_bash_tool, is_edit_like_tool

if TYPE_CHECKING:
    from vibeforcer.context import HookContext

    CheckFn = Callable[[str, str, "HookContext"], list[RuleFinding]]


# Paths containing any of these segments are third-party / vendored code
# and should be excluded from quality analysis.
_THIRD_PARTY_SEGMENTS = (
    ".venv/",
    "site-packages/",
    "node_modules/",
    ".tox/",
    ".nox/",
    "/.eggs/",
)


def _is_third_party_path(path: str) -> bool:
    """Return True if path points to third-party / vendored code."""
    normalised = path.replace("\\", "/")
    return any(seg in normalised for seg in _THIRD_PARTY_SEGMENTS)


def _decision(ctx: HookContext) -> str:
    return "deny" if ctx.event_name in ("PreToolUse", "PermissionRequest") else "block"


def _parse_module(source: str, max_chars: int) -> ast.Module | None:
    """Parse source into an AST module, respecting size limit."""
    if len(source) > max_chars:
        return None
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def _evaluate_common(
    rule: Rule,
    ctx: HookContext,
    check_fn: CheckFn,
) -> list[RuleFinding]:
    """Shared evaluate logic for all Python AST rules."""
    if not is_rule_enabled(ctx, rule.rule_id):
        return []
    if not ctx.config.python_ast_enabled:
        return []
    findings: list[RuleFinding] = []
    is_pre = ctx.event_name in ("PreToolUse", "PermissionRequest")
    if is_pre:
        for ct in ctx.content_targets:
            if not ct.path.lower().endswith((".py", ".pyi")):
                continue
            if _is_third_party_path(ct.path):
                continue
            findings.extend(check_fn(ct.content, ct.path, ctx))
    else:
        # Only run PostToolUse AST analysis for edit-like/bash tools, not Read/Grep/Glob
        if not (is_edit_like_tool(ctx.tool_name) or is_bash_tool(ctx.tool_name)):
            return []
        for path_value in ctx.candidate_paths:
            if not path_value.lower().endswith((".py", ".pyi")):
                continue
            # Skip third-party / vendored code — not authored by the agent
            if _is_third_party_path(path_value):
                continue
            full_path = (
                (ctx.config.root / path_value).resolve()
                if not Path(path_value).is_absolute()
                else Path(path_value)
            )
            try:
                source = full_path.read_text(encoding="utf-8")
            except OSError:
                continue
            findings.extend(check_fn(source, path_value, ctx))
    return findings


# ---------------------------------------------------------------------------
# Existing rules (PY-CODE-008, PY-CODE-009)
# ---------------------------------------------------------------------------


@final
class PythonLongMethodRule(Rule):
    rule_id = "PY-CODE-008"
    title = "Block long Python methods"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        """Parse source and return findings for any too-long functions."""
        if len(source) > ctx.config.python_ast_max_parse_chars:
            return []
        try:
            module = ast.parse(source)
        except SyntaxError:
            return []
        too_long: list[tuple[str, int]] = []
        for node in ast.walk(module):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.end_lineno is None:
                    continue
                span = node.end_lineno - node.lineno + 1
                if span > ctx.config.python_long_method_lines:
                    too_long.append((node.name, span))
        if not too_long:
            return []
        name, span = sorted(too_long, key=lambda item: item[1], reverse=True)[0]
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.HIGH,
                decision="deny"
                if ctx.event_name in ("PreToolUse", "PermissionRequest")
                else "block",
                message=(
                    f"Python function `{name}` in `{path_value}` is {span} lines long. "
                    f"Keep functions under {ctx.config.python_long_method_lines} lines or split them into helpers."
                ),
                metadata={"path": path_value, "function": name, "lines": span},
            ),
        ]

    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        return _evaluate_common(self, ctx, self._check_source)


@final
class PythonLongParameterRule(Rule):
    rule_id = "PY-CODE-009"
    title = "Block long Python parameter lists"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        """Parse source and return findings for any too-long parameter lists."""
        if len(source) > ctx.config.python_ast_max_parse_chars:
            return []
        try:
            module = ast.parse(source)
        except SyntaxError:
            return []
        offenders: list[tuple[str, int]] = []
        for node in ast.walk(module):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = (
                    list(node.args.posonlyargs)
                    + list(node.args.args)
                    + list(node.args.kwonlyargs)
                )
                names = [arg.arg for arg in args]
                if names and names[0] in {"self", "cls"}:
                    names = names[1:]
                if len(names) > ctx.config.python_long_parameter_limit:
                    offenders.append((node.name, len(names)))
        if not offenders:
            return []
        name, count = sorted(offenders, key=lambda item: item[1], reverse=True)[0]
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.MEDIUM,
                decision="deny"
                if ctx.event_name in ("PreToolUse", "PermissionRequest")
                else "block",
                message=(
                    f"Python function `{name}` in `{path_value}` declares {count} parameters. "
                    f"Keep functions at or below {ctx.config.python_long_parameter_limit} parameters or group inputs into objects."
                ),
                metadata={
                    "path": path_value,
                    "function": name,
                    "parameter_count": count,
                },
            ),
        ]

    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        return _evaluate_common(self, ctx, self._check_source)


# ---------------------------------------------------------------------------
# New rules (PY-CODE-010 through PY-CODE-016)
# ---------------------------------------------------------------------------


@final
class PythonLongLineRule(Rule):
    """PY-CODE-010: Block files containing lines over 120 characters."""

    rule_id = "PY-CODE-010"
    title = "Block long lines"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    # max line length read from config.python_max_line_length

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        max_length = ctx.config.python_max_line_length
        if len(source) > ctx.config.python_ast_max_parse_chars:
            return []
        in_docstring = False
        worst_lineno = 0
        worst_length = 0
        for lineno, raw_line in enumerate(source.splitlines(), start=1):
            stripped = raw_line.strip()
            # Toggle docstring state on triple-quote boundaries
            for marker in ('"""', "'''"):
                count = stripped.count(marker)
                if count % 2 == 1:
                    in_docstring = not in_docstring
            if in_docstring:
                continue
            # Skip comments
            if stripped.startswith("#"):
                continue
            # Skip URL-containing lines
            if "http://" in raw_line or "https://" in raw_line:
                continue
            if len(raw_line) > max_length and len(raw_line) > worst_length:
                worst_lineno = lineno
                worst_length = len(raw_line)
        if worst_length <= max_length:
            return []
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.MEDIUM,
                decision=_decision(ctx),
                message=(
                    f"Line {worst_lineno} in `{path_value}` is {worst_length} characters long. "
                    f"Keep lines at or below {max_length} characters."
                ),
                metadata={
                    "path": path_value,
                    "line": worst_lineno,
                    "length": worst_length,
                },
            ),
        ]

    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        return _evaluate_common(self, ctx, self._check_source)


@final
class PythonDeepNestingRule(Rule):
    """PY-CODE-011: Block functions with nesting depth > 4."""

    rule_id = "PY-CODE-011"
    title = "Block deep nesting"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    # max nesting read from config.python_max_nesting_depth
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
        """Return the maximum nesting depth below *node*."""
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
        module = _parse_module(source, ctx.config.python_ast_max_parse_chars)
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
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.HIGH,
                decision=_decision(ctx),
                message=(
                    f"Function `{worst_name}` in `{path_value}` has nesting depth {worst_depth}. "
                    f"Keep nesting at or below {ctx.config.python_max_nesting_depth} levels."
                ),
                metadata={
                    "path": path_value,
                    "function": worst_name,
                    "depth": worst_depth,
                },
            ),
        ]

    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        return _evaluate_common(self, ctx, self._check_source)


@final
class PythonFeatureEnvyRule(Rule):
    """PY-CODE-012: Detect functions where >60% of attribute accesses target one external object."""

    rule_id = "PY-CODE-012"
    title = "Block feature envy"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    # threshold read from config.python_feature_envy_threshold
    # min accesses read from config.python_feature_envy_min_accesses
    # Common stdlib/utility module names that look like objects but are not
    _IGNORE_NAMES = frozenset(
        {
            "os",
            "sys",
            "re",
            "io",
            "abc",
            "ast",
            "csv",
            "json",
            "math",
            "time",
            "uuid",
            "enum",
            "copy",
            "gzip",
            "html",
            "http",
            "shutil",
            "signal",
            "socket",
            "string",
            "struct",
            "typing",
            "base64",
            "codecs",
            "hashlib",
            "logging",
            "pathlib",
            "secrets",
            "sqlite3",
            "urllib",
            "asyncio",
            "collections",
            "contextlib",
            "dataclasses",
            "datetime",
            "functools",
            "importlib",
            "itertools",
            "multiprocessing",
            "operator",
            "platform",
            "pprint",
            "random",
            "subprocess",
            "tempfile",
            "textwrap",
            "threading",
            "traceback",
            "unittest",
            "warnings",
            "np",
            "pd",
            "plt",
            "tf",
            "torch",
            "sk",  # common aliases
            "Path",
            "Enum",
            "Optional",
            "Union",
            "List",
            "Dict",
            "Set",
            "Tuple",
        }
    )

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

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = _parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []
        findings: list[RuleFinding] = []
        for node in ast.walk(module):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            param_ns = self._param_names(node)
            counts: dict[str, int] = {}
            total = 0
            for child in ast.walk(node):
                if isinstance(child, ast.Attribute):
                    root = self._root_name(child)
                    if (
                        root is None
                        or root in ("self", "cls")
                        or root in self._IGNORE_NAMES
                    ):
                        continue
                    if root in param_ns:
                        continue
                    counts[root] = counts.get(root, 0) + 1
                    total += 1
            if total < ctx.config.python_feature_envy_min_accesses:
                continue
            for obj_name, count in counts.items():
                if count / total > ctx.config.python_feature_envy_threshold:
                    findings.append(
                        RuleFinding(
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
                        ),
                    )
                    break  # one finding per function
        return findings

    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        return _evaluate_common(self, ctx, self._check_source)


@final
class PythonThinWrapperRule(Rule):
    """PY-CODE-013: Detect functions whose body is a single delegating call."""

    rule_id = "PY-CODE-013"
    title = "Block thin wrappers"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = _parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []
        findings: list[RuleFinding] = []
        for node in ast.walk(module):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Exclude dunders
            if node.name.startswith("__") and node.name.endswith("__"):
                continue
            # Exclude decorated functions
            if node.decorator_list:
                continue
            # Must have exactly one statement in body
            if len(node.body) != 1:
                continue
            stmt = node.body[0]
            # Return(Call(...)) or Expr(Call(...))
            call_node: ast.Call | None = None
            if (isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call)) or (
                isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)
            ):
                call_node = stmt.value
            if call_node is None:
                continue
            # Determine what is being wrapped
            func = call_node.func
            if isinstance(func, ast.Name):
                wrapped = func.id
            elif isinstance(func, ast.Attribute):
                wrapped = ast.dump(func)
            else:
                wrapped = "<unknown>"
            findings.append(
                RuleFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    decision=_decision(ctx),
                    message=(
                        f"Function `{node.name}` in `{path_value}` is a thin wrapper "
                        f"around `{wrapped}`. Consider calling the wrapped function directly."
                    ),
                    metadata={
                        "path": path_value,
                        "function": node.name,
                        "wraps": wrapped,
                    },
                ),
            )
        return findings

    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        return _evaluate_common(self, ctx, self._check_source)


@final
class PythonGodClassRule(Rule):
    """PY-CODE-014: Block classes with more than 10 non-dunder methods."""

    rule_id = "PY-CODE-014"
    title = "Block god class"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    # max methods read from config.python_max_god_class_methods

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = _parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []
        findings: list[RuleFinding] = []
        for node in ast.walk(module):
            if not isinstance(node, ast.ClassDef):
                continue
            method_count = 0
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not (child.name.startswith("__") and child.name.endswith("__")):
                        method_count += 1
            if method_count > ctx.config.python_max_god_class_methods:
                findings.append(
                    RuleFinding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.HIGH,
                        decision=_decision(ctx),
                        message=(
                            f"Class `{node.name}` in `{path_value}` has {method_count} non-dunder methods. "
                            f"Keep classes at or below {ctx.config.python_max_god_class_methods} methods or split responsibilities."
                        ),
                        metadata={
                            "path": path_value,
                            "class": node.name,
                            "method_count": method_count,
                        },
                    ),
                )
        return findings

    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        return _evaluate_common(self, ctx, self._check_source)


@final
class PythonCyclomaticComplexityRule(Rule):
    """PY-CODE-015: Block functions with cyclomatic complexity > 10."""

    rule_id = "PY-CODE-015"
    title = "Block cyclomatic complexity"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    # max complexity read from config.python_max_complexity

    @staticmethod
    def _complexity(node: ast.AST) -> int:
        """Compute cyclomatic complexity for a function body."""
        complexity = 1
        for child in ast.walk(node):
            if (
                isinstance(child, (ast.If, ast.IfExp))
                or isinstance(child, (ast.For, ast.AsyncFor, ast.While))
                or isinstance(child, ast.ExceptHandler)
                or isinstance(child, (ast.With, ast.AsyncWith))
                or isinstance(child, ast.Assert)
            ):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
            elif isinstance(child, ast.comprehension):
                complexity += 1
        return complexity

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = _parse_module(source, ctx.config.python_ast_max_parse_chars)
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
        return [
            RuleFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=Severity.HIGH,
                decision=_decision(ctx),
                message=(
                    f"Function `{worst_name}` in `{path_value}` has cyclomatic complexity {worst_cc}. "
                    f"Keep complexity at or below {ctx.config.python_max_complexity}."
                ),
                metadata={
                    "path": path_value,
                    "function": worst_name,
                    "complexity": worst_cc,
                },
            ),
        ]

    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        return _evaluate_common(self, ctx, self._check_source)


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

    def _find_dead_code(self, node: ast.AST) -> list[tuple[str, int]]:
        """Walk all statement blocks and collect dead code locations."""
        results: list[tuple[str, int]] = []
        for child in ast.walk(node):
            blocks: list[list[ast.stmt]] = []
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                blocks.append(child.body)
            elif isinstance(child, ast.If) or isinstance(
                child, (ast.For, ast.AsyncFor, ast.While)
            ):
                blocks.append(child.body)
                if child.orelse:
                    blocks.append(child.orelse)
            elif isinstance(child, ast.Try):
                blocks.append(child.body)
                for handler in child.handlers:
                    blocks.append(handler.body)
                if child.orelse:
                    blocks.append(child.orelse)
                if child.finalbody:
                    blocks.append(child.finalbody)
            elif isinstance(child, (ast.With, ast.AsyncWith)) or isinstance(
                child, ast.ExceptHandler
            ):
                blocks.append(child.body)
            for block in blocks:
                cause, lineno = self._scan_block(block)
                if cause is not None:
                    results.append((cause, lineno))
        return results

    def _check_source(
        self, source: str, path_value: str, ctx: HookContext
    ) -> list[RuleFinding]:
        module = _parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []
        findings: list[RuleFinding] = []
        for node in ast.walk(module):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            dead = self._find_dead_code(node)
            if dead:
                cause, lineno = dead[0]
                findings.append(
                    RuleFinding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=Severity.HIGH,
                        decision=_decision(ctx),
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
                    ),
                )
        return findings

    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        return _evaluate_common(self, ctx, self._check_source)


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

    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        if not is_rule_enabled(ctx, self.rule_id):
            return []
        if ctx.event_name not in self.events:
            return []
        if not (is_edit_like_tool(ctx.tool_name) or is_bash_tool(ctx.tool_name)):
            return []

        findings: list[RuleFinding] = []
        seen_dirs: set[Path] = set()

        for path_value in ctx.candidate_paths:
            if not path_value.lower().endswith((".py", ".pyi")):
                continue
            full = (
                (Path(ctx.cwd) / path_value).resolve()
                if not Path(path_value).is_absolute()
                else Path(path_value)
            )
            parent = full.parent
            if parent in seen_dirs or not parent.is_dir():
                continue
            seen_dirs.add(parent)

            groups = self._prefix_groups(parent)
            for prefix, files in groups.items():
                if len(files) >= self._MIN_SIBLINGS:
                    files_str = ", ".join(sorted(files)[:5])
                    nl = chr(10)  # newline for f-strings
                    pkg_lines = []
                    for fname in sorted(files)[:5]:
                        stem = fname
                        tag = "_" + prefix + "_"
                        stem = stem.removeprefix(tag)
                        pkg_lines.append("        " + stem)
                    pkg_block = nl.join(pkg_lines)
                    msg = (
                        f"Directory `{parent.name}/` has {len(files)} "
                        f"`_{prefix}_*.py` sibling files ({files_str}). "
                        f"Convert to a sub-package instead:{nl}{nl}"
                        f"    {parent.name}/{prefix}/{nl}"
                        f"        __init__.py   (re-export public API){nl}"
                        f"{pkg_block}{nl}{nl}"
                        f"The __init__.py should re-export so "
                        f"external imports don't change."
                    )
                    findings.append(
                        RuleFinding(
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
                        ),
                    )
        return findings


# ---------------------------------------------------------------------------
# PY-IMPORT-001: Import fanout suggests facade opportunity
# ---------------------------------------------------------------------------

# Prefixes that signal a function family (parse_*, build_*, validate_*, …)
_FAMILY_PREFIXES = (
    "parse_",
    "build_",
    "create_",
    "make_",
    "get_",
    "set_",
    "validate_",
    "check_",
    "format_",
    "render_",
    "load_",
    "save_",
    "encode_",
    "decode_",
    "serialize_",
    "deserialize_",
)


def _detect_family_prefix(names: list[str]) -> str | None:
    """Return the shared prefix if 3+ names share one, else None."""
    prefix_counts: Counter[str] = Counter()
    for name in names:
        for prefix in _FAMILY_PREFIXES:
            if name.startswith(prefix):
                prefix_counts[prefix] += 1
                break
    for prefix, count in prefix_counts.most_common(1):
        if count >= 3:
            return prefix
    return None


@final
class PythonImportFanoutRule(Rule):
    """PY-IMPORT-001: Detect when too many names are imported from one module.

    A high import count from a single module signals that the caller should
    either use a namespace import or that the source module needs a facade.
    """

    rule_id = "PY-IMPORT-001"
    title = "Import fanout suggests facade opportunity"
    events = ("PreToolUse", "PermissionRequest", "PostToolUse")

    def _check_source(
        self,
        source: str,
        path_value: str,
        ctx: HookContext,
    ) -> list[RuleFinding]:
        module = _parse_module(source, ctx.config.python_ast_max_parse_chars)
        if module is None:
            return []

        limit = ctx.config.python_import_fanout_limit

        # Collect names imported per source module (top-level only)
        names_by_module: dict[str, list[str]] = defaultdict(list)
        for node in module.body:
            if not isinstance(node, ast.ImportFrom):
                continue
            if node.module is None:
                continue
            for alias in node.names:
                imported_name = alias.asname if alias.asname else alias.name
                names_by_module[node.module].append(imported_name)

        findings: list[RuleFinding] = []
        for mod_name, names in names_by_module.items():
            if len(names) <= limit:
                continue

            family_prefix = _detect_family_prefix(names)
            names_preview = ", ".join(names[:6])
            if len(names) > 6:
                names_preview += ", ..."

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

            findings.append(
                RuleFinding(
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
                ),
            )
        return findings

    def evaluate(self, ctx: HookContext) -> list[RuleFinding]:
        return _evaluate_common(self, ctx, self._check_source)
