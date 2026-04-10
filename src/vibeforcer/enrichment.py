"""Context enrichment for rule findings.

Enriches denial messages with project-specific context: nearby fixtures,
parametrize examples from sibling test files, and existing patterns the
agent can follow.  All enrichment is best-effort — filesystem errors or
missing files silently produce empty context (no exceptions propagate).

The enrichment pipeline runs *after* rule evaluation and *before* output
rendering, so it augments both ``message`` (all platforms) and
``additional_context`` (Claude Code bonus channel).
"""

from __future__ import annotations

import ast
import re
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Callable, cast

if TYPE_CHECKING:
    from vibeforcer.context import HookContext
    from vibeforcer.models import RuleFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_read(path: Path, max_bytes: int = 100_000) -> str:
    """Read a file, returning empty string on any error."""
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _safe_parse(source: str) -> ast.Module | None:
    """Parse Python source, returning None on syntax error."""
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def _resolve_path(path_str: str, root: Path) -> Path:
    """Resolve a possibly-relative path against root."""
    p = Path(path_str)
    if p.is_absolute():
        return p
    return (root / p).resolve()


# ---------------------------------------------------------------------------
# Fixture discovery
# ---------------------------------------------------------------------------


def _discover_fixtures(test_path: Path, root: Path) -> list[dict]:
    """Walk up from test_path finding conftest.py fixtures.

    Returns list of {name, conftest_path, params (bool)} dicts, capped at 10.
    """
    fixtures: list[dict] = []
    seen_names: set[str] = set()
    current = test_path.parent

    for _ in range(10):  # depth limit
        conftest = current / "conftest.py"
        if conftest.exists():
            remaining = 10 - len(fixtures)
            if remaining > 0:
                fixtures.extend(
                    _collect_fixtures_from_conftest(
                        conftest=conftest,
                        root=root,
                        seen_names=seen_names,
                        max_items=remaining,
                    )
                )
        if len(fixtures) >= 10:
            break
        if current == root or current == current.parent:
            break
        current = current.parent

    return fixtures


def _collect_fixtures_from_conftest(
    *,
    conftest: Path,
    root: Path,
    seen_names: set[str],
    max_items: int,
) -> list[dict]:
    source = _safe_read(conftest)
    if not source:
        return []
    tree = _safe_parse(source)
    if not tree:
        return []

    rel = (
        str(conftest.relative_to(root)) if _is_under(conftest, root) else str(conftest)
    )
    discovered: list[dict] = []
    for node in ast.walk(tree):
        if len(discovered) >= max_items:
            break
        if not isinstance(node, ast.FunctionDef):
            continue
        if not _has_fixture_decorator(node):
            continue
        if node.name in seen_names:
            continue

        seen_names.add(node.name)
        discovered.append(
            {
                "name": node.name,
                "conftest": rel,
                "has_params": _fixture_has_params(node),
            }
        )
    return discovered


def _is_fixture_attr(node: ast.expr) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "fixture"


def _is_fixture_name(node: ast.expr) -> bool:
    return isinstance(node, ast.Name) and node.id == "fixture"


def _is_fixture_decorator(node: ast.expr) -> bool:
    if _is_fixture_attr(node) or _is_fixture_name(node):
        return True
    if not isinstance(node, ast.Call):
        return False
    return _is_fixture_attr(node.func) or _is_fixture_name(node.func)


def _has_fixture_decorator(node: ast.FunctionDef) -> bool:
    """Check if a function has @pytest.fixture decorator."""
    for dec in node.decorator_list:
        if _is_fixture_decorator(dec):
            return True
    return False


def _fixture_has_params(node: ast.FunctionDef) -> bool:
    """Check if a pytest.fixture decorator uses params=."""
    for dec in node.decorator_list:
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg == "params":
                    return True
    return False


def _is_under(path: Path, root: Path) -> bool:
    """Check if path is under root."""
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _append_enrichment_message(finding: "RuleFinding", lines: list[str]) -> None:
    if not lines:
        return
    base_message = finding.message or ""
    finding.message = base_message.rstrip() + "\n" + "\n".join(lines)


# ---------------------------------------------------------------------------
# Parametrize example discovery
# ---------------------------------------------------------------------------

_PARAMETRIZE_RE = re.compile(
    r"(@pytest\.mark\.parametrize\(.+?\))\s*\n\s*(def\s+\w+\([^)]*\))",
    re.DOTALL,
)


def _find_parametrize_examples(
    test_path: Path, _root: Path, max_examples: int = 3
) -> list[dict]:
    """Find @pytest.mark.parametrize usage in sibling test files.

    Returns list of {file, snippet} dicts.
    """
    examples: list[dict] = []
    parent = test_path.parent
    if not parent.exists():
        return examples

    try:
        siblings = sorted(parent.glob("test_*.py"))
    except OSError:
        return examples

    for sibling in siblings:
        if sibling == test_path or sibling.name == "conftest.py":
            continue
        source = _safe_read(sibling, max_bytes=50_000)
        if not source or "@pytest.mark.parametrize" not in source:
            continue

        # Extract the first parametrize decorator + function signature
        match = _PARAMETRIZE_RE.search(source)
        if match:
            snippet = match.group(0).strip()
            # Truncate overly long snippets
            if len(snippet) > 300:
                snippet = snippet[:297] + "..."
            rel = sibling.name
            examples.append({"file": rel, "snippet": snippet})

        if len(examples) >= max_examples:
            break

    return examples


def _build_test_loop_message_extras(
    fixtures: list[dict], examples: list[dict]
) -> list[str]:
    extras: list[str] = []

    if fixtures:
        names = ", ".join(f"`{f['name']}`" for f in fixtures[:6])
        conftest_paths = sorted({f["conftest"] for f in fixtures})
        if len(conftest_paths) == 1:
            extras.append(f"\nAvailable fixtures (from {conftest_paths[0]}): {names}")
        else:
            extras.append(f"\nAvailable fixtures: {names}")
        parameterized = [f for f in fixtures if f["has_params"]]
        if parameterized:
            extras.append(
                f"  Fixtures with params (already data-driven): "
                + ", ".join(f"`{f['name']}`" for f in parameterized[:3])
            )

    if examples:
        extras.append("\nExisting parametrize patterns in sibling tests:")
        for ex in examples[:2]:
            indented = "\n".join(f"    {line}" for line in ex["snippet"].splitlines())
            extras.append(f"  # From {ex['file']}:\n{indented}")

    return extras


def _build_test_loop_context_parts(
    fixtures: list[dict], examples: list[dict]
) -> list[str]:
    context_parts: list[str] = []

    if fixtures:
        context_parts.append("AVAILABLE FIXTURES:")
        for fixture in fixtures:
            param_note = " (parametrized)" if fixture["has_params"] else ""
            context_parts.append(
                f"  • {fixture['name']}{param_note}  — from {fixture['conftest']}"
            )

    if examples:
        context_parts.append("\nEXISTING PARAMETRIZE PATTERNS IN THIS DIRECTORY:")
        for example in examples:
            context_parts.append(f"  # {example['file']}:\n{example['snippet']}")

    context_parts.append(
        "\nCOMPLIANT ALTERNATIVES:\n"
        "1. @pytest.mark.parametrize for simple data-driven cases\n"
        "2. @pytest.mark.parametrize with indirect=True to parametrize fixtures\n"
        "3. pytest-subtests for cases needing independent reporting per iteration:\n"
        "     def test_all(subtests):\n"
        "         for case in cases:\n"
        "             with subtests.test(case=case):\n"
        "                 assert func(case)\n"
        "4. Parametrized fixture (conftest.py):\n"
        "     @pytest.fixture(params=[case1, case2, case3])\n"
        "     def input_val(request): return request.param"
    )

    return context_parts


# ---------------------------------------------------------------------------
# Enrichment strategies per rule prefix
# ---------------------------------------------------------------------------


def _enrich_test_loop(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-TEST-003 with fixture discovery and parametrize examples."""
    paths = finding.metadata.get("hits", [])
    if not paths:
        return

    test_path = _resolve_path(paths[0], ctx.config.root)
    fixtures = _discover_fixtures(test_path, ctx.config.root)
    examples = _find_parametrize_examples(test_path, ctx.config.root)

    _append_enrichment_message(
        finding, _build_test_loop_message_extras(fixtures, examples)
    )

    context_parts = _build_test_loop_context_parts(fixtures, examples)
    if context_parts:
        existing = finding.additional_context or ""
        finding.additional_context = (
            existing + "\n\n" + "\n".join(context_parts)
        ).strip()


def _enrich_assertion_roulette(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-TEST-001 with fixture context."""
    paths = finding.metadata.get("hits", [])
    if not paths:
        return

    test_path = _resolve_path(paths[0], ctx.config.root)
    fixtures = _discover_fixtures(test_path, ctx.config.root)

    extras: list[str] = []

    if fixtures:
        names = ", ".join(f"`{f['name']}`" for f in fixtures[:6])
        extras.append(f"\nAvailable fixtures: {names}")

    extras.append(
        "\nTIP: If assertions test different aspects of one result, consider "
        "splitting into focused test functions (one concept per test)."
    )

    _append_enrichment_message(finding, extras)


def _enrich_test_smells(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-TEST-002 with project-specific alternatives."""
    paths = finding.metadata.get("hits", [])
    if not paths:
        return

    test_path = _resolve_path(paths[0], ctx.config.root)
    fixtures = _discover_fixtures(test_path, ctx.config.root)

    extras: list[str] = []

    if fixtures:
        names = ", ".join(f"`{f['name']}`" for f in fixtures[:6])
        extras.append(f"\nAvailable fixtures: {names}")

    # Check if the project has common test utility packages
    root = ctx.config.root
    time_utils: list[str] = []
    for candidate in ("freezegun", "pytest-freezegun", "time_machine"):
        # Quick heuristic: check pyproject.toml or requirements*.txt
        for req_file in root.glob("requirements*.txt"):
            content = _safe_read(req_file, max_bytes=20_000)
            if candidate in content.lower():
                time_utils.append(candidate)
                break
        if not time_utils:
            pyproject = root / "pyproject.toml"
            content = _safe_read(pyproject, max_bytes=30_000)
            if candidate in content.lower():
                time_utils.append(candidate)

    if time_utils:
        extras.append(
            f"\nProject has time utilities: {', '.join(time_utils)} — "
            "prefer these over time.sleep() for test timing."
        )

    _append_enrichment_message(finding, extras)


def _enrich_fixture_outside_conftest(
    finding: "RuleFinding", ctx: "HookContext"
) -> None:
    """Enrich PY-TEST-004 with the nearest conftest.py path."""
    paths = finding.metadata.get("hits", [])
    if not paths:
        return

    test_path = _resolve_path(paths[0], ctx.config.root)
    test_dir = test_path.parent
    conftest = test_dir / "conftest.py"

    extras: list[str] = []

    if conftest.exists():
        fixtures = _discover_fixtures(test_path, ctx.config.root)
        if fixtures:
            names = ", ".join(f"`{f['name']}`" for f in fixtures[:6])
            extras.append(f"\nExisting fixtures in conftest.py: {names}")
        extras.append(
            f"\nMove the fixture to: {conftest.relative_to(ctx.config.root) if _is_under(conftest, ctx.config.root) else conftest}"
        )
    else:
        extras.append(
            f"\nNo conftest.py exists yet in {test_dir.relative_to(ctx.config.root) if _is_under(test_dir, ctx.config.root) else test_dir}/. "
            "Create one and define the fixture there."
        )

    _append_enrichment_message(finding, extras)


def _first_content_target(content_targets: Sequence[object]) -> str:
    """Return the first available target's content string."""
    for target in content_targets:
        return getattr(target, "content", "")
    return ""


def _typedict_tip() -> str:
    return (
        "\nTIP: For dict-like structures, consider TypedDict:\n"
        "    class UserData(TypedDict):\n"
        "        name: str\n"
        "        email: str"
    )


def _callable_tip() -> str:
    return (
        "\nTIP: For callbacks/handlers, use Callable with specific signatures:\n"
        "    Callable[[str, int], bool]"
    )


def _protocol_tip() -> str:
    return (
        "\nTIP: For duck-typed interfaces, define a Protocol:\n"
        "    class Readable(Protocol):\n"
        "        def read(self, n: int = -1) -> bytes: ..."
    )


def _python_any_suggestions(content_hint: str) -> list[str]:
    lower = content_hint.lower()
    extras: list[str] = []
    if "dict" in lower or "mapping" in lower:
        extras.append(_typedict_tip())
    if "def " in lower and any(
        token in lower for token in ("callback", "callable", "func", "handler")
    ):
        extras.append(_callable_tip())
    if "class " in lower and ("__getattr__" in lower or "__getitem__" in lower):
        extras.append(_protocol_tip())
    return extras


def _enrich_python_any(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-TYPE-001 with nearby type pattern hints."""
    content_hint = _first_content_target(ctx.content_targets)
    extras = _python_any_suggestions(content_hint)
    _append_enrichment_message(finding, extras)


# ---------------------------------------------------------------------------
# AST code quality enrichers (PY-CODE-*)
# ---------------------------------------------------------------------------


def _enrich_long_method(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-CODE-008 with function structure to suggest split points."""
    path_str = finding.metadata.get("path", "")
    func_name = finding.metadata.get("function", "")
    source = _read_and_parse_source(path_str, ctx.config.root)
    if not source:
        return
    tree, full_path = source
    node = _find_function_node(tree, func_name)
    if not node or not full_path:
        return
    extras = _build_long_method_extras(node, full_path)
    _append_enrichment_message(finding, extras)


def _find_function_node(
    tree: ast.Module, func_name: str
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == func_name
        ):
            return node
    return None


def _collect_long_method_blocks(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[str]:
    blocks: list[str] = []
    for child in node.body:
        if isinstance(child, ast.If):
            blocks.append(f"  • if-block at line {child.lineno}")
        elif isinstance(child, (ast.For, ast.AsyncFor)):
            blocks.append(f"  • loop at line {child.lineno}")
        elif isinstance(child, ast.With):
            blocks.append(f"  • with-block at line {child.lineno}")
        elif isinstance(child, ast.Try):
            blocks.append(f"  • try-block at line {child.lineno}")
    return blocks


def _collect_nested_function_names(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[str]:
    return [
        child.name
        for child in ast.iter_child_nodes(node)
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def _build_long_method_extras(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    full_path: Path,
) -> list[str]:
    # Keep behavior parity; return only the legacy message payload.
    _ = full_path
    blocks = _collect_long_method_blocks(node)
    nested = _collect_nested_function_names(node)
    extras: list[str] = []

    if blocks:
        extras.append("\nFunction structure (potential extraction points):")
        extras.extend(blocks[:8])
    if nested:
        extras.append(f"\nNested functions: {', '.join(f'`{n}`' for n in nested[:5])}")
    extras.append(
        "\nSplit strategy: extract each logical block into a named helper "
        "that does one thing. The parent function becomes an orchestrator."
    )
    return extras


def _enrich_long_method(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-CODE-008 with function structure to suggest split points."""
    meta = finding.metadata
    path_str = meta.get("path", "")
    func_name = meta.get("function", "")
    if not path_str or not func_name:
        return

    full_path = _resolve_path(path_str, ctx.config.root)
    source = _safe_read(full_path)
    if not source:
        return
    tree = _safe_parse(source)
    if not tree:
        return

    # Find the function and analyze its structure
    node = _find_function_node(tree=tree, func_name=func_name)
    if node is None:
        return
    extras = _build_long_method_extras(node, full_path)
    _append_enrichment_message(finding, extras)


def _enrich_long_params(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-CODE-009 with project patterns for parameter grouping."""
    meta = finding.metadata
    path_str = meta.get("path", "")
    func_name = meta.get("function", "")
    if not path_str:
        return

    full_path = _resolve_path(path_str, ctx.config.root)
    source = _safe_read(full_path)
    if not source:
        return
    tree = _safe_parse(source)
    if not tree:
        return

    # Find the function and list its params
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == func_name
        ):
            args = (
                list(node.args.posonlyargs)
                + list(node.args.args)
                + list(node.args.kwonlyargs)
            )
            param_names = [a.arg for a in args if a.arg not in ("self", "cls")]

            extras: list[str] = []
            if param_names:
                extras.append(
                    f"\nParameters: {', '.join(f'`{p}`' for p in param_names)}"
                )

            # Look for existing dataclass/TypedDict/NamedTuple in the same file
            grouped_types: list[str] = []
            for other in ast.walk(tree):
                if isinstance(other, ast.ClassDef):
                    for dec in other.decorator_list:
                        if (isinstance(dec, ast.Name) and dec.id == "dataclass") or (
                            isinstance(dec, ast.Attribute) and dec.attr == "dataclass"
                        ):
                            grouped_types.append(f"`{other.name}` (dataclass)")
                            break
                    # Check for TypedDict / NamedTuple bases
                    for base in other.bases:
                        name = ""
                        if isinstance(base, ast.Name):
                            name = base.id
                        elif isinstance(base, ast.Attribute):
                            name = base.attr
                        if name in ("TypedDict", "NamedTuple"):
                            grouped_types.append(f"`{other.name}` ({name})")

            if grouped_types:
                extras.append(
                    f"\nExisting parameter grouping patterns in this file: "
                    + ", ".join(grouped_types[:4])
                )

            extras.append(
                "\nGroup related parameters into a dataclass or TypedDict:\n"
                "    @dataclass\n"
                "    class Config:\n"
                "        param_a: str\n"
                "        param_b: int\n"
                "        param_c: bool = True"
            )

            _append_enrichment_message(finding, extras)
            break


def _enrich_cyclomatic_complexity(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-CODE-015 with the specific branches driving complexity."""
    meta = finding.metadata
    path_str = meta.get("path", "")
    func_name = meta.get("function", "")
    if not path_str or not func_name:
        return

    full_path = _resolve_path(path_str, ctx.config.root)
    source = _safe_read(full_path)
    if not source:
        return
    tree = _safe_parse(source)
    if not tree:
        return

    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == func_name
        ):
            # Count complexity sources
            ifs = 0
            loops = 0
            excepts = 0
            boolops = 0
            for child in ast.walk(node):
                if isinstance(child, (ast.If, ast.IfExp)):
                    ifs += 1
                elif isinstance(child, (ast.For, ast.AsyncFor, ast.While)):
                    loops += 1
                elif isinstance(child, ast.ExceptHandler):
                    excepts += 1
                elif isinstance(child, ast.BoolOp):
                    boolops += len(child.values) - 1

            extras: list[str] = []
            breakdown: list[str] = []
            if ifs:
                breakdown.append(f"{ifs} if/elif branches")
            if loops:
                breakdown.append(f"{loops} loops")
            if excepts:
                breakdown.append(f"{excepts} except handlers")
            if boolops:
                breakdown.append(f"{boolops} boolean operators (and/or)")

            if breakdown:
                extras.append(f"\nComplexity breakdown: {', '.join(breakdown)}")

            # Suggest refactoring strategy based on dominant source
            if ifs >= 4:
                extras.append(
                    "\nTIP: Multiple if/elif branches → consider a dispatch dict, "
                    "strategy pattern, or match/case (Python 3.10+)."
                )
            if loops >= 2:
                extras.append(
                    "\nTIP: Multiple loops → extract each loop body into a named function."
                )

            _append_enrichment_message(finding, extras)
            break


def _enrich_feature_envy(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-CODE-012 with the envied class's location."""
    meta = finding.metadata
    envied = meta.get("envied_object", "")
    path_str = meta.get("path", "")
    if not envied or not path_str:
        return

    full_path = _resolve_path(path_str, ctx.config.root)
    source = _safe_read(full_path)
    if not source:
        return

    extras: list[str] = []

    # Check if the envied object's type is defined in the same file
    tree = _safe_parse(source)
    if tree:
        local_classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        if local_classes:
            extras.append(
                f"\nClasses in this file: {', '.join(f'`{c}`' for c in local_classes[:5])}"
            )

    # Check imports to find where the envied type might live
    for line in source.splitlines()[:50]:
        stripped = line.strip()
        if envied in stripped and (
            stripped.startswith("from ") or stripped.startswith("import ")
        ):
            extras.append(f"\nImport of `{envied}`: `{stripped}`")
            break

    extras.append(
        f"\nConsider moving this logic to `{envied}`'s class as a method, "
        f"or restructuring so `{envied}` exposes a higher-level API."
    )

    _append_enrichment_message(finding, extras)


def _enrich_thin_wrapper(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-CODE-013 with the actual wrapped call for easy inlining."""
    meta = finding.metadata
    func_name = meta.get("function", "")
    path_str = meta.get("path", "")
    if not func_name or not path_str:
        return

    full_path = _resolve_path(path_str, ctx.config.root)
    source = _safe_read(full_path)
    if not source:
        return

    extras: list[str] = []

    # Find callers of this wrapper in the same file
    call_count = source.count(f"{func_name}(")
    if call_count > 1:
        # subtract the definition itself
        extras.append(
            f"\n`{func_name}` is called ~{call_count - 1} time(s) in this file."
        )
        extras.append(
            f"Replace each `{func_name}(...)` call with a direct call to the wrapped "
            f"function, then remove the wrapper."
        )
    else:
        extras.append(
            f"\n`{func_name}` appears to be called from other files. "
            f"Search for all usages before inlining."
        )

    _append_enrichment_message(finding, extras)


# ---------------------------------------------------------------------------
# Regex rule enrichers (PY-EXC-*, PY-LOG-*, PY-QUALITY-*)
# ---------------------------------------------------------------------------


def _enrich_silent_except(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-EXC-002 with specific exception types to catch."""
    paths = finding.metadata.get("hits", [])
    if not paths:
        return

    # Scan content for function calls inside try blocks
    content = ""
    for ct in ctx.content_targets:
        content = ct.content
        break

    extras: list[str] = []

    if content:
        # Extract function names called inside the try block
        tree = _safe_parse(content)
        if tree:
            called_funcs: list[str] = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Try):
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            if isinstance(child.func, ast.Name):
                                called_funcs.append(child.func.id)
                            elif isinstance(child.func, ast.Attribute):
                                called_funcs.append(child.func.attr)
            if called_funcs:
                unique = list(dict.fromkeys(called_funcs))[:5]
                extras.append(
                    f"\nFunctions called in try block: {', '.join(f'`{f}`' for f in unique)}"
                )
                extras.append(
                    "Check what exceptions these functions raise and catch those specifically."
                )

    extras.append(
        "\nCommon specific exceptions:\n"
        "  • File I/O: `FileNotFoundError`, `PermissionError`, `IsADirectoryError`\n"
        "  • Network: `ConnectionError`, `TimeoutError`, `httpx.HTTPError`\n"
        "  • Parsing: `json.JSONDecodeError`, `ValueError`, `KeyError`\n"
        "  • Encoding: `UnicodeDecodeError`, `UnicodeEncodeError`"
    )

    _append_enrichment_message(finding, extras)


def _enrich_stdlib_logger(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-LOG-001 by finding the project's actual logger abstraction."""
    root = ctx.config.root
    extras: list[str] = []

    # Search for common logger module patterns
    candidates = [
        root / "src" / "logger.py",
        root / "src" / "log.py",
        root / "src" / "logging_config.py",
        root / "src" / "utils" / "logger.py",
        root / "src" / "utils" / "logging.py",
        root / "src" / "core" / "logger.py",
        root / "lib" / "logger.py",
        root / "app" / "logger.py",
    ]

    # Also check for structlog or loguru in dependencies
    log_libs: list[str] = []
    for name in ("structlog", "loguru"):
        for req in root.glob("requirements*.txt"):
            if name in _safe_read(req, max_bytes=10_000).lower():
                log_libs.append(name)
                break
        if name not in log_libs:
            pyproject = _safe_read(root / "pyproject.toml", max_bytes=30_000)
            if name in pyproject.lower():
                log_libs.append(name)

    if log_libs:
        extras.append(f"\nProject uses: {', '.join(log_libs)}")
        if "structlog" in log_libs:
            extras.append(
                "  Import with: `import structlog; logger = structlog.get_logger()`"
            )
        if "loguru" in log_libs:
            extras.append("  Import with: `from loguru import logger`")

    # Check for project logger module
    for candidate in candidates:
        if candidate.exists():
            rel = (
                str(candidate.relative_to(root))
                if _is_under(candidate, root)
                else str(candidate)
            )
            extras.append(f"\nProject logger found at: `{rel}`")
            # Try to find the import pattern
            content = _safe_read(candidate, max_bytes=5_000)
            if content:
                for line in content.splitlines()[:30]:
                    stripped = line.strip()
                    if (
                        "get_logger" in stripped
                        or "getLogger" in stripped
                        or "logger" in stripped.lower()
                    ):
                        if (
                            stripped.startswith("def ")
                            or stripped.startswith("class ")
                            or "=" in stripped
                        ):
                            extras.append(f"  Pattern: `{stripped[:100]}`")
                            break
            break

    if not extras:
        extras.append(
            "\nNo project logger abstraction found. Consider creating one, "
            "or use structlog/loguru instead of stdlib logging."
        )

    _append_enrichment_message(finding, extras)


def _enrich_type_suppression(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-TYPE-002 with the specific suppression and fix hints."""
    content = ""
    for ct in ctx.content_targets:
        content = ct.content
        break

    if not content:
        return

    extras: list[str] = []

    # Detect which specific suppression was used
    suppressions = []
    for line in content.splitlines():
        if "# type: ignore" in line:
            # Extract the error code if present
            m = re.search(r"#\s*type:\s*ignore\[([^\]]+)\]", line)
            if m:
                suppressions.append(f"type: ignore[{m.group(1)}]")
            else:
                suppressions.append("type: ignore (no error code)")
        elif "# noqa" in line:
            m = re.search(r"#\s*noqa:\s*(\S+)", line)
            if m:
                suppressions.append(f"noqa: {m.group(1)}")
            else:
                suppressions.append("noqa (no code)")
        elif "# pylint: disable" in line:
            m = re.search(r"#\s*pylint:\s*disable=(\S+)", line)
            if m:
                suppressions.append(f"pylint: disable={m.group(1)}")

    if suppressions:
        extras.append(f"\nSuppression(s) found: {', '.join(suppressions[:3])}")

    # Give specific fix advice based on the error code
    for s in suppressions:
        if "arg-type" in s:
            extras.append(
                "  → `arg-type`: The argument type doesn't match. Add an overload or cast."
            )
        elif "return-value" in s:
            extras.append(
                "  → `return-value`: Narrow the return type or add a type guard."
            )
        elif "assignment" in s:
            extras.append(
                "  → `assignment`: Use a wider type annotation or restructure the code."
            )
        elif "union-attr" in s:
            extras.append(
                "  → `union-attr`: Narrow the union with isinstance() before accessing the attribute."
            )
        elif "override" in s:
            extras.append(
                "  → `override`: Match the parent's signature exactly or use covariant return types."
            )
        elif "no-untyped-def" in s:
            extras.append(
                "  → `no-untyped-def`: Add type annotations to all parameters and return type."
            )

    _append_enrichment_message(finding, extras)


def _enrich_magic_numbers(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-QUALITY-010 by finding the project's constants module."""
    root = ctx.config.root
    extras: list[str] = []

    paths = finding.metadata.get("hits", [])
    if paths:
        file_path = _resolve_path(paths[0], root)
        file_dir = file_path.parent

        # Look for constants.py in same directory or parent
        for search_dir in [file_dir, file_dir.parent, root / "src"]:
            for name in ("constants.py", "config.py", "settings.py", "defaults.py"):
                candidate = search_dir / name
                if candidate.exists() and candidate != file_path:
                    rel = (
                        str(candidate.relative_to(root))
                        if _is_under(candidate, root)
                        else str(candidate)
                    )
                    extras.append(f"\nDefine constants in: `{rel}`")
                    break
            if extras:
                break

    if not extras:
        extras.append(
            "\nCreate a `constants.py` in the same package and define named constants there:\n"
            "    MAX_RETRIES = 3\n"
            "    TIMEOUT_SECONDS = 30\n"
            "    DEFAULT_PAGE_SIZE = 50"
        )

    _append_enrichment_message(finding, extras)


def _enrich_hardcoded_paths(finding: "RuleFinding", ctx: "HookContext") -> None:
    """Enrich PY-QUALITY-009 by showing how the project resolves paths."""
    root = ctx.config.root
    extras: list[str] = []

    # Look for existing path configuration patterns
    for name in ("config.py", "settings.py", "constants.py", "paths.py"):
        for search_dir in [
            root / "src",
            root / "src" / "utils",
            root / "src" / "core",
            root,
        ]:
            candidate = search_dir / name
            if candidate.exists():
                content = _safe_read(candidate, max_bytes=10_000)
                # Check for Path or pathlib usage
                if (
                    "pathlib" in content
                    or "Path(" in content
                    or "BASE_DIR" in content
                    or "ROOT_DIR" in content
                ):
                    rel = (
                        str(candidate.relative_to(root))
                        if _is_under(candidate, root)
                        else str(candidate)
                    )
                    extras.append(f"\nPath configuration found in: `{rel}`")
                    # Extract path-related constants
                    for line in content.splitlines():
                        stripped = line.strip()
                        if (
                            "DIR" in stripped
                            or "PATH" in stripped
                            or "ROOT" in stripped
                        ) and "=" in stripped:
                            if not stripped.startswith("#"):
                                extras.append(f"  {stripped[:100]}")
                                if len(extras) >= 5:
                                    break
                    break
        if extras:
            break

    if not extras:
        extras.append(
            "\nUse pathlib for portable path resolution:\n"
            "    from pathlib import Path\n"
            "    BASE_DIR = Path(__file__).resolve().parent.parent\n"
            '    DATA_DIR = BASE_DIR / "data"\n'
            "\nOr use environment variables:\n"
            "    import os\n"
            '    DATA_DIR = Path(os.environ.get("DATA_DIR", "./data"))'
        )

    _append_enrichment_message(finding, extras)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_ENRICHERS: dict[str, object] = {
    # Test rules
    "PY-TEST-003": _enrich_test_loop,
    "PY-TEST-001": _enrich_assertion_roulette,
    "PY-TEST-002": _enrich_test_smells,
    "PY-TEST-004": _enrich_fixture_outside_conftest,
    # Type rules
    "PY-TYPE-001": _enrich_python_any,
    "PY-TYPE-002": _enrich_type_suppression,
    # AST code quality rules
    "PY-CODE-008": _enrich_long_method,
    "PY-CODE-009": _enrich_long_params,
    "PY-CODE-012": _enrich_feature_envy,
    "PY-CODE-013": _enrich_thin_wrapper,
    "PY-CODE-015": _enrich_cyclomatic_complexity,
    # Other code quality rules
    "PY-EXC-002": _enrich_silent_except,
    "PY-LOG-001": _enrich_stdlib_logger,
    "PY-QUALITY-009": _enrich_hardcoded_paths,
    "PY-QUALITY-010": _enrich_magic_numbers,
}


def enrich_findings(findings: list["RuleFinding"], ctx: "HookContext") -> None:
    """Enrich findings in-place with project-specific context.

    Best-effort: enrichment failures are captured into additional context
    while keeping the hook pipeline running.
    """
    for finding in findings:
        enricher = _ENRICHERS.get(finding.rule_id)
        if not callable(enricher):
            continue
        typed_enricher = cast(Callable[..., None], enricher)
        try:
            typed_enricher(finding, ctx)
        except (
            AttributeError,
            KeyError,
            OSError,
            SyntaxError,
            TypeError,
            ValueError,
        ) as exc:
            # Preserve hook flow while making enrichment failures explicit.
            existing = finding.additional_context or ""
            detail = f"Enrichment skipped due to {type(exc).__name__}."
            finding.additional_context = (existing + "\n" + detail).strip()
