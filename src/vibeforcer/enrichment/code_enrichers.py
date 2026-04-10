"""Enrichment handlers for AST-based code quality rule IDs."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import TYPE_CHECKING

from vibeforcer.enrichment._helpers import (
    _append_enrichment_message,
    _resolve_path,
    _safe_parse,
    _safe_read,
)

if TYPE_CHECKING:
    from pathlib import Path

    from vibeforcer.context import HookContext
    from vibeforcer.models import RuleFinding


FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True)
class _TargetFunction:
    path: Path
    tree: ast.Module
    node: FunctionNode


@dataclass(frozen=True)
class _ComplexityBreakdown:
    ifs: int
    loops: int
    excepts: int
    boolops: int


def _metadata_str(metadata: dict[str, object], key: str) -> str | None:
    value = metadata.get(key)
    return value if isinstance(value, str) and value else None


def _find_function_node(tree: ast.Module, func_name: str) -> FunctionNode | None:
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == func_name
        ):
            return node
    return None


def _load_target_function(
    finding: RuleFinding,
    ctx: HookContext,
) -> _TargetFunction | None:
    path_str = _metadata_str(finding.metadata, "path")
    func_name = _metadata_str(finding.metadata, "function")
    if path_str is None or func_name is None:
        return None
    full_path = _resolve_path(path_str, ctx.config.root)
    source = _safe_read(full_path)
    if not source:
        return None
    tree = _safe_parse(source)
    if tree is None:
        return None
    node = _find_function_node(tree, func_name)
    if node is None:
        return None
    return _TargetFunction(path=full_path, tree=tree, node=node)


def _block_description(node: ast.stmt) -> str | None:
    node_type = type(node)
    if node_type is ast.If:
        return f"  • if-block at line {node.lineno}"
    if node_type in (ast.For, ast.AsyncFor):
        return f"  • loop at line {node.lineno}"
    if node_type is ast.With:
        return f"  • with-block at line {node.lineno}"
    if node_type is ast.Try:
        return f"  • try-block at line {node.lineno}"
    return None


def _collect_long_method_blocks(node: FunctionNode) -> list[str]:
    blocks: list[str] = []
    for child in node.body:
        description = _block_description(child)
        if description is not None:
            blocks.append(description)
    return blocks


def _collect_nested_function_names(node: FunctionNode) -> list[str]:
    return [
        child.name
        for child in ast.iter_child_nodes(node)
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def _build_long_method_extras(node: FunctionNode) -> list[str]:
    blocks = _collect_long_method_blocks(node)
    nested = _collect_nested_function_names(node)
    extras: list[str] = []
    if blocks:
        extras.append("\nFunction structure (potential extraction points):")
        extras.extend(blocks[:8])
    if nested:
        names = ", ".join(f"`{name}`" for name in nested[:5])
        extras.append(f"\nNested functions: {names}")
    extras.append(
        "\nSplit strategy: extract each logical block into a named helper "
        "that does one thing. The parent function becomes an orchestrator."
    )
    return extras


def _parameter_names(node: FunctionNode) -> list[str]:
    args = (
        list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
    )
    return [arg.arg for arg in args if arg.arg not in ("self", "cls")]


def _decorator_is_dataclass(decorator: ast.expr) -> bool:
    if isinstance(decorator, ast.Name):
        return decorator.id == "dataclass"
    return isinstance(decorator, ast.Attribute) and decorator.attr == "dataclass"


def _base_name(base: ast.expr) -> str:
    if isinstance(base, ast.Name):
        return base.id
    if isinstance(base, ast.Attribute):
        return base.attr
    return ""


def _grouped_type_hints(tree: ast.Module) -> list[str]:
    grouped: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        if any(_decorator_is_dataclass(dec) for dec in node.decorator_list):
            grouped.append(f"`{node.name}` (dataclass)")
            continue
        for base in node.bases:
            base_name = _base_name(base)
            if base_name in ("TypedDict", "NamedTuple"):
                grouped.append(f"`{node.name}` ({base_name})")
                break
    return grouped


def _build_long_params_extras(
    param_names: list[str],
    grouped_types: list[str],
) -> list[str]:
    extras: list[str] = []
    if param_names:
        extras.append(f"\nParameters: {', '.join(f'`{name}`' for name in param_names)}")
    if grouped_types:
        extras.append(
            "\nExisting parameter grouping patterns in this file: "
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
    return extras


def _complexity_delta(node: ast.AST) -> _ComplexityBreakdown:
    if isinstance(node, (ast.If, ast.IfExp)):
        return _ComplexityBreakdown(ifs=1, loops=0, excepts=0, boolops=0)
    if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
        return _ComplexityBreakdown(ifs=0, loops=1, excepts=0, boolops=0)
    if isinstance(node, ast.ExceptHandler):
        return _ComplexityBreakdown(ifs=0, loops=0, excepts=1, boolops=0)
    if isinstance(node, ast.BoolOp):
        return _ComplexityBreakdown(
            ifs=0, loops=0, excepts=0, boolops=len(node.values) - 1
        )
    return _ComplexityBreakdown(ifs=0, loops=0, excepts=0, boolops=0)


def _count_complexity_sources(node: FunctionNode) -> _ComplexityBreakdown:
    ifs = 0
    loops = 0
    excepts = 0
    boolops = 0
    for child in ast.walk(node):
        delta = _complexity_delta(child)
        ifs += delta.ifs
        loops += delta.loops
        excepts += delta.excepts
        boolops += delta.boolops
    return _ComplexityBreakdown(ifs=ifs, loops=loops, excepts=excepts, boolops=boolops)


def _complexity_breakdown_lines(breakdown: _ComplexityBreakdown) -> list[str]:
    parts: list[str] = []
    if breakdown.ifs:
        parts.append(f"{breakdown.ifs} if/elif branches")
    if breakdown.loops:
        parts.append(f"{breakdown.loops} loops")
    if breakdown.excepts:
        parts.append(f"{breakdown.excepts} except handlers")
    if breakdown.boolops:
        parts.append(f"{breakdown.boolops} boolean operators (and/or)")
    return parts


def _complexity_tips(breakdown: _ComplexityBreakdown) -> list[str]:
    tips: list[str] = []
    if breakdown.ifs >= 4:
        tips.append(
            "\nTIP: Multiple if/elif branches → consider a dispatch dict, "
            "strategy pattern, or match/case (Python 3.10+)."
        )
    if breakdown.loops >= 2:
        tips.append(
            "\nTIP: Multiple loops → extract each loop body into a named function."
        )
    return tips


def _enrich_long_method(finding: RuleFinding, ctx: HookContext) -> None:
    """Enrich long-method findings with block structure hints."""
    target = _load_target_function(finding, ctx)
    if target is None:
        return
    _append_enrichment_message(finding, _build_long_method_extras(target.node))


def _enrich_long_params(finding: RuleFinding, ctx: HookContext) -> None:
    """Enrich too-many-params findings with grouping suggestions."""
    target = _load_target_function(finding, ctx)
    if target is None:
        return
    param_names = _parameter_names(target.node)
    grouped_types = _grouped_type_hints(target.tree)
    extras = _build_long_params_extras(param_names, grouped_types)
    _append_enrichment_message(finding, extras)


def _enrich_cyclomatic_complexity(finding: RuleFinding, ctx: HookContext) -> None:
    """Enrich complexity findings with a branch breakdown."""
    target = _load_target_function(finding, ctx)
    if target is None:
        return
    breakdown = _count_complexity_sources(target.node)
    parts = _complexity_breakdown_lines(breakdown)
    extras: list[str] = []
    if parts:
        extras.append(f"\nComplexity breakdown: {', '.join(parts)}")
    extras.extend(_complexity_tips(breakdown))
    _append_enrichment_message(finding, extras)


def _enrich_feature_envy(finding: RuleFinding, ctx: HookContext) -> None:
    """Enrich feature-envy findings with local class/import clues."""
    envied = _metadata_str(finding.metadata, "envied_object")
    path_str = _metadata_str(finding.metadata, "path")
    if envied is None or path_str is None:
        return
    full_path = _resolve_path(path_str, ctx.config.root)
    source = _safe_read(full_path)
    if not source:
        return
    extras: list[str] = []
    tree = _safe_parse(source)
    if tree is not None:
        local_classes = [
            node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
        ]
        if local_classes:
            extras.append(
                f"\nClasses in this file: {', '.join(f'`{name}`' for name in local_classes[:5])}"
            )
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


def _enrich_thin_wrapper(finding: RuleFinding, ctx: HookContext) -> None:
    """Enrich thin-wrapper findings with inlining guidance."""
    func_name = _metadata_str(finding.metadata, "function")
    path_str = _metadata_str(finding.metadata, "path")
    if func_name is None or path_str is None:
        return
    full_path = _resolve_path(path_str, ctx.config.root)
    source = _safe_read(full_path)
    if not source:
        return
    call_count = source.count(f"{func_name}(")
    extras: list[str] = []
    if call_count > 1:
        extras.append(
            f"\n`{func_name}` is called ~{call_count - 1} time(s) in this file."
        )
        extras.append(
            f"Replace each `{func_name}(...)` call with a direct call to the wrapped "
            "function, then remove the wrapper."
        )
    else:
        extras.append(
            f"\n`{func_name}` appears to be called from other files. Search for all usages before inlining."
        )
    _append_enrichment_message(finding, extras)
