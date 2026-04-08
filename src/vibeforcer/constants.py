from __future__ import annotations

EDIT_TOOL_NAMES = {
    "edit",
    "write",
    "multiedit",
    "notebookedit",
    "patch",
    "applypatch",
    "apply_patch",
}

READ_TOOL_NAMES = {"read", "grep", "glob", "webfetch", "websearch"}

SAFE_READ_SHELL_VERBS = {
    "cat",
    "less",
    "more",
    "head",
    "tail",
    "grep",
    "egrep",
    "fgrep",
    "zgrep",
    "wc",
    "file",
    "stat",
    "ls",
    "find",
    "awk",
    "sort",
    "uniq",
    "diff",
    "cmp",
    "md5sum",
    "sha256sum",
    "hexdump",
    "strings",
    "od",
}

SHELL_REDIRECT_PATTERNS = (">", ">>", "|", "tee")
SELFTEST_SEPARATOR_WIDTH = 40
MAX_LINT_VIOLATIONS_SHOWN = 5
EXIT_KEYBOARD_INTERRUPT = 130

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyi": "python",
    ".js": "js_ts",
    ".jsx": "js_ts",
    ".ts": "js_ts",
    ".tsx": "js_ts",
    ".mjs": "js_ts",
    ".cjs": "js_ts",
    ".rs": "rust",
}
