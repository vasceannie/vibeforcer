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


# Canonical quality thresholds shared by runtime and lint defaults.
MAX_COMPLEXITY = 12
MAX_PARAMS = 4
MAX_METHOD_LINES = 50
MAX_NESTING_DEPTH = 4
MAX_GOD_CLASS_METHODS = 15
MAX_GOD_CLASS_LINES = 400


# Runtime quality-gate policy defaults.
RUNTIME_MAX_COMPLEXITY = MAX_COMPLEXITY
RUNTIME_MAX_NESTING_DEPTH = MAX_NESTING_DEPTH
RUNTIME_MAX_GOD_CLASS_METHODS = MAX_GOD_CLASS_METHODS
RUNTIME_MAX_LINE_LENGTH = 120
RUNTIME_FEATURE_ENVY_THRESHOLD = 0.60
RUNTIME_FEATURE_ENVY_MIN_ACCESSES = 6
RUNTIME_IMPORT_FANOUT_LIMIT = 5
RUNTIME_LONG_METHOD_LINES = MAX_METHOD_LINES
RUNTIME_LONG_PARAMETER_LIMIT = MAX_PARAMS
RUNTIME_MAX_PARSE_CHARS = 200000

# enrichment extraction defaults
ENRICHMENT_MAX_READ_BYTES = 100000
ENRICHMENT_FIXTURE_PARENT_DEPTH = 10
ENRICHMENT_MAX_FIXTURES = 10
ENRICHMENT_MAX_PARAMETRIZE_EXAMPLES = 3
ENRICHMENT_MAX_PARAMETRIZE_SNIPPET = 300


# Lint quality-gate policy defaults.
LINT_MAX_COMPLEXITY = MAX_COMPLEXITY
LINT_MAX_PARAMS = MAX_PARAMS
LINT_MAX_METHOD_LINES = MAX_METHOD_LINES
LINT_MAX_TEST_LINES = 35
LINT_MAX_MODULE_LINES_SOFT = 350
LINT_MAX_MODULE_LINES_HARD = 600
LINT_MAX_NESTING_DEPTH = MAX_NESTING_DEPTH
LINT_MAX_GOD_CLASS_METHODS = MAX_GOD_CLASS_METHODS
LINT_MAX_GOD_CLASS_LINES = MAX_GOD_CLASS_LINES
LINT_MAX_EAGER_TEST_CALLS = 7
LINT_MAX_REPEATED_MAGIC_NUMBERS = 5
LINT_MAX_REPEATED_STRING_LITERALS = 10
LINT_MAX_SCATTERED_HELPERS = 5
LINT_MAX_DUPLICATE_HELPER_SIGNATURES = 10
LINT_MAX_REPEATED_CODE_PATTERNS = 50
LINT_MIN_FUNCTION_BODY_LINES = 5
LINT_MIN_CALL_SEQUENCE_LENGTH = 3
LINT_MAX_LINE_LENGTH = 120
LINT_FEATURE_ENVY_THRESHOLD = 0.60
LINT_FEATURE_ENVY_MIN_ACCESSES = 6
LINT_MAX_CONSECUTIVE_BARE_ASSERTS = 3
LINT_BAN_CONDITIONAL_ASSERTIONS = True
LINT_BAN_FIXTURES_OUTSIDE_CONFTEXT = True

LINT_ALLOWED_NUMBERS = (0, 1, 2, 3, 4, 5, -1, 10, 100, 200, 255, 1000, 1024, 0.5)
LINT_ALLOWED_STRINGS = (
    "",
    " ",
    "\n",
    "\t",
    "utf-8",
    "r",
    "w",
    "rb",
    "wb",
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "id",
    "name",
    "type",
    "value",
    "text",
    "status",
)
