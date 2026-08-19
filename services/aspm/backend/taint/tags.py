"""
Phase 1 continued: tags AST nodes within each function as a taint SOURCE
(untrusted input entry point), SINK (dangerous operation), or SANITIZER
(a call that neutralizes taint for a specific vulnerability class).

This is deliberately conservative — every pattern here is something with a
well-known, unambiguous meaning (request.args IS untrusted input; eval() IS
a code-exec sink) rather than heuristic pattern-matching prone to false
positives. Phase 2 (propagation) is what actually decides whether a
tainted SOURCE reaches a SINK without passing through a SANITIZER; tagging
alone makes no exploitability claim.
"""
import ast
from dataclasses import dataclass
from typing import List, Optional

from .ast_parser import FunctionInfo


@dataclass
class TagHit:
    category: str          # "source" | "sink" | "sanitizer"
    kind: str               # short label, e.g. "flask_request_args", "eval_exec"
    cwe: Optional[str]       # only set for sinks
    lineno: int
    node: ast.AST
    detail: str              # human-readable, e.g. "request.args (Flask query params)"


_SOURCE_ATTRS = [
    (("request", "args"), "Flask/Django query parameters"),
    (("request", "form"), "Flask form data"),
    (("request", "json"), "Flask/FastAPI JSON body"),
    (("request", "values"), "Flask combined args+form"),
    (("request", "data"), "raw request body"),
    (("request", "cookies"), "request cookies"),
    (("request", "headers"), "request headers"),
    (("request", "files"), "uploaded files"),
    (("request", "GET"), "Django query parameters"),
    (("request", "POST"), "Django form data"),
    (("request", "body"), "Django raw request body"),
    (("sys", "argv"), "command-line arguments"),
]
_SOURCE_CALLS = {"input": "interactive stdin input", "raw_input": "interactive stdin input (Python 2)"}
_SOURCE_ENV_CALLS = {"getenv"}  # os.getenv(...) — environment is untrusted in a multi-tenant/shared context

# ── Sinks: (call name or attr suffix) -> (cwe, label) ────────────────────────
_SINK_CALLS = {
    "eval": ("CWE-95", "eval() — arbitrary code execution"),
    "exec": ("CWE-95", "exec() — arbitrary code execution"),
    "system": ("CWE-78", "os.system() — OS command execution"),
    "popen": ("CWE-78", "os.popen()/subprocess.Popen — OS command execution"),
    "getoutput": ("CWE-78", "commands.getoutput() — OS command execution"),
    "render_template_string": ("CWE-79", "Flask render_template_string — SSTI/XSS if template is user-influenced"),
}
_SINK_EXECUTE_METHODS = {"execute", "executemany"}  # cursor.execute — CWE-89, tagged separately (needs arg-shape check)
_UNSAFE_DESERIALIZE_MODULES = {"pickle", "marshal", "yaml"}


def _attr_chain(node: ast.AST) -> List[str]:
    """`request.args.get` -> ['request', 'args', 'get'] (innermost first is
    actually outermost-first here — the base name comes first)."""
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return list(reversed(parts))


def _is_dynamic_string(node: ast.AST) -> bool:
    """True if node builds a string at runtime from variable data — f-string,
    %-formatting, .format(), or + concatenation — as opposed to a plain
    string literal or a placeholder-style parameterized query string."""
    if isinstance(node, ast.JoinedStr):  # f-string
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def tag_function(func: FunctionInfo) -> List[TagHit]:
    hits: List[TagHit] = []
    for node in ast.walk(func.node):
        if isinstance(node, ast.Attribute):
            chain = _attr_chain(node)
            for suffix, label in _SOURCE_ATTRS:
                if len(chain) >= len(suffix) and tuple(chain[-len(suffix):]) == suffix:
                    hits.append(TagHit("source", "_".join(suffix), None, node.lineno, node, label))
                    break

        elif isinstance(node, ast.Call):
            func_node = node.func
            call_name = func_node.id if isinstance(func_node, ast.Name) else (
                func_node.attr if isinstance(func_node, ast.Attribute) else None
            )
            if call_name is None:
                continue

            if call_name in _SOURCE_CALLS:
                hits.append(TagHit("source", call_name, None, node.lineno, node, _SOURCE_CALLS[call_name]))
            elif call_name in _SOURCE_ENV_CALLS and isinstance(func_node, ast.Attribute):
                chain = _attr_chain(func_node)
                if chain[:1] == ["os"]:
                    hits.append(TagHit("source", "os_getenv", None, node.lineno, node, "environment variable"))

            if call_name in _SINK_CALLS:
                cwe, label = _SINK_CALLS[call_name]
                hits.append(TagHit("sink", call_name, cwe, node.lineno, node, label))
            elif call_name in {"load", "loads"} and isinstance(func_node, ast.Attribute):
                chain = _attr_chain(func_node)
                if chain[:1] and chain[0] in _UNSAFE_DESERIALIZE_MODULES:
                    hits.append(TagHit("sink", f"{chain[0]}_{call_name}", "CWE-502", node.lineno, node,
                                        f"{chain[0]}.{call_name}() — insecure deserialization"))
            elif call_name in _SINK_EXECUTE_METHODS and node.args:
                query_arg = node.args[0]
                dynamic = _is_dynamic_string(query_arg)
                if dynamic:
                    hits.append(TagHit("sink", "sql_execute_dynamic", "CWE-89", node.lineno, node,
                                        "cursor.execute() with a dynamically-built query string"))
                else:
                    hits.append(TagHit("sanitizer", "parameterized_query", None, node.lineno, node,
                                        "cursor.execute() called with a static/placeholder query — parameterized shape"))

            if call_name in {"run", "call", "check_call", "check_output", "Popen"}:
                shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                if shell_true:
                    hits.append(TagHit("sink", "subprocess_shell_true", "CWE-78", node.lineno, node,
                                        f"subprocess.{call_name}(..., shell=True) — OS command execution"))

            # ── Sanitizers ──
            if call_name == "quote" and isinstance(func_node, ast.Attribute):
                chain = _attr_chain(func_node)
                if chain[:1] == ["shlex"]:
                    hits.append(TagHit("sanitizer", "shlex_quote", None, node.lineno, node,
                                        "shlex.quote() — neutralizes shell metacharacters (protects CWE-78)"))
            if call_name == "escape":
                hits.append(TagHit("sanitizer", "escape", None, node.lineno, node,
                                    "html/markupsafe/re .escape() — neutralizes markup/regex metacharacters"))
            if call_name in {"int", "float"}:
                hits.append(TagHit("sanitizer", "numeric_cast", None, node.lineno, node,
                                    f"{call_name}() cast — implicitly rejects non-numeric input"))

    return hits
