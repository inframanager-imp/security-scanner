"""
Phase 1 of real taint tracking (see taint/__init__.py roadmap in the PR
description / session notes): parses Python source into function-level
units the rest of the taint package operates on.

Deliberately Python-only for now via the stdlib `ast` module — zero new
dependencies, and this is the language this backend itself is written in,
so correctness is directly checkable against real code. JS/TS support
(Phase 4) needs an actual JS parser (tree-sitter or esprima), which is a
separate, larger addition.

This does NOT do taint propagation — it's purely structural extraction
(functions, their call sites, their qualified names). Source/sink/sanitizer
tagging lives in tags.py; call graph construction lives in call_graph.py;
propagation is Phase 2+.
"""
import ast
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class FunctionInfo:
    qualname: str          # "module.ClassName.method_name" or "module.function_name"
    name: str               # bare function name
    file_path: str          # relative path within the scanned repo
    lineno: int
    end_lineno: int
    node: ast.AST            # the ast.FunctionDef / AsyncFunctionDef node
    params: List[str] = field(default_factory=list)
    is_method: bool = False
    class_name: Optional[str] = None


@dataclass
class ParsedFile:
    file_path: str
    tree: Optional[ast.Module]
    functions: List[FunctionInfo]
    parse_error: Optional[str] = None


def _module_name(file_path: str) -> str:
    """'app/routes/users.py' -> 'app.routes.users' — used as the qualname
    prefix so functions with the same name in different files don't collide."""
    without_ext = file_path[:-3] if file_path.endswith(".py") else file_path
    return without_ext.replace(os.sep, ".").replace("/", ".").strip(".")


def parse_python_source(source: str, file_path: str) -> ParsedFile:
    """Parses one file's source into a ParsedFile. Never raises — a syntax
    error (e.g. Python 2 source, or a genuinely malformed file) is recorded
    as parse_error and the file is simply excluded from the call graph/tags,
    same fail-open-on-one-file philosophy as the rest of this codebase's
    scanners (one bad file shouldn't abort the whole analysis)."""
    try:
        tree = ast.parse(source, filename=file_path)
    except (SyntaxError, ValueError) as e:
        return ParsedFile(file_path=file_path, tree=None, functions=[], parse_error=str(e))

    module_name = _module_name(file_path)
    functions = extract_functions(tree, module_name, file_path)
    return ParsedFile(file_path=file_path, tree=tree, functions=functions)


def _params_of(node) -> List[str]:
    args = node.args
    names = [a.arg for a in args.posonlyargs] if hasattr(args, "posonlyargs") else []
    names += [a.arg for a in args.args]
    if args.vararg:
        names.append(f"*{args.vararg.arg}")
    names += [a.arg for a in args.kwonlyargs]
    if args.kwarg:
        names.append(f"**{args.kwarg.arg}")
    return names


def extract_functions(tree: ast.Module, module_name: str, file_path: str) -> List[FunctionInfo]:
    """Walks the module top-down, tracking class nesting so methods get a
    proper 'module.Class.method' qualname instead of colliding with a
    module-level function of the same name."""
    functions: List[FunctionInfo] = []

    def visit(node: ast.AST, class_stack: List[str]):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, class_stack + [child.name])
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                class_name = class_stack[-1] if class_stack else None
                qualname_parts = [module_name] + class_stack + [child.name]
                functions.append(FunctionInfo(
                    qualname=".".join(p for p in qualname_parts if p),
                    name=child.name,
                    file_path=file_path,
                    lineno=child.lineno,
                    end_lineno=getattr(child, "end_lineno", child.lineno),
                    node=child,
                    params=_params_of(child),
                    is_method=class_name is not None,
                    class_name=class_name,
                ))
                visit(child, class_stack)

    visit(tree, [])
    return functions


def parse_repo(scan_dir: str, skip_dirs: set, max_file_bytes: int = 500_000) -> List[ParsedFile]:
    """Parses every .py file under scan_dir (excluding skip_dirs), returning
    one ParsedFile per file. This is the entry point call_graph.py and
    tags.py build on."""
    results: List[ParsedFile] = []
    for root, dirs, files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            try:
                if os.path.getsize(fpath) > max_file_bytes:
                    continue
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    source = fh.read()
            except OSError:
                continue
            rel_path = os.path.relpath(fpath, scan_dir).replace("\\", "/")
            results.append(parse_python_source(source, rel_path))
    return results
