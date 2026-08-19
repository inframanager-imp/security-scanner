"""
Phase 1 entry point — ties ast_parser + call_graph + tags together into one
report, matching the shape of LVRP's "Step 3b: Code Graph Construction"
(the deterministic foundation step, run before any path enumeration or
propagation exists). This module makes NO exploitability claims — it's
infrastructure: parse, build the call graph, tag sources/sinks/sanitizers.
Whether a tagged source actually reaches a tagged sink is Phase 2
(propagation), not yet implemented.
"""
import os
from dataclasses import dataclass, field
from typing import Dict, List

from .ast_parser import ParsedFile, parse_repo
from .call_graph import CallGraph, build_call_graph
from .tags import TagHit, tag_function

_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
              ".tox", "site-packages", "migrations", "test", "tests"}


@dataclass
class CodeGraphReport:
    files_parsed: int
    files_with_errors: int
    functions_analyzed: int
    call_graph_edges: int
    sources: List[Dict] = field(default_factory=list)
    sinks: List[Dict] = field(default_factory=list)
    sanitizers: List[Dict] = field(default_factory=list)
    parse_errors: List[Dict] = field(default_factory=list)


def build_code_graph(scan_dir: str, skip_dirs: set = None) -> tuple:
    """Returns (CallGraph, CodeGraphReport). The CallGraph is the reusable
    structure Phase 2+ will walk for propagation; the report is a
    human/API-facing summary of what was found, same spirit as
    scanners.quality_report() for chunking."""
    parsed_files: List[ParsedFile] = parse_repo(scan_dir, skip_dirs or _SKIP_DIRS)
    graph = build_call_graph(parsed_files)

    sources, sinks, sanitizers = [], [], []
    for func in graph.functions.values():
        for hit in tag_function(func):
            entry = {
                "function": func.qualname, "file": func.file_path, "line": hit.lineno,
                "kind": hit.kind, "detail": hit.detail,
            }
            if hit.category == "source":
                sources.append(entry)
            elif hit.category == "sink":
                entry["cwe"] = hit.cwe
                sinks.append(entry)
            else:
                sanitizers.append(entry)

    parse_errors = [{"file": pf.file_path, "error": pf.parse_error} for pf in parsed_files if pf.parse_error]
    edge_count = sum(len(callees) for callees in graph.edges.values())

    report = CodeGraphReport(
        files_parsed=len([pf for pf in parsed_files if pf.parse_error is None]),
        files_with_errors=len(parse_errors),
        functions_analyzed=len(graph.functions),
        call_graph_edges=edge_count,
        sources=sources, sinks=sinks, sanitizers=sanitizers,
        parse_errors=parse_errors,
    )
    return graph, report
