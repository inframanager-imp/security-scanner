"""
Phase 1 continued: builds a same-repo call graph from the functions
ast_parser.py extracted.

Resolution is name-based, not full type/scope resolution (that needs a real
type checker, out of scope here): a call site `foo(...)` resolves to any
function named `foo` anywhere in the repo; `self.bar(...)` / `obj.bar(...)`
resolves to any method named `bar` on any class. This means a same-named
function in an unrelated module can produce a spurious edge — a real but
bounded imprecision, same category as LVRP's own documented limits (dynamic
dispatch, reflection) rather than a correctness bug. Cross-file edges work
today because resolution is name-based rather than import-based; real
import-resolution (only follow edges to functions actually imported/visible
at the call site) is Phase 3, where it meaningfully cuts false edges.
"""
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set
import ast

from .ast_parser import FunctionInfo, ParsedFile


@dataclass
class CallSite:
    caller_qualname: str
    callee_name: str        # the bare name as written at the call site — "foo" or "bar" from self.bar()
    lineno: int
    is_method_call: bool    # True for self.x()/obj.x(), False for bare x()


@dataclass
class CallGraph:
    functions: Dict[str, FunctionInfo] = field(default_factory=dict)   # qualname -> FunctionInfo
    by_name: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))     # bare function name -> [qualnames]
    by_method_name: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))  # bare method name -> [qualnames]
    edges: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))          # caller qualname -> {callee qualnames}
    call_sites: Dict[str, List[CallSite]] = field(default_factory=lambda: defaultdict(list))  # caller qualname -> [CallSite]

    def callees_of(self, qualname: str) -> Set[str]:
        return self.edges.get(qualname, set())

    def callers_of(self, qualname: str) -> List[str]:
        return [caller for caller, callees in self.edges.items() if qualname in callees]


def _extract_call_sites(func: FunctionInfo) -> List[CallSite]:
    sites: List[CallSite] = []
    for node in ast.walk(func.node):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        if isinstance(callee, ast.Name):
            sites.append(CallSite(func.qualname, callee.id, node.lineno, is_method_call=False))
        elif isinstance(callee, ast.Attribute):
            sites.append(CallSite(func.qualname, callee.attr, node.lineno, is_method_call=True))
    return sites


def build_call_graph(parsed_files: List[ParsedFile]) -> CallGraph:
    graph = CallGraph()

    all_functions = [f for pf in parsed_files for f in pf.functions]
    for f in all_functions:
        graph.functions[f.qualname] = f
        graph.by_name[f.name].append(f.qualname)
        if f.is_method:
            graph.by_method_name[f.name].append(f.qualname)

    for f in all_functions:
        sites = _extract_call_sites(f)
        graph.call_sites[f.qualname] = sites
        for site in sites:
            candidates = (
                graph.by_method_name.get(site.callee_name, [])
                if site.is_method_call
                else graph.by_name.get(site.callee_name, [])
            )
            if not candidates and not site.is_method_call:
                candidates = graph.by_name.get(site.callee_name, []) or graph.by_method_name.get(site.callee_name, [])
            for callee_qualname in candidates:
                if callee_qualname != f.qualname:  # skip trivial self-recursion edges for now — not useful for taint routing
                    graph.edges[f.qualname].add(callee_qualname)

    return graph
