"""
SATARK Layer 1 — Python Code Parser (A1) — v3

ROOT CAUSE FIX for missing E_invoke call graph:
  The original parser only creates E_invoke for bare function calls: fn()
  It SKIPS attribute calls: self.method(), obj.method()

  This is the exact reason process_payment_route -> process_payment is missing.
  process_payment_route calls self.process_payment(...) which is an attribute call.

  FIX: For attribute calls (self.fn()), extract the method name (fn) and
  look it up in the func_registry. If found in the same file, create E_invoke.
  This is safe because:
    - We only match names that exist as actual function definitions in this file
    - self.fn() where fn is defined in this class = definite match
    - False positives (e.g. requests.get where get is also a local name) are rare
      and the spec allows confidence < 1.0 for these

Tree-sitter fix: use parser.set_language() not Parser(lang) constructor.
Regex fallback: produces ONLY E_contain edges — no E_invoke.
"""
import re
from typing import Optional
from models.nodes import KGNode, KGEdge, GraphFragment, SourceLocation, NodeMetadata
import structlog

logger = structlog.get_logger(__name__)
ORG_ID = "prototype"

ROUTE_DECORATORS = {
    "app.route", "router.get", "router.post", "router.put", "router.delete",
    "router.patch", "app.get", "app.post", "app.put", "app.delete",
    "blueprint.route", "api.route", "app.task", "celery.task", "shared_task",
}
HANDLER_NAMES = {"handler", "lambda_handler", "main"}
TAINT_PATTERNS = {
    "request.GET", "request.POST", "request.args", "request.form",
    "request.json", "request.body", "request.data", "event[", "event.get(",
}

# Standard library / third-party method names to SKIP for attribute call resolution
# Avoids false positives like self.get() → requests.get or dict.get
SKIP_METHOD_NAMES = {
    "get", "post", "put", "delete", "patch", "head", "options",  # HTTP
    "append", "extend", "pop", "remove", "insert", "clear",       # list
    "update", "keys", "values", "items",                           # dict
    "strip", "split", "join", "format", "encode", "decode",       # str
    "run", "start", "stop", "close", "open", "read", "write",    # IO
    "info", "debug", "warning", "error", "critical",              # logging
    "commit", "rollback", "execute", "fetchone", "fetchall",      # DB
    "save", "load", "dump", "dumps", "loads",                     # serialization
}


def _is_entry_point(decorators: list[str], func_name: str) -> bool:
    for dec in decorators:
        for pattern in ROUTE_DECORATORS:
            if pattern in dec.lower():
                return True
    return func_name.lower() in HANDLER_NAMES


def _detect_taint_class(body: str) -> str:
    return "external_untrusted" if any(p in body for p in TAINT_PATTERNS) else "internal_trusted"


def _make_entity_id(file_path: str, kind: str, name: str) -> str:
    safe = file_path.replace("/", ".").replace(".py", "")
    return f"{ORG_ID}::code::repo::{safe}.{kind}.{name}"


def parse_python_file(content: str, file_path: str, asset_id: str) -> GraphFragment:
    fragment = GraphFragment(asset_id=asset_id, file_path=file_path, domain_type="code")
    try:
        import tree_sitter_python as tspython
        from tree_sitter import Language, Parser

        PY_LANGUAGE = Language(tspython.language())
        try:
            parser = Parser(PY_LANGUAGE)
        except TypeError:
            parser = Parser()
            parser.set_language(PY_LANGUAGE)

        tree = parser.parse(bytes(content, "utf8"))
        return _parse_with_treesitter(tree, content, file_path, asset_id, fragment)
    except Exception as e:
        logger.warning("treesitter_unavailable", error=str(e), fallback="regex_no_einvoke")
        return _parse_with_regex(content, file_path, asset_id, fragment)


def _parse_with_treesitter(tree, content: str, file_path: str, asset_id: str,
                            fragment: GraphFragment) -> GraphFragment:
    lines = content.split("\n")
    file_id = _make_entity_id(file_path, "file", file_path.split("/")[-1])
    fragment.nodes.append(KGNode(
        entity_id=file_id, node_type="File", domain_type="code",
        name=file_path.split("/")[-1],
        source_location=SourceLocation(file_path=file_path, start_line=1, end_line=len(lines)),
        metadata=NodeMetadata(semantic_summary=f"Python module {file_path}"),
        org_id=ORG_ID,
    ))

    # Pass 1: collect all function entity_ids
    func_registry: dict[str, str] = {}
    _collect_functions_ts(tree.walk(), file_path, func_registry)

    # Pass 2: build nodes + edges
    _walk_ts(tree.walk(), content, file_path, asset_id, fragment,
             file_id, None, None, func_registry)

    logger.info("code_parsed_treesitter", file=file_path,
                nodes=len(fragment.nodes), edges=len(fragment.edges))
    return fragment


def _collect_functions_ts(cursor, file_path: str, registry: dict):
    node = cursor.node
    if node.type == "function_definition":
        nn = node.child_by_field_name("name")
        if nn:
            name = nn.text.decode("utf8")
            registry[name] = _make_entity_id(file_path, "function", name)
    if cursor.goto_first_child():
        while True:
            _collect_functions_ts(cursor, file_path, registry)
            if not cursor.goto_next_sibling():
                break
        cursor.goto_parent()


def _walk_ts(cursor, content: str, file_path: str, asset_id: str,
             fragment: GraphFragment, parent_id: str,
             current_class: Optional[str], current_func_id: Optional[str],
             func_registry: dict):
    node = cursor.node

    if node.type == "class_definition":
        nn = node.child_by_field_name("name")
        class_name = nn.text.decode("utf8") if nn else "UnknownClass"
        class_id = _make_entity_id(file_path, "class", class_name)
        s, e = node.start_point[0] + 1, node.end_point[0] + 1
        fragment.nodes.append(KGNode(
            entity_id=class_id, node_type="Class", domain_type="code", name=class_name,
            source_location=SourceLocation(file_path=file_path, start_line=s, end_line=e),
            metadata=NodeMetadata(semantic_summary=f"Python class {class_name}",
                                  resolved_by="deterministic"),
            org_id=ORG_ID,
        ))
        fragment.edges.append(KGEdge(from_entity_id=parent_id, to_entity_id=class_id,
                                     edge_type="E_contain", source_asset_ids=[asset_id]))
        if cursor.goto_first_child():
            while True:
                _walk_ts(cursor, content, file_path, asset_id, fragment,
                         class_id, class_name, None, func_registry)
                if not cursor.goto_next_sibling():
                    break
            cursor.goto_parent()
        return

    if node.type == "function_definition":
        nn = node.child_by_field_name("name")
        func_name = nn.text.decode("utf8") if nn else "unknown"
        s, e = node.start_point[0] + 1, node.end_point[0] + 1
        body_text = content[node.start_byte:node.end_byte]

        decorators = []
        prev = node.prev_named_sibling
        while prev and prev.type == "decorator":
            decorators.append(prev.text.decode("utf8"))
            prev = prev.prev_named_sibling

        is_entry = _is_entry_point(decorators, func_name)
        taint_class = _detect_taint_class(body_text)

        params_node = node.child_by_field_name("parameters")
        params = []
        if params_node:
            for child in params_node.children:
                if child.type in ("identifier", "typed_parameter", "default_parameter"):
                    params.append(child.text.decode("utf8").split(":")[0].strip())

        func_id = _make_entity_id(file_path, "function", func_name)

        summary = f"Python function {func_name}"
        if is_entry:
            summary += " — HTTP route handler (entry point)"
        if taint_class == "external_untrusted":
            summary += " — receives external user input"

        fragment.nodes.append(KGNode(
            entity_id=func_id, node_type="Function", domain_type="code", name=func_name,
            source_location=SourceLocation(file_path=file_path, start_line=s, end_line=e,
                                           block_identifier=f"function.{func_name}"),
            metadata=NodeMetadata(is_entry_point=is_entry, semantic_summary=summary,
                                  resolved_by="deterministic", confidence=1.0),
            properties={"params": params, "decorators": decorators,
                        "taint_class": taint_class, "class": current_class},
            org_id=ORG_ID,
        ))
        if is_entry:
            fragment.entry_points.append(func_id)
        fragment.edges.append(KGEdge(from_entity_id=parent_id, to_entity_id=func_id,
                                     edge_type="E_contain", source_asset_ids=[asset_id]))

        if cursor.goto_first_child():
            while True:
                _walk_ts(cursor, content, file_path, asset_id, fragment,
                         func_id, current_class, func_id, func_registry)
                if not cursor.goto_next_sibling():
                    break
            cursor.goto_parent()
        return

    # ── E_invoke from call nodes ───────────────────────────────────────────────
    if node.type == "call" and current_func_id:
        func_node = node.child_by_field_name("function")
        called_id = None
        call_confidence = 1.0

        if func_node:
            if func_node.type == "identifier":
                # Direct call: fn(args) — definite match if in registry
                called_name = func_node.text.decode("utf8")
                if called_name in func_registry:
                    called_id = func_registry[called_name]

            elif func_node.type == "attribute":
                # FIX: Method call: self.method(args) or obj.method(args)
                # Extract the method name (rightmost part)
                attr_node = func_node.child_by_field_name("attribute")
                if attr_node:
                    method_name = attr_node.text.decode("utf8")
                    # Only match if: method name is in our file's func_registry
                    # AND it's not a known stdlib/third-party method name
                    if (method_name in func_registry
                            and method_name not in SKIP_METHOD_NAMES):
                        called_id = func_registry[method_name]
                        call_confidence = 0.95  # Slightly lower: could be different obj

        if called_id and called_id != current_func_id:
            existing = any(
                e.from_entity_id == current_func_id and
                e.to_entity_id == called_id and
                e.edge_type == "E_invoke"
                for e in fragment.edges
            )
            if not existing:
                fragment.edges.append(KGEdge(
                    from_entity_id=current_func_id,
                    to_entity_id=called_id,
                    edge_type="E_invoke",
                    resolution_method="deterministic_parse",
                    confidence=call_confidence,
                    source_asset_ids=[asset_id],
                ))
        return  # Don't recurse into call args

    if cursor.goto_first_child():
        while True:
            _walk_ts(cursor, content, file_path, asset_id, fragment,
                     parent_id, current_class, current_func_id, func_registry)
            if not cursor.goto_next_sibling():
                break
        cursor.goto_parent()


def _parse_with_regex(content: str, file_path: str, asset_id: str,
                      fragment: GraphFragment) -> GraphFragment:
    """Regex fallback: E_contain only, no E_invoke (can't safely distinguish method calls)."""
    lines = content.split("\n")
    file_id = _make_entity_id(file_path, "file", file_path.split("/")[-1])
    fragment.nodes.append(KGNode(
        entity_id=file_id, node_type="File", domain_type="code",
        name=file_path.split("/")[-1],
        source_location=SourceLocation(file_path=file_path, start_line=1, end_line=len(lines)),
        metadata=NodeMetadata(semantic_summary=f"Python module {file_path}"),
        org_id=ORG_ID,
    ))

    i, pending_decorators, current_class = 0, [], None
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("@"):
            pending_decorators.append(stripped)
            i += 1
            continue

        cm = re.match(r'^class\s+(\w+)', stripped)
        if cm:
            cname = cm.group(1)
            cid = _make_entity_id(file_path, "class", cname)
            current_class = cname
            fragment.nodes.append(KGNode(
                entity_id=cid, node_type="Class", domain_type="code", name=cname,
                source_location=SourceLocation(file_path=file_path, start_line=i+1, end_line=i+1),
                metadata=NodeMetadata(semantic_summary=f"Python class {cname}",
                                      resolved_by="deterministic"),
                org_id=ORG_ID,
            ))
            fragment.edges.append(KGEdge(from_entity_id=file_id, to_entity_id=cid,
                                         edge_type="E_contain", source_asset_ids=[asset_id]))
            pending_decorators = []
            i += 1
            continue

        fm = re.match(r'^def\s+(\w+)\s*\(([^)]*)\)', stripped)
        if fm:
            func_name = fm.group(1)
            params_str = fm.group(2)
            params = [p.strip().split(":")[0].split("=")[0].strip()
                      for p in params_str.split(",")
                      if p.strip() not in ("self", "cls", "")]
            is_method = line.startswith("    ") and current_class is not None
            is_entry = _is_entry_point(pending_decorators, func_name)

            body_lines = []
            j = i + 1
            while j < len(lines):
                bl = lines[j]
                if bl.strip() and not bl.startswith("    "):
                    break
                body_lines.append(bl)
                j += 1
            body_text = "\n".join(body_lines)
            taint_class = _detect_taint_class(body_text)

            func_id = _make_entity_id(file_path, "function", func_name)
            parent_id = _make_entity_id(file_path, "class", current_class) if is_method and current_class else file_id
            summary = f"Python {'method' if is_method else 'function'} {func_name}"
            if is_entry:
                summary += " — HTTP route handler (entry point)"

            fragment.nodes.append(KGNode(
                entity_id=func_id, node_type="Function", domain_type="code", name=func_name,
                source_location=SourceLocation(file_path=file_path, start_line=i+1, end_line=j,
                                               block_identifier=f"function.{func_name}"),
                metadata=NodeMetadata(is_entry_point=is_entry, semantic_summary=summary,
                                      resolved_by="deterministic", confidence=1.0),
                properties={"params": params, "decorators": pending_decorators,
                            "taint_class": taint_class, "class": current_class},
                org_id=ORG_ID,
            ))
            if is_entry:
                fragment.entry_points.append(func_id)
            fragment.edges.append(KGEdge(from_entity_id=parent_id, to_entity_id=func_id,
                                         edge_type="E_contain", source_asset_ids=[asset_id]))
            pending_decorators = []
        i += 1

    logger.info("code_parsed_regex", file=file_path,
                nodes=len(fragment.nodes), edges=len(fragment.edges))
    return fragment
