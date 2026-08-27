#!/usr/bin/env python3
"""One-shot worker for exactly one validation or invocation."""

from __future__ import annotations

import argparse
import ast
import contextlib
import importlib
import io
import json
import os
import sys
import traceback
import types
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cyberstrike_transform import Context, Message, Result, message_from_wire, result_to_wire


PROTOCOL = "traffic-transform/v1"
ALLOWED_IMPORT_ROOTS = {
    "base64", "binascii", "collections", "cryptography", "dataclasses", "datetime",
    "decimal", "enum", "functools", "hashlib", "hmac", "json", "math", "operator",
    "re", "secrets", "struct", "time", "typing", "urllib", "uuid", "zlib", "gzip",
    "cyberstrike_transform",
}
DENIED_CALLS = {
    "eval", "exec", "compile", "open", "input", "breakpoint", "__import__",
    "getattr", "setattr", "delattr", "globals", "locals", "vars",
}
DENIED_ATTRIBUTE_PREFIX = "__"


class SourcePolicyError(ValueError):
    pass


def validate_source(source: str, hooks: list[str]) -> ast.AST:
    try:
        tree = ast.parse(source, filename="transform.py", mode="exec")
    except SyntaxError as exc:
        raise SourcePolicyError(f"syntax error at line {exc.lineno}: {exc.msg}") from exc

    declared_hooks = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for name in names:
                root = name.split(".", 1)[0]
                if root not in ALLOWED_IMPORT_ROOTS:
                    raise SourcePolicyError(f"import {root!r} is not available in the transform runner")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in DENIED_CALLS:
            raise SourcePolicyError(f"call to {node.func.id!r} is not permitted")
        if isinstance(node, ast.Attribute) and node.attr.startswith(DENIED_ATTRIBUTE_PREFIX):
            raise SourcePolicyError("dunder attribute access is not permitted")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in hooks:
            declared_hooks.add(node.name)
    missing = sorted(set(hooks) - declared_hooks)
    if missing:
        raise SourcePolicyError("missing declared hooks: " + ", ".join(missing))
    return tree


def load_module(source: str, hooks: list[str]) -> types.ModuleType:
    tree = validate_source(source, hooks)
    module = types.ModuleType("agent_traffic_transform")
    module.__file__ = "transform.py"
    # The container/worker boundary is the primary sandbox. The reduced
    # builtins below additionally prevents common accidental escape paths.
    safe_builtins = dict(vars(importlib.import_module("builtins")))
    original_import = safe_builtins["__import__"]
    for name in DENIED_CALLS:
        safe_builtins.pop(name, None)

    def guarded_import(name: str, globals=None, locals=None, fromlist=(), level=0):
        root = name.split(".", 1)[0]
        if root not in ALLOWED_IMPORT_ROOTS:
            raise ImportError(f"import {root!r} is not available in the transform runner")
        return original_import(name, globals, locals, fromlist, level)

    safe_builtins["__import__"] = guarded_import
    safe_builtins.pop("open", None)
    safe_builtins.pop("input", None)
    safe_builtins.pop("breakpoint", None)
    module.__dict__["__builtins__"] = safe_builtins
    code = compile(tree, "transform.py", "exec", dont_inherit=True, optimize=2)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        exec(code, module.__dict__, module.__dict__)
    return module


def error(code: str, message: str, invocation_id: str = "") -> dict[str, Any]:
    return {
        "protocolVersion": PROTOCOL,
        "invocationId": invocation_id,
        "action": "error",
        "error": {"code": code, "message": message[:1000]},
    }


def run_validate(bundle_dir: str) -> dict[str, Any]:
    manifest = json.loads(read_text(os.path.join(bundle_dir, "manifest.json")))
    source = read_text(os.path.join(bundle_dir, "transform.py"))
    hooks = list(manifest.get("hooks") or [])
    load_module(source, hooks)
    return {"valid": True, "hooks": hooks}


def run_invoke(bundle_dir: str, invocation: dict[str, Any]) -> dict[str, Any]:
    invocation_id = str(invocation.get("invocationId", ""))
    manifest = json.loads(read_text(os.path.join(bundle_dir, "manifest.json")))
    source = read_text(os.path.join(bundle_dir, "transform.py"))
    hooks = list(manifest.get("hooks") or [])
    hook_name = str(invocation.get("hook", ""))
    if hook_name not in hooks:
        return {
            "protocolVersion": PROTOCOL,
            "invocationId": invocation_id,
            "action": "pass",
        }
    module = load_module(source, hooks)
    hook = getattr(module, hook_name, None)
    if not callable(hook):
        return error("hook_not_implemented", f"hook {hook_name} is not callable", invocation_id)
    ctx = Context(invocation.get("context") or {}, invocation.get("transactionState") or {})
    message = message_from_wire(invocation.get("message") or {})
    args: list[Any] = [ctx, message]
    if hook_name.startswith("encode_"):
        original = invocation.get("originalWire")
        if original is None:
            return error("invalid_input", "encode hook requires originalWire", invocation_id)
        args.append(message_from_wire(original))
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        value = hook(*args)
    return result_to_wire(value, PROTOCOL, invocation_id)


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("validate", "invoke"))
    parser.add_argument("bundle_dir")
    args = parser.parse_args()
    try:
        if args.operation == "validate":
            output = run_validate(args.bundle_dir)
        else:
            invocation = json.load(sys.stdin)
            output = run_invoke(args.bundle_dir, invocation)
    except SourcePolicyError as exc:
        output = error("invalid_source", str(exc))
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        output = error("invalid_input", str(exc))
    except Exception as exc:  # sanitized: tracebacks stay in the worker stderr only
        traceback.print_exc(file=sys.stderr)
        output = error("script_exception", f"{type(exc).__name__}: {exc}")
    json.dump(output, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
