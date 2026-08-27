#!/usr/bin/env python3
"""Authenticated private HTTP control plane for traffic transform workers."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib.metadata
import json
import os
import resource
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional


PROTOCOL = "traffic-transform/v1"
MAX_HTTP_BODY = 16 << 20
MAX_SOURCE = 256 << 10
MAX_WORKER_OUTPUT = 1 << 20
MAX_DEADLINE_MS = 5000
ALLOWED_HOOKS = {
    "decode_request", "mutate_request", "encode_request",
    "decode_response", "mutate_response", "encode_response",
}
ALLOWED_REQUIREMENTS = {"cryptography": "38.0.4"}
RUNNER_DIR = Path(__file__).resolve().parent
WORKER = RUNNER_DIR / "worker.py"


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sanitized_error(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": str(message)[:1000]}}


class RunnerState:
    def __init__(self, token: str, root: Path) -> None:
        self.token = token
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.generation = secrets.token_hex(16)
        self.loaded: dict[str, tuple[str, Path]] = {}
        self.lock = threading.RLock()

    def load_revision(self, request: dict[str, Any]) -> dict[str, Any]:
        revision_id = str(request.get("revisionId", "")).strip()
        expected_digest = str(request.get("sourceSha256", "")).strip()
        source = request.get("source")
        manifest = request.get("manifest") or {}
        if not revision_id or not isinstance(source, str):
            raise ValueError("revisionId and source are required")
        if len(source.encode("utf-8")) > MAX_SOURCE:
            raise ValueError("transform source is too large")
        actual_digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(actual_digest, expected_digest):
            raise ValueError("transform source digest mismatch")
        self._validate_manifest(manifest)

        bundle = self.root / actual_digest
        with self.lock:
            already_loaded = self.loaded.get(revision_id)
            if already_loaded is not None and hmac.compare_digest(already_loaded[0], actual_digest):
                return {
                    "protocolVersion": PROTOCOL,
                    "revisionId": revision_id,
                    "sourceSha256": actual_digest,
                    "valid": True,
                    "hooks": manifest.get("hooks") or [],
                    "runnerGeneration": self.generation,
                }
            if bundle.exists():
                self._verify_existing_bundle(bundle, source, manifest)
            else:
                staging = Path(tempfile.mkdtemp(prefix="revision-", dir=self.root))
                try:
                    (staging / "transform.py").write_text(source, encoding="utf-8")
                    (staging / "manifest.json").write_bytes(json_bytes(manifest))
                    os.chmod(staging / "transform.py", 0o400)
                    os.chmod(staging / "manifest.json", 0o400)
                    os.chmod(staging, 0o500)
                    os.replace(staging, bundle)
                except Exception:
                    shutil.rmtree(staging, ignore_errors=True)
                    raise

            validation = self._run_worker("validate", bundle, None, 2000)
            if not validation.get("valid"):
                worker_error = validation.get("error") or {}
                raise ValueError(worker_error.get("message") or "runner rejected transform source")
            self.loaded[revision_id] = (actual_digest, bundle)
        return {
            "protocolVersion": PROTOCOL,
            "revisionId": revision_id,
            "sourceSha256": actual_digest,
            "valid": True,
            "hooks": validation.get("hooks") or [],
            "runnerGeneration": self.generation,
        }

    def invoke(self, invocation: dict[str, Any]) -> dict[str, Any]:
        if invocation.get("protocolVersion") != PROTOCOL:
            raise ValueError("unsupported traffic transform protocol")
        revision_id = str(invocation.get("revisionId", "")).strip()
        digest = str(invocation.get("revisionSha256", "")).strip()
        invocation_id = str(invocation.get("invocationId", "")).strip()
        hook = str(invocation.get("hook", ""))
        mode = str(invocation.get("mode", ""))
        deadline_ms = int(invocation.get("deadlineMs", 0))
        if not revision_id or not invocation_id or hook not in ALLOWED_HOOKS:
            raise ValueError("invalid invocation identity or hook")
        if mode not in ("observe", "inline"):
            raise ValueError("invalid invocation mode")
        if mode == "observe" and hook not in ("decode_request", "decode_response"):
            raise ValueError("observe mode only permits decode hooks")
        if deadline_ms <= 0 or deadline_ms > MAX_DEADLINE_MS:
            raise ValueError("invalid invocation deadline")
        with self.lock:
            loaded = self.loaded.get(revision_id)
        if loaded is None:
            return self._invocation_error(invocation_id, "revision_not_loaded", "revision is not loaded")
        loaded_digest, bundle = loaded
        if not hmac.compare_digest(loaded_digest, digest):
            return self._invocation_error(invocation_id, "revision_hash_mismatch", "revision digest mismatch")
        result = self._run_worker("invoke", bundle, invocation, deadline_ms)
        result["protocolVersion"] = PROTOCOL
        result["invocationId"] = invocation_id
        if "action" not in result and isinstance(result.get("error"), dict):
            result["action"] = "error"
        return result

    def health(self) -> dict[str, Any]:
        with self.lock:
            revisions = [{"revisionId": revision_id, "sourceSha256": item[0]} for revision_id, item in sorted(self.loaded.items())]
        return {
            "status": "ok",
            "protocolVersion": PROTOCOL,
            "runnerGeneration": self.generation,
            "loadedRevisions": revisions,
            "inventory": dict(ALLOWED_REQUIREMENTS),
        }

    def _validate_manifest(self, manifest: dict[str, Any]) -> None:
        if manifest.get("protocolVersion") != PROTOCOL:
            raise ValueError("unsupported manifest protocol")
        if manifest.get("language") != "python3" or manifest.get("entrypoint") != "transform.py" or manifest.get("sdkVersion") != "1":
            raise ValueError("unsupported transform manifest runtime")
        hooks = manifest.get("hooks") or []
        if not isinstance(hooks, list) or not hooks or any(item not in ALLOWED_HOOKS for item in hooks) or len(set(hooks)) != len(hooks):
            raise ValueError("invalid transform manifest hooks")
        requirements = manifest.get("requirements") or []
        if not isinstance(requirements, list):
            raise ValueError("invalid transform requirements")
        for requirement in requirements:
            name, separator, version = str(requirement).partition("==")
            if separator != "==" or ALLOWED_REQUIREMENTS.get(name.lower()) != version:
                raise ValueError(f"dependency {requirement!r} is not in the runner inventory")
            try:
                actual = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError as exc:
                raise ValueError(f"dependency {name!r} is not installed") from exc
            if actual != version:
                raise ValueError(f"dependency {name!r} version mismatch")

    def _verify_existing_bundle(self, bundle: Path, source: str, manifest: dict[str, Any]) -> None:
        if bundle.is_symlink() or not bundle.is_dir():
            raise ValueError("invalid revision bundle")
        if (bundle / "transform.py").read_text(encoding="utf-8") != source:
            raise ValueError("immutable revision source conflict")
        existing_manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        if existing_manifest != manifest:
            raise ValueError("immutable revision manifest conflict")

    def _run_worker(self, operation: str, bundle: Path, invocation: Optional[dict[str, Any]], deadline_ms: int) -> dict[str, Any]:
        command = [sys.executable, "-I", str(WORKER), operation, str(bundle)]
        payload = b"" if invocation is None else json_bytes(invocation)
        timeout = max(0.05, deadline_ms / 1000.0)
        env = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        try:
            completed = subprocess.run(
                command,
                input=payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=str(bundle),
                timeout=timeout,
                check=False,
                start_new_session=True,
                preexec_fn=worker_limits,
            )
        except subprocess.TimeoutExpired:
            return {"error": {"code": "deadline_exceeded", "message": "transform worker exceeded its deadline"}}
        if len(completed.stdout) > MAX_WORKER_OUTPUT:
            return {"error": {"code": "invalid_output", "message": "transform worker output is too large"}}
        if completed.returncode != 0:
            return {"error": {"code": "worker_crashed", "message": f"transform worker exited with status {completed.returncode}"}}
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return {"error": {"code": "invalid_output", "message": "transform worker returned invalid JSON"}}
        if not isinstance(result, dict):
            return {"error": {"code": "invalid_output", "message": "transform worker returned a non-object result"}}
        return result

    @staticmethod
    def _invocation_error(invocation_id: str, code: str, message: str) -> dict[str, Any]:
        return {
            "protocolVersion": PROTOCOL,
            "invocationId": invocation_id,
            "action": "error",
            "error": {"code": code, "message": message},
        }


def worker_limits() -> None:
    # These are a second line of defense. Container CPU/memory/PID limits remain
    # authoritative and also cover native extensions.
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    os.umask(0o077)


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberStrikeTransformRunner/1"
    state: RunnerState

    def log_message(self, format: str, *args: Any) -> None:
        # Never log request bodies, tokens, source, decoded traffic, or tracebacks.
        sys.stderr.write(f"transform-runner {self.address_string()} {format % args}\n")

    def do_GET(self) -> None:
        if not self._authorized():
            return self._send(HTTPStatus.UNAUTHORIZED, sanitized_error("unauthorized", "invalid runner token"))
        if self.path != "/v1/health":
            return self._send(HTTPStatus.NOT_FOUND, sanitized_error("not_found", "endpoint not found"))
        self._send(HTTPStatus.OK, self.state.health())

    def do_POST(self) -> None:
        if not self._authorized():
            return self._send(HTTPStatus.UNAUTHORIZED, sanitized_error("unauthorized", "invalid runner token"))
        try:
            request = self._read_json()
            if self.path == "/v1/revisions/load":
                response = self.state.load_revision(request)
            elif self.path == "/v1/invoke":
                response = self.state.invoke(request)
            else:
                return self._send(HTTPStatus.NOT_FOUND, sanitized_error("not_found", "endpoint not found"))
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return self._send(HTTPStatus.BAD_REQUEST, sanitized_error("invalid_request", str(exc)))
        except Exception:
            return self._send(HTTPStatus.INTERNAL_SERVER_ERROR, sanitized_error("runner_failure", "runner could not process the request"))
        self._send(HTTPStatus.OK, response)

    def _authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        expected = "Bearer " + self.state.token
        return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))

    def _read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length <= 0 or length > MAX_HTTP_BODY:
            raise ValueError("request body size is invalid")
        body = self.rfile.read(length)
        parsed = json.loads(body)
        if not isinstance(parsed, dict):
            raise ValueError("request body must be a JSON object")
        return parsed

    def _send(self, status: HTTPStatus, value: dict[str, Any]) -> None:
        body = json_bytes(value)
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default=os.environ.get("CYBERSTRIKE_TRANSFORM_LISTEN", "127.0.0.1:9089"))
    parser.add_argument("--revision-root", default=os.environ.get("CYBERSTRIKE_TRANSFORM_REVISION_ROOT", "/run/cyberstrike-transform/revisions"))
    args = parser.parse_args()
    token = os.environ.get("CYBERSTRIKE_TRANSFORM_TOKEN", "")
    token_file = os.environ.get("CYBERSTRIKE_TRANSFORM_TOKEN_FILE", "").strip()
    if not token and token_file:
        try:
            token_path = Path(token_file)
            token_stat = token_path.stat()
            if token_path.is_symlink() or not token_path.is_file() or token_stat.st_mode & 0o077:
                raise ValueError("token file must be regular, non-symlink, and mode 0600/0400")
            token = token_path.read_text(encoding="utf-8").strip()
        except Exception as exc:
            sys.stderr.write(f"cannot read CYBERSTRIKE_TRANSFORM_TOKEN_FILE: {exc}\n")
            return 2
    if len(token) < 32:
        sys.stderr.write("traffic transform token must contain at least 32 characters\n")
        return 2
    host, separator, port_text = args.listen.rpartition(":")
    if separator != ":" or not host:
        sys.stderr.write("--listen must be HOST:PORT\n")
        return 2
    state = RunnerState(token, Path(args.revision_root).resolve())
    Handler.state = state
    server = ThreadingHTTPServer((host, int(port_text)), Handler)
    server.daemon_threads = True
    sys.stderr.write(f"traffic transform runner listening on {host}:{port_text}, generation={state.generation}\n")
    server.serve_forever(poll_interval=0.25)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
