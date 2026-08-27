from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


RUNNER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(RUNNER_DIR))

import worker


SOURCE = '''from cyberstrike_transform import Annotation, Message, Result

def decode_request(ctx, wire: Message) -> Result:
    decoded = wire.with_body(wire.body[::-1], content_type="application/json")
    return Result.replace(decoded, (Annotation("codec", "reverse"),), {"decoded": True})
'''

DECORATOR_SOURCE = '''from cyberstrike_transform import body_decoder

@body_decoder(content_type="text/plain; charset=utf-8")
def decode_request(body: bytes) -> bytes:
    return body[::-1]
'''


class WorkerTest(unittest.TestCase):
    def bundle(self, source: str = SOURCE) -> tempfile.TemporaryDirectory[str]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "transform.py").write_text(source, encoding="utf-8")
        (root / "manifest.json").write_text(json.dumps({
            "protocolVersion": "traffic-transform/v1",
            "language": "python3",
            "entrypoint": "transform.py",
            "sdkVersion": "1",
            "hooks": ["decode_request"],
            "requirements": [],
        }), encoding="utf-8")
        return temporary

    def test_validate_and_invoke_binary_message(self) -> None:
        temporary = self.bundle()
        self.addCleanup(temporary.cleanup)
        self.assertTrue(worker.run_validate(temporary.name)["valid"])
        body = b"abc\x00"
        invocation = {
            "protocolVersion": "traffic-transform/v1",
            "invocationId": "inv-1",
            "hook": "decode_request",
            "context": {
                "transactionId": "txn-1",
                "conversationId": "conv-1",
                "direction": "request",
                "scheme": "https",
                "host": "example.test",
                "port": 443,
                "method": "POST",
                "path": "/encrypted",
                "config": {},
            },
            "message": {
                "kind": "request",
                "method": "POST",
                "path": "/encrypted",
                "headers": [],
                "body": {
                    "encoding": "base64",
                    "data": "YWJjAA==",
                    "length": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "complete": True,
                },
            },
            "transactionState": {},
        }
        result = worker.run_invoke(temporary.name, invocation)
        self.assertEqual("replace", result["action"])
        self.assertEqual("AGNiYQ==", result["message"]["body"]["data"])
        self.assertEqual({"decoded": True}, result["statePatch"])
        self.assertEqual("reverse", result["annotations"][0]["value"])

    def test_source_policy_rejects_os_and_open(self) -> None:
        with self.assertRaises(worker.SourcePolicyError):
            worker.validate_source("import os\ndef decode_request(ctx, wire): return wire\n", ["decode_request"])
        with self.assertRaises(worker.SourcePolicyError):
            worker.validate_source("def decode_request(ctx, wire): open('/tmp/x')\n", ["decode_request"])

    def test_source_policy_reports_exact_hook_signature(self) -> None:
        with self.assertRaisesRegex(worker.SourcePolicyError, r"decode_request must accept exactly \(ctx, wire\)"):
            worker.validate_source("def decode_request(body): return body\n", ["decode_request"])
        with self.assertRaisesRegex(worker.SourcePolicyError, r"encode_request must accept exactly \(ctx, logical, original_wire\)"):
            worker.validate_source("def encode_request(ctx, wire): return wire\n", ["encode_request"])
        with self.assertRaisesRegex(worker.SourcePolicyError, r"with body_decoder must accept exactly \(body\)"):
            worker.validate_source(
                "from cyberstrike_transform import body_decoder\n@body_decoder()\ndef decode_request(ctx, body): return body\n",
                ["decode_request"],
            )

    def test_body_decoder_hides_hook_protocol_for_common_codecs(self) -> None:
        temporary = self.bundle(DECORATOR_SOURCE)
        self.addCleanup(temporary.cleanup)
        self.assertTrue(worker.run_validate(temporary.name)["valid"])
        body = b"cipher"
        invocation = {
            "protocolVersion": "traffic-transform/v1",
            "invocationId": "inv-decorator",
            "hook": "decode_request",
            "context": {"direction": "request", "host": "example.test", "config": {}},
            "message": {
                "kind": "request",
                "method": "POST",
                "path": "/encrypted",
                "headers": [],
                "body": {
                    "encoding": "base64",
                    "data": "Y2lwaGVy",
                    "length": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "complete": True,
                },
            },
            "transactionState": {},
        }
        result = worker.run_invoke(temporary.name, invocation)
        self.assertEqual("replace", result["action"])
        self.assertEqual("cmVocGlj", result["message"]["body"]["data"])
        self.assertEqual(
            "text/plain; charset=utf-8",
            next(item["value"] for item in result["message"]["headers"] if item["name"] == "Content-Type"),
        )


if __name__ == "__main__":
    unittest.main()
