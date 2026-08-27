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


if __name__ == "__main__":
    unittest.main()
