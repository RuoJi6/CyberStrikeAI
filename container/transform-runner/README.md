# CyberStrikeAI Traffic Transform Runner

An isolated, multi-architecture Python runtime for auditable CyberStrikeAI MITM traffic-transform hooks.

CyberStrikeAI uses this image as an internal runtime component. The application loads immutable, hash-verified scripts into the Runner and invokes them only for HTTP transactions that match an enabled transform scope. Users normally do not start this image directly.

> 中文简介：CyberStrikeAI 可编程 MITM 流量转换脚本的双架构隔离运行时。它负责验证并执行 Agent 或用户编写的请求/响应加解密 Hook，本身不是代理网关。

**Use only on systems you own or are explicitly authorized to test. / 仅可用于自有或已获得明确授权的目标。**

## Current release

| Item | Value |
| --- | --- |
| Tags | `mitm-20260828`, `latest` |
| Platforms | `linux/amd64`, `linux/arm64` |
| Multi-platform digest | `sha256:07a8cba57f50805ca657112f9847ad666325439ebd6bf372595a01950d26306d` |
| AMD64 manifest | `sha256:57da8360b90e47ff7a46d04e2c59591b7ae5acacda086a657f45b9e2250da287` |
| ARM64 manifest | `sha256:e17b70ef0be22abf4fb6aeaeb499d926216254ddea949192d8c50974c82b1cbf` |
| Source revision | `2c6537ba19e2edf59c9866bd7e1b5beca80e99ed` |
| Protocol | `traffic-transform/v1` |
| Python dependency inventory | `cryptography==38.0.4` |

Production deployments should pin the multi-platform digest. The `latest` tag is a discovery channel, not a runtime trust anchor.

## What changed in this release

- Published the first standalone AMD64/ARM64 Traffic Transform Runner image.
- Added authenticated immutable revision loading with source SHA-256 verification.
- Added request and response `decode`, `mutate`, and `encode` Hook execution.
- Added the `@body_decoder` SDK helper for common `bytes -> bytes` decryption functions.
- Added exact Hook-signature validation with actionable error messages.
- Added isolated worker subprocesses, deadlines, output limits, and sanitized errors.
- Published OCI provenance and SBOM attestations for both architectures.

## Hook model

The Runner supports the following ordered chains:

```text
request:  decode_request -> mutate_request -> encode_request
response: decode_response -> mutate_response -> encode_response
```

For the common body-decryption case, a script can use the compact SDK helper:

```python
from cyberstrike_transform import body_decoder

@body_decoder(content_type="application/json")
def decode_request(body: bytes) -> bytes:
    return decrypt(body)
```

Transform scope, enabled state, execution location, conversation binding, and replay behavior are controlled by CyberStrikeAI. The Runner does not decide which websites it may process.

## Pull

```bash
docker pull ruoji6/cyberstrikeai-transform-runner:mitm-20260828

# Recommended for immutable deployments
docker pull ruoji6/cyberstrikeai-transform-runner@sha256:07a8cba57f50805ca657112f9847ad666325439ebd6bf372595a01950d26306d
```

Docker automatically selects the matching AMD64 or ARM64 image for the host.

## Runtime security

CyberStrikeAI starts this image as a non-root user with a read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, CPU/memory/PID/file-descriptor limits, and a private internal network. Revision storage is provided through a size-limited temporary filesystem.

The HTTP control plane requires a bearer token supplied by the application. Do not expose port `9089` to an untrusted network and do not pass secrets through image build arguments.

The source-policy checks and reduced Python builtins are defense in depth. The container and worker process boundaries remain the primary isolation controls.
