# ARM64 Container Image Supply Chain

CyberStrikeAI deploys the Agent runtime and per-conversation egress gateway as
locally built, digest-pinned `linux/arm64` images. The production configuration
must never use a floating tag.

## Build boundary

- Build both images on the controlled ARM64 deployment VM from a reviewed Git
  revision. Do not use a GitHub-hosted build for this release path.
- Pass `BUILD_DATE`, `SOURCE_URL`, `VCS_REF`, and `VERSION` to both Dockerfiles.
- The Agent base image and the egress Go builder are pinned by digest in their
  Dockerfiles.
- Record the resulting local image ID (`sha256:...`) as the configured digest.
- Regenerate the Agent tool inventory for that exact image digest.

Example:

```bash
docker build --platform linux/arm64 \
  --build-arg BUILD_DATE="$BUILD_DATE" \
  --build-arg SOURCE_URL="https://github.com/RuoJi6/CyberStrikeAI" \
  --build-arg VCS_REF="$REVISION" \
  --build-arg VERSION="$VERSION" \
  -t cyberstrike/agent:"$VERSION" -f container/agent/Dockerfile .

docker build --platform linux/arm64 \
  --build-arg BUILD_DATE="$BUILD_DATE" \
  --build-arg SOURCE_URL="https://github.com/RuoJi6/CyberStrikeAI" \
  --build-arg VCS_REF="$REVISION" \
  --build-arg VERSION="$VERSION" \
  -t cyberstrike/egress:"$VERSION" -f container/egress/Dockerfile .
```

## Offline verification bundle

Run `scripts/verify-container-release.sh` on the VM with digest-qualified local
references, the exact tool inventory, and a new output directory. The script:

1. verifies `linux/arm64`, image IDs, non-root users, entrypoints, source and
   revision OCI labels;
2. uses Trivy 0.73.0 from the pinned Agent image, with networking disabled, to
   generate SPDX JSON SBOMs for the Agent filesystem and exported gateway
   rootfs;
3. verifies the tool inventory is bound to the exact Agent image digest;
4. writes normalized image metadata and `images.json`;
5. creates and verifies `SHA256SUMS`; and
6. optionally runs both hardened image smoke tests.

The resulting directory is an offline verification bundle. Store it beside the
deployment record; do not copy it into the application image or repository.

## Runtime checks and rollback

Before enabling container mode, confirm the configured repository, digest,
platform, inventory digest, and gateway digest match the bundle. A mismatch is
fail-closed. Rollback means restoring the previous digest-pinned configuration
and inventory, restarting CyberStrikeAI, and rebuilding affected conversation
runtimes. Host execution remains the default and is not changed by this image
release process.
