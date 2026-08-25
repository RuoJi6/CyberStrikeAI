#!/usr/bin/env bash
set -euo pipefail

cd /opt/jwt_tool
exec python3 /opt/jwt_tool/jwt_tool.py "$@"
