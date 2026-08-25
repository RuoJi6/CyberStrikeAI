#!/usr/bin/env bash
set -euo pipefail

cd /opt/cloudmapper
exec /opt/tools-venv/bin/python /opt/cloudmapper/cloudmapper.py "$@"
