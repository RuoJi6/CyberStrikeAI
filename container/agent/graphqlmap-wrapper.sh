#!/usr/bin/env bash
set -euo pipefail

export PYTHONPATH="/opt/graphqlmap${PYTHONPATH:+:${PYTHONPATH}}"
exec python3 /opt/graphqlmap/bin/graphqlmap "$@"
