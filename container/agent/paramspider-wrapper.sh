#!/usr/bin/env bash
set -euo pipefail

export PYTHONPATH="/opt/paramspider${PYTHONPATH:+:${PYTHONPATH}}"
exec python3 -m paramspider.main "$@"
