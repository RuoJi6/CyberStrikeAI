#!/bin/sh
set -eu

# Kali's /usr/bin/amass launcher tries to download libpostal data through sudo
# before every invocation. Agent containers intentionally run as a non-root
# user with no-new-privileges and a read-only root filesystem, so bypass that
# packaging launcher and execute the real Amass binary directly.
export HOME=${HOME:-/workspace}
export XDG_CONFIG_HOME=${XDG_CONFIG_HOME:-${HOME}/.config}
export XDG_CACHE_HOME=${XDG_CACHE_HOME:-${HOME}/.cache}

exec /usr/lib/amass/amass "$@"
