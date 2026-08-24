#!/bin/sh
set -eu

# Kali's Responder launcher changes into /usr/share/responder and stores its
# database and logs there. CyberStrikeAI keeps the image root filesystem
# read-only, so copy the immutable application files into the conversation
# workspace and keep every runtime artifact inside that bounded volume.
source_dir=/usr/share/responder
data_root=${XDG_DATA_HOME:-${HOME:-/workspace}/.local/share}
runtime_dir=${data_root}/cyberstrike-responder

mkdir -p "${runtime_dir}"
if [ ! -f "${runtime_dir}/Responder.py" ]; then
    cp -R "${source_dir}/." "${runtime_dir}/"
fi

cd "${runtime_dir}"
exec /usr/bin/python3 ./Responder.py "$@"
