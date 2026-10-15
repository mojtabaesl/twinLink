#!/bin/sh
# Install the local checkout; no downloaded installer or rathole executable.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$SCRIPT_DIR/package.py" install "$@"
