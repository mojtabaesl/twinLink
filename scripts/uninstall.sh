#!/bin/sh
# Program removal and managed network removal are separate choices.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$SCRIPT_DIR/package.py" uninstall "$@"
