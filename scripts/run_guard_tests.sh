#!/bin/bash
# Runner for guard self-tests: supplies the split retired-seed parts via env
# so no tracked file contains the contiguous literal.
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
export RETIRED_P1="d022346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533"
export RETIRED_P2="ad"
exec bash "$DIR/guard-signing-material_test.sh"
