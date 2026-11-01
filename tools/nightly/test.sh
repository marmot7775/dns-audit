#!/bin/bash
# The full test suite, as the nightly fix run and its prompt call it.
set -euo pipefail
python -m pytest tests/ -q "$@"
