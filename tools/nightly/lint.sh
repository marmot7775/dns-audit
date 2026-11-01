#!/bin/bash
# Lint for the files the nightly fix run changed. Optional per repository.
set -euo pipefail
ruff check "$@"
