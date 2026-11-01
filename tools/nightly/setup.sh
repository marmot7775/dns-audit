#!/bin/bash
# Installs what the nightly fix run needs to run this repository's tests.
# Each repository carries its own copy; the workflow and the Python
# collector are identical across repositories.
set -euo pipefail
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt
python -m playwright install --with-deps chromium
