"""pyproject.toml is the single source for dependencies.

requirements.txt and requirements-dev.txt are generated from it by
tools/gen_requirements.py, because the deploy and CI install from them. A pin
changed in one place and not the other is how a deploy ends up running a
version no test ran, so the files must match the generator's output exactly.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

tomllib = pytest.importorskip("tomllib")
import gen_requirements  # noqa: E402


@pytest.mark.parametrize("name", ["requirements.txt", "requirements-dev.txt"])
def test_requirements_file_is_generated_from_pyproject(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        on_disk = fh.read()
    assert on_disk == gen_requirements.render()[name], (
        f"{name} does not match pyproject.toml. Edit pyproject.toml, then run "
        "python3 tools/gen_requirements.py"
    )
