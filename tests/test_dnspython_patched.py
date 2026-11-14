"""dnspython below 2.9.2 has an excessive memory and CPU use advisory
(Dependabot DB-4, DB-5). Pin the declared version at or above the patch."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATCHED = (2, 9, 2)


def _pinned(path):
    m = re.search(r"dnspython==(\d+)\.(\d+)\.(\d+)", (ROOT / path).read_text())
    assert m, f"dnspython not pinned in {path}"
    return tuple(int(x) for x in m.groups())


def test_pyproject_pin_is_patched():
    assert _pinned("pyproject.toml") >= PATCHED


def test_requirements_pin_is_patched():
    assert _pinned("requirements.txt") >= PATCHED
