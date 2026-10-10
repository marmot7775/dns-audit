"""Write requirements.txt and requirements-dev.txt from pyproject.toml.

pyproject.toml is the one place dependencies are declared. The deploy runs
`pip install -r requirements.txt` and CI installs both files, so they stay,
generated. tests/test_requirements_generated.py fails when they drift.

    python3 tools/gen_requirements.py
"""
import pathlib
import sys

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    sys.exit("tools/gen_requirements.py needs Python 3.11 or newer (tomllib)")

ROOT = pathlib.Path(__file__).resolve().parent.parent

HEADER = (
    "# Generated from pyproject.toml by tools/gen_requirements.py. Do not edit:\n"
    "# change pyproject.toml, where each pin's reason is written, and rerun.\n"
)


def render() -> dict[str, str]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return {
        "requirements.txt": HEADER + "".join(f"{d}\n" for d in project["dependencies"]),
        "requirements-dev.txt": HEADER
        + "".join(f"{d}\n" for d in project["optional-dependencies"]["dev"]),
    }


def main() -> None:
    for name, text in render().items():
        (ROOT / name).write_text(text, encoding="utf-8")
        print(f"wrote {name}")


if __name__ == "__main__":
    main()
