# Contributing

Right answers come before everything else. A change that makes the code
nicer and one verdict wrong is a regression.

## Run the suite

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m playwright install chromium   # browser tests; they skip without it
python3 -m pytest tests/ -q
ruff check .
mypy                                    # report only for now; see CHANGELOG.md
```

Tests run against fake DNS zones (`FakeZone` in tests/conftest.py). Build new
ones the same way, through `run_full_audit` and the transformer, not with
hand-built cards.

## Rules for a change

- **A verdict change needs a test that fails without it.** Anything that
  changes a card's status, pill, verdict, fix or the summary ships with a
  test that fails on main and passes on the branch. Run it against main
  before you open the pull request.
- **An RFC claim cites its section.** In code comments, card text, articles
  and docs: "RFC 9989 section 4.7", not "the RFC". DMARC reporting rules
  live in RFC 9990 and failure reports in RFC 9991, not RFC 9989.
- **A failed lookup is not a finding.** If a query did not complete, the card
  says "Not checked". See [the decision](docs/decisions/2026-09-02-failed-lookup-is-not-a-finding.md).
- **Dependencies go in pyproject.toml.** Then run
  `python3 tools/gen_requirements.py`; the requirements files are generated.
- **No em dashes or double hyphens** in anything a person reads. A test
  enforces it.
- **No personal email address** anywhere in the repo. Contact is the
  address in [SECURITY.md](SECURITY.md) or GitHub.

[ARCHITECTURE.md](ARCHITECTURE.md) has the pipeline and module map, and
[docs/decisions](docs/decisions/) has the reasoning behind the choices people
most often want to reopen.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
