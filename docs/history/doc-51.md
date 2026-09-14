# Doc 51: Repo hygiene and README

Last doc from the Sept 13 review. Nothing here changes the
site or the audit. It makes the repo read correctly for
someone arriving from GitHub: the README says what the tool is
and is not, the files in the root are the ones that run the
app, and the docs and tests are named for what they cover.
Line numbers are from main at 1ebfc1a. Every fact below was
checked against that commit; where a README claim is replaced,
the replacement was verified against the code.

## 1. Version floor and stale numbers

- pyproject.toml:5 requires-python >=3.9 and :11
  target-version py39, while README:179 says 3.10 or newer and
  requirements.txt:2 says six pins require 3.10 while the
  reviewer counted seven; count them and put the same number
  in both places. Set >=3.10 and py310.
- pyproject.toml:14 to 18: the ruff comment cites counts
  (1748, 51, 1533) and the E402 note cites 23 of 24 hits.
  Re-run ruff with the default set and with E,F,W,I and put
  the current numbers in, or drop the numbers and keep the
  reasoning. :29 omits _starttls_test_server.py at the root;
  the file is tests/_starttls_test_server.py, and tests/*
  already covers it, so delete the line.
- pyproject.toml:4 description "Comprehensive DNS and email
  security auditing tool": Doc 47 removed that word from the
  site; make it "DNS and email security audit: DMARC, SPF,
  DKIM, MTA-STS, DNSSEC, DANE, CAA, BIMI, TLS-RPT, MX,
  nameservers, Certificate Transparency."
- CLAUDE.md:11 "all 13 security checks" is 12
  (len(ALL_SCOPE_CHECK_KEYS)). CLAUDE.md:92 to 96 and
  dns-auditor.service:19 to 23 cite server.py line numbers
  that are already wrong (_inflight is at 421, _cache at 538,
  _health_cache at 1252). Drop the numbers from both and name
  the globals only; the service file comment then points at
  CLAUDE.md "Single worker by design" for the reasoning
  instead of repeating it.
- README:57 "How many of nine protocols" reads as a fixed
  denominator; the ring's denominator is the number of
  protocols the audit could assess. Make it "How many of up to
  nine protocols".
- README:36 RFC 9904 clause is correct (RFC 9904, November
  2025, obsoletes RFC 8624 and moves the canonical source to
  the IANA registries). audit_engine.py:2778 still cites "RFC
  8624 (Algorithm Implementation Requirements)" in the DNSSEC
  docstring; make it "IANA DNSSEC algorithm registries (RFC
  9904, which obsoletes RFC 8624)". Docstring only; the
  generated text is unchanged.

## 2. README

2,180 words, and Key Features alone is 1,029. Target under
1,200 words total, in this order: one paragraph on what it is;
the 12 Security Checks table as it stands (it matches
SCOPE_CHECKS); How Results Are Presented; a short Features
list of one line each (tree walk, SPF trace, defensive DNS,
resilience, anomalies, PDF, scoped audits, vendor detection,
roadmap); Architecture; API; Self-Hosting; Tests; What it does
not do; License; Author.

- Delete "Why RFC 9989 Matters" (79 to 85, 316 words) and
  replace with one sentence linking to
  https://dns-audit.com/articles/dmarcbis. Delete "RFC 9989
  Checker" (122 to 133), which restates the table; fold the
  tree walk line into Features.
- Line 126 "16 layered checks across tokenization, grammar,
  and semantics" is unverifiable (the validator has 29 finding
  codes). Replace with a count taken from the code, for
  example "N finding codes", with N computed in the commit, or
  drop the number.
- Architecture (145 to 163) lists 11 of the 20 root modules.
  List every module that runs in production with a one-line
  purpose, including mx_check.py, spf_intelligence.py,
  dns_tools.py, dns_snapshots.py, config.py, ua_classify.py,
  comprehensive_selectors.py, and under static/ add theme.js,
  articles.js, and articles/. The list must match the tree;
  add a test that every .py file in the root except tests
  appears in the README Architecture block.
- Add Tests: "python3 -m pytest tests/ -q" with the current
  count, "no network in tests (the no_network fixture),
  browser assertions need playwright and chromium
  (requirements-dev.txt)".
- Add What it does not do: no blocklist lookups, no mail
  sending and no SMTP connections (Doc 49 removed the last
  STARTTLS probe; grep smtplib and socket to confirm before
  writing the line), no accounts, no stored audit history
  beyond the 90-day snapshot table.
- Add License: MIT, link to LICENSE.
- Screenshots: keep docs/screenshots/doc-35/home-light.jpg and
  results-light.jpg, delete the other four, and reference the
  two from the README under the first paragraph. If the file
  names change, update them in the README in the same commit.
- Keep the Author block as it is. No email address anywhere in
  the README.

tests/test_doc30_readme_accuracy.py asserts on the README;
keep it passing.

## 3. Files and directories

- Create tools/ and move live_check.py and
  rewrite_audit_log_ua.py into it.
  tests/test_doc30_readme_accuracy.py:19 imports live_check;
  update the import path (tools/__init__.py or a sys.path line
  in the test, whichever matches how conftest already handles
  paths). CLAUDE.md:81 and live_check.py:18 name the old
  paths; fix both.
- Create deploy/ and move dns-auditor.service into it; update
  the path in CLAUDE.md "Deploy".
- docs/live-baseline.txt is a stale run (four Blocklist rows,
  a check removed in Doc 30, and no date). Delete it, and
  change live_check.py:18 to say the output goes wherever the
  operator points it.
- docs/redesign-addendum-homepage.md is referenced by nothing.
  Delete it.
- Rename docs/prompts to docs/history and add
  docs/history/README.md: one line per doc, number and title
  taken from each file's first heading, with a note that docs
  1 to 24 predate the practice of committing them and are not
  in the repo. Update the ALIAS_FILES entry in
  tests/test_no_personal_email_in_repo.py:46 and any other
  path that names docs/prompts (grep, including the "Save this
  doc as" lines only in the history files themselves, which
  stay as written). Add one line to the main README pointing
  at docs/history.
- .gitignore: add .ruff_cache/; delete the duplicate audit.log
  at 99; delete dns_auditor/ at 55 (no such directory exists
  and the pattern would hide a future package).
- .github/ISSUE_TEMPLATE/bug_report.md is the stock GitHub
  template (iPhone6, iOS8.1, "help us improve"). Replace with:
  the domain audited (or "cannot share"), the scope, the
  request ID from the results page, what the card said, what
  it should have said and why (RFC section if known), browser
  and width if it is a display problem.
- SECURITY.md: add the dns@dns-audit.com alias as a second
  private channel beside GitHub's private reporting and
  LinkedIn, and add "SECURITY.md" to ALIAS_FILES in
  tests/test_no_personal_email_in_repo.py so the guard allows
  exactly that address there. Delete the Supported Versions
  table (there are no releases; the site runs main).
- CLAUDE.md: record the droplet's Python version (read it from
  the server with python3 --version during deploy and write it
  in the Deploy section) next to the CI versions 3.11 and
  3.12, so the floor in pyproject is checked against something
  real.

## 4. Modules and tests

- Fold dkim_tag_analyzer.py (3.5 KB) into dkim_formatter.py,
  its only production importer; update the three tests and
  test_no_dashes_in_user_facing_text.py that name it.
- Rename the 37 doc-numbered test files in tests/ to subject
  names (test_doc44_dmarc_grades.py becomes
  test_dmarc_grades.py, test_doc36_header_identical.py becomes
  test_site_header_identical.py, and so on). Keep "Doc N" in
  each file's module docstring so the history is findable.
  Where two renamed files would collide, merge them.
- test_doc36_header_identical.py:43 and
  test_doc39_footer_attribution_identical.py:50 both define
  test_every_static_page_is_covered; move one copy to a shared
  helper or give them distinct names.
- tests/test_normalize_domain.py is a subset of
  tests/test_dns_tools.py; delete it.
  tests/test_dmarc_tree_walk_author_hit.py repeats two cases
  from test_dmarc_tree_walk.py; delete the two duplicates and
  keep any case that is unique.
- Add the Architecture-matches-tree test from item 2.

## Repo rules

No em dashes and no double hyphens in any user-facing text or
the README.
Run python3 -m pytest tests/ -q. All must pass; report the new
count.
No cache-bust needed unless static/ changes; it should not.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/history/doc-51.md in the same commit.

## Done when

The README is under 1,200 words, every claim in it matches the
code, and a test ties its Architecture block to the tree; the
root holds only the modules that run the app plus the standard
files; docs/history has an index; no test file is named for a
doc number; the version floor is 3.10 everywhere; and the full
suite passes.
