# dns-audit: making the standard visible

dns-audit has the discipline: around 750 tests, repeated cold
reviews, and an accuracy record most tools do not have. What it
does not do is show that to someone who opens the repo. This
session closes that gap. Nothing in it changes behaviour. The
rule that right answers come before everything else still
holds, and any item that would risk a verdict is skipped and
reported.

Work in two phases. Phase 1 is a report and no commits. Phase 2
starts only after Neil has read the report and said which items
to apply.

## Phase 1: inventory

Read the repo fresh and report, item by item, present or
missing, with one line of evidence each.

1. Is there an architecture page a newcomer can read in five
   minutes: what the pipeline is, which module owns what, and
   the rules the code keeps.
2. Is there a record of decisions a newcomer would otherwise
   argue about, with the reason for each.
3. Does the README open with a real audit result, or with
   install instructions.
4. Does the README state what the tool does not do.
5. Do tests, ruff and mypy run in CI on every push and pull
   request, with badges on the README.
6. Is there a CHANGELOG.
7. Does /api/health report the deployed commit, so deploy state
   can be checked from outside.
8. Does pyproject.toml alone define the Python version and the
   dependencies, or do README and requirements.txt also claim
   versions that can drift.
9. How large is audit_engine.py, and how many modules are over
   1000 lines.
10. How many modules, functions and imports are dead. Use a
    tool, not a reading.
11. Are there stale branches on origin or stashes in the
    working tree.
12. Do test names read as rules of the system, or as labels.
13. Is CLAUDE.md agent operating instructions only, or does it
    also carry architecture that belongs in a page for people.
14. Is there a CONTRIBUTING section and a SECURITY.md.

Finish phase 1 with the list of items you recommend, grouped
must, should and taste, each with the effort in minutes and
whether it touches any verdict path. Stop and wait.

## Phase 2: apply what Neil approves

Each item below is one commit. The suite is green after every
commit. ruff and mypy strict are clean at the end of each.

ARCHITECTURE.md. One screen. The pipeline from request to
result to report. A table of modules and what each owns. The
rules the code keeps, written as plain directives: a failed
lookup is reported as not assessed, never as a finding; a
verdict cites the record it read; an out of scope check is
absent from the summary, not passed. Link it from the README.

docs/decisions. One short file per decision, dated, with
context, decision, consequences. Start with the ones already
made and argued: correctness before refactoring; failed lookups
are stated as such; Blocklist removed because it is not a
configuration check; rua missing on an enforcing policy is an
amber warning, not a failure; BIMI is branding, not security;
no scoring model, because the weightings described in the old
About page were never implemented; DANE at hosted providers.
Each one cites the RFC section where one applies.

README. Lead with one real audit result and its evidence, then
one paragraph on running it, then what the tool does not do,
then install and self hosting. Badges for tests, lint and
types at the top. Keep the trust line and the What gets logged
link as they are.

CI. One workflow: pytest, ruff check, ruff format --check, mypy
on the package, on push and pull request. Badges wired to it.
If mypy is not clean today, add it in report only mode and
record the error count in the CHANGELOG as the number to drive
to zero.

Version marker. /api/health returns the deployed commit SHA,
read at startup from the environment or from git describe.
Document it in the README under self hosting.

Single source of truth for packaging. pyproject.toml defines
the Python floor and dependencies. requirements.txt either
goes, or is generated from pyproject with a note saying so.
README states the floor once, by reference.

CHANGELOG. Keep a Changelog format. Seed it from the git log
since the September accuracy work, grouped by the doc that
drove each change, dated.

Cleanup. Delete the branches that are fully merged into main
after confirming each is zero ahead. Drop stale stashes after
listing their contents in the report. Remove dead code found in
phase 1, one module per commit, with the tool output that
proved it dead in the commit message.

CONTRIBUTING and SECURITY.md. CONTRIBUTING: how to run the
suite, the rule that a verdict change needs a test that fails
without it, and that an RFC claim cites its section. SECURITY:
how to report, and that no email address appears in the repo;
contact goes through a form or GitHub.

Test names. Rename tests whose names are labels into rules of
the system. Report any test whose name does not match what it
checks; that is a finding, not a rename.

audit_engine.py. If it is over 3000 lines, propose a split by
check into a checks package, one module per protocol, with the
engine keeping orchestration only. Proposal and module map
only; the split itself is its own session because it touches
every verdict path.

## Out of scope

No new checks. No change to any verdict, grade, wording or
threshold. No redesign of the front end. No change to the
droplet or nginx. Anything that looks like it needs one of
those goes in the report as a question for Neil.

## Reporting

At the end: the commit hashes in order, the test count before
and after, the CI run link, and the questions left for Neil.
