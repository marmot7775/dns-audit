# Doc 37: Remove my email address from the repo

Hard rule for this repo from now on: no personal
email address appears in any file. Public contact
goes through LinkedIn or GitHub private
vulnerability reporting. Line numbers are from main
at 55bf1c8.

The address was removed from the live site in
b5233ec. Four committed files still carry it.

## 1. SECURITY.md

Line 7: **Email:** [address removed]

Replace that line with:

**Report privately:** use GitHub's private
vulnerability reporting on this repository
(Security tab, Report a vulnerability). If that is
not available to you, message me on
https://www.linkedin.com/in/neilanuskiewicz/ and I
will open a private channel.

Everything else in SECURITY.md stays.

## 2. docs/prompts

docs/prompts/doc-26.md lines 25 and 60,
docs/prompts/doc-30.md line 73 (two addresses on
that line), docs/prompts/doc-32.md line 23. These
are archived prompt docs, so do not rewrite them
into something they never said. Replace each
address with the literal text [address removed]
and leave the surrounding sentence intact.

## 3. Test

Add tests/test_no_personal_email_in_repo.py. It
walks every tracked file in the repo (git ls-files)
and fails if any file contains an address at
dns-audit.com, icloud.com, gmail.com, outlook.com,
or hotmail.com. The only allowed match is
user@gmail.com in tests/test_dns_tools.py, which is
a synthetic fixture; allowlist that one occurrence
by file and string, not by pattern. Do not put any
real address in the test file, not even as a
negative example. The test must also cover
docs/prompts so a future prompt doc cannot
reintroduce one.

## 4. Git history

Four earlier commits contain the address in their
diffs. Leave history alone; rewriting main on a
public repo costs more than it hides, and the
address is already out of every current file after
this doc. Say in the PR description that history
was deliberately not rewritten.

## Repo rules

No em dashes and no double hyphens in any
user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
No cache-bust needed; no static asset changes.
Commit to a branch, push, merge to main, then
deploy per CLAUDE.md and confirm /api/health
reports the new SHA.
Save this doc as docs/prompts/doc-37.md in the same
commit. This doc contains one address in the file
list above; replace it with [address removed]
before saving, and the new test will confirm it.

## Done when

git grep for the five domains above returns only
the allowlisted fixture line, SECURITY.md points to
private vulnerability reporting and LinkedIn, and
the test passes.
