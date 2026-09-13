# Doc 37: remove the email address from the public repo

The address was removed from the site in b5233ec. It remains in files GitHub renders publicly. Current main is 55bf1c8.

Standing rule this enforces: no email address of Neil's goes anywhere it can be harvested. No plain address and no mailto link in any public web page, public repo file, or committed doc. Public contact paths use LinkedIn or a form.

## 1. SECURITY.md

SECURITY.md:7 read "**Email:** [contact address redacted]". GitHub renders SECURITY.md publicly and links it from the repo's Security tab, so this is as harvestable as a web page.

Replaced the reporting instruction with GitHub private vulnerability reporting, which needs no address: point reporters at the Security tab, Report a vulnerability. Kept the existing response-time language and the credit line. Removed the Email line entirely rather than substituting another address.

Note for Neil, outside this change: private vulnerability reporting has to be switched on once in repo Settings, under Code security, before that button appears.

## 2. Committed prompt docs

These contained the address because the docs told the previous session to save them:

docs/prompts/doc-26.md lines 25 and 60
docs/prompts/doc-30.md line 73
docs/prompts/doc-32.md line 23

Redacted each to a placeholder ([contact address redacted]). The surrounding text still reads as a record of what was done.

## 3. Guard against recurrence

Added tests/test_no_leaked_email_addresses.py, which walks every file `git ls-files` tracks and fails if any of them contains an address at the project domain or a personal mail domain. The banned domains are assembled from string parts inside the test so the test file itself does not contain a live address to match against.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Commit to a branch, push, PR, wait for CI, merge to main, deploy per CLAUDE.md, confirm /api/health reports the new SHA.
Saved this doc as docs/prompts/doc-37.md in the same commit, with no address in it.

## Done when

No tracked file in the repo contains one of Neil's email addresses, SECURITY.md routes reports through GitHub instead, and a test fails the build if an address comes back.
