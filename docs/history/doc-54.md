# Doc 54: Rename the repo to dns-audit

The site, the wordmark, and the domain are all dns-audit; the
repo is dns-security-auditor. One name. Line numbers are from
main at f0476c8.

## 1. Rename on GitHub

Run gh repo rename dns-audit from the checkout (gh auth status
first). If gh reports a scope it lacks, stop and say so; the
rename then happens in the GitHub UI (Settings, General,
Repository name) and the rest of this doc runs afterwards.
GitHub redirects the old name for links and clones, so nothing
is broken in between.

## 2. Update the references in the repo

- The GitHub link in the footer of all eight pages:
  static/index.html:325, 330, 332, about.html:89,
  privacy.html:123, 404.html:66, and the four article pages
  (articles/index.html:124, dane.html:115, dnssec.html:189,
  dmarcbis.html:291). Replace
  github.com/marmot7775/dns-security-auditor with
  github.com/marmot7775/dns-audit everywhere, including the
  /security/policy and /blob/main/LICENSE links. The
  identical-footer test must stay green.
- SECURITY.md:5 and :21: "dns-security-auditor" becomes
  "dns-audit".
- CLAUDE.md:1: the heading becomes "# dns-audit". Line 133,
  the deploy command, keeps cd dns-security-auditor, because
  that is the directory name on the droplet and it is not
  being renamed; add a one-line note under it saying the
  droplet directory keeps the old name on purpose.
- deploy/dns-auditor.service:13 and :34 keep the old directory
  name for the same reason.
- pyproject.toml:2: name becomes "dns-audit".
- .gitignore:54: delete the dns-security-auditor/ line; it
  ignores a directory that does not exist.
- docs/history/doc-25.md, doc-26.md and doc-32.md mention the
  old name; they are history and stay as written.

## 3. Point the remotes at the new name

Locally: git remote set-url origin
git@github.com:marmot7775/dns-audit.git (or the https form,
matching what git remote -v shows now). On the droplet, in the
deploy step: ssh in, cd dns-security-auditor, and run the same
set-url with the URL form the droplet uses. Confirm git fetch
works on both before deploying.

## Tests

Add to the site-header or footer test: no tracked file outside
docs/history contains "dns-security-auditor" except
deploy/dns-auditor.service and the CLAUDE.md deploy line,
which name the droplet directory.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since static/ changes.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/history/doc-54.md in the same commit.

## Done when

github.com/marmot7775/dns-audit is the repo, every footer link
on the live site points at it, the old name survives only in
the droplet's directory path and in history, both remotes
fetch from the new name, and the suite passes.
