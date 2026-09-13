# Doc 41: Contact lines with the dns@ alias

Copy only. Line numbers are from main at 101900e;
re-locate by content if they have moved.

Two places get a mailto to dns@dns-audit.com beside
the existing LinkedIn link. Nowhere else. No other
address may appear anywhere in the repo; the guard
test from Doc 37 stays as it is, and this alias is
added to its allowlist by exact string in exactly
these two files.

## 1. Footer, all eight pages

Replace the contents of .footer-attribution in
static/index.html, about.html, privacy.html,
404.html, and the four files under static/articles/
with exactly:

Built by Neil Anuskiewicz. Need help with email
deliverability, email security, or DNS?
<a href="mailto:dns@dns-audit.com"
class="footer-link">Email dns@dns-audit.com</a> or
<a href="https://www.linkedin.com/in/neilanuskiewicz/"
target="_blank" rel="noopener"
class="footer-link">message me on LinkedIn</a>.

The identical-footer test from Doc 39 must still
pass.

## 2. Results closing note

static/app.js, _renderContactNote. Replace the
innerHTML string with:

Some of these are a five-minute DNS change. Some are
not. If you want a second opinion on which is which,
this is what I do for a living.
<a href="mailto:dns@dns-audit.com">Email
dns@dns-audit.com</a> or
<a href="https://www.linkedin.com/in/neilanuskiewicz/"
target="_blank" rel="noopener">message me on
LinkedIn</a>.

Keep the condition: the note shows only when the
audit found a fail or a warn.

## 3. Test

Add a test that the string dns@dns-audit.com appears
in the eight footers and in app.js and in no other
tracked file, and that the personal-address guard
from Doc 37 still passes.

## Repo rules

No em dashes and no double hyphens in any
user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since app.js changes.
Commit to a branch, push, merge to main, then
deploy per CLAUDE.md and confirm /api/health
reports the new SHA.
Save this doc as docs/prompts/doc-41.md in the
same commit.

## Done when

Every footer and the results note offer email and
LinkedIn, the alias appears in exactly nine files,
and no other address appears anywhere.
