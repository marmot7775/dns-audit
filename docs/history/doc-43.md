# Doc 43: Origin exposure and four hardening gaps

First doc from the Sept 13 full review. Security only; wording
and correctness come in later docs. Line numbers are from main
at 7ea72c2; re-locate by content if they have moved.

## 1. The public repo names the origin IP and the SSH user, and the origin answers direct traffic

CLAUDE.md:6 "Ubuntu on DigitalOcean (DROPLET_HOST)" and
CLAUDE.md:121 "ssh DEPLOY_USER@DROPLET_HOST".
dns-auditor.service:7 to 9 carry the same username in User and
paths. dns-audit.com is behind Cloudflare, but a request sent
straight to that IP with the Host header set to dns-audit.com
returns the site and /api/health with HTTP 200, so
Cloudflare's rate limiting, WAF, and email obfuscation can all
be bypassed by anyone who reads the repo. The reviewer
confirmed the direct response today.

Fix, in the repo: replace the IP and username in CLAUDE.md
with placeholders (DROPLET_HOST and DEPLOY_USER) and say the
real values live in a local untracked file named
deploy.local.md; add that filename to .gitignore. In
dns-auditor.service, keep it as a template with a placeholder
user and path and say so in a comment at the top. Do not
rewrite git history; the IP stays in past commits, which is
why the next item is the real fix.

Fix, on the droplet (you already deploy over SSH per
CLAUDE.md, so do it in the same session): restrict inbound 80
and 443 to Cloudflare's published ranges. Fetch
https://www.cloudflare.com/ips-v4 and
https://www.cloudflare.com/ips-v6, add a ufw allow rule for
each range to ports 80 and 443, then deny 80 and 443 from
anywhere else. Leave port 22 exactly as it is; do not touch
the SSH rules. Before enabling, confirm ufw status shows 22
allowed, otherwise stop and report. After enabling, verify
from outside: a request to https://dns-audit.com/api/health
through Cloudflare returns 200, and the same request sent to
the origin IP directly (curl --resolve
dns-audit.com:443:ORIGIN_IP) times out or is refused. Report
both results. Put the two commands used, with the placeholder
host, in CLAUDE.md under a new "Origin firewall" heading so
the ranges can be refreshed later.

## 2. MTA-STS policy fetch has no body size cap

checks_extra.py:569 fetches the policy with _safe_fetch and
588 reads resp.text, which loads and gunzips the whole body in
memory. A domain owner can serve a multi hundred megabyte or
gzip bombed policy file at
https://mta-sts.DOMAIN/.well-known/mta-sts.txt, and every
audit of that domain allocates it in the single worker. The
BIMI fetch at 1035 to 1075 already streams with a 1 MB cap
counted on decoded bytes.

Fix: stream the MTA-STS fetch the same way with a 64 KB cap
(RFC 8461 section 3.3 suggests that maximum). Over the cap,
emit a finding "Policy file larger than 64 KB, not read" with
status fail for MTA-STS, and stop reading. Test with a fake
response whose body is 200 KB and assert the check returns the
finding and reads no more than the cap.

## 3. Raw exception text is served to API clients

audit_engine.py:4713, 4775, 4797, and 5078 append f"{label}:
{str(e)}" to the errors list that 5613 returns as "errors" in
the JSON. The DMARC branch at 4757 was already changed to a
fixed string, and the docstring at 6207 says why: str(e) has
leaked filesystem paths before. The reviewer reproduced it by
making the MX check raise an error containing a path; the path
came back in the JSON, and the response is cached for five
minutes. Nothing reads the field: no match in app.js or
pdf_report.py.

Fix: use fixed strings at all four sites ("Tree Walk: check
failed", and so on), matching the DMARC branch. Add a test
that raises an exception with a fake path from each check and
asserts the path does not appear anywhere in the result JSON.
Two lesser sites: audit_engine.py:3576 and 3968 put dnspython
error text into card details, which can include the resolver
address; replace with fixed wording.

## 4. The PDF and streaming endpoints run the audit with no deadline

server.py:791 to 806 give /api/audit a 90 second wall clock
budget and pass deadline= into run_full_audit. server.py:973
(the SSE stream) and 1197 (the PDF) call run_full_audit with
no deadline, so a slow domain requested as a PDF holds a
concurrency slot past Cloudflare's 100 second limit, and the
stream only notices its own 90 second cutoff at the next
progress callback.

Fix: compute the same deadline in both handlers and pass
deadline= exactly as 806 does. Test: patch run_full_audit in
each handler and assert it receives a deadline argument.

## 5. DNS controlled text reaches the explanation unescaped, and the HTML allowlist keeps links

result_transformer.py:5754 appends the TLS-RPT rua
destinations to the explanation without _e(), and app.js
renders explanation through sanitizeHtml, whose allowlist
keeps a, strong, b, em, i, code, and br. The reviewer
published _smtp._tls with a rua of mailto:
href=https://evil.test/verify>Click here to verify your DMARC
now</a> and got a live link inside the TLS-RPT card's own
prose. No script runs; the allowlist strips img and script. A
DNS record owner can still plant a labelled link in the
audit's text.

Fix: wrap the destinations at 5754 in _e(), and do the same at
1927 ({policy}) and 5384 ({providers}) which use the same
pattern. In app.js:3350, escapeHtml uses textContent then
innerHTML, which leaves quotes alone; add replacements for
double and single quotes so the helper is safe inside
attributes (it is used in data-domain and title at 1703 and
1704). Test: a zone whose TLS-RPT rua contains an anchor tag
renders as literal text in the explanation string.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since app.js changes.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-43.md in the same commit,
with the origin IP and username replaced by the placeholders.

## Done when

The repo contains no origin IP and no deploy username, a
direct request to the origin is refused while the site works
through Cloudflare, an oversized MTA-STS policy is a finding
rather than a memory allocation, the errors field carries
fixed strings, every audit path has a deadline, and DNS
controlled text cannot place markup in a card.
