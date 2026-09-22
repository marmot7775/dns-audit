# Doc 69: The PDF endpoint reports on domains that do not exist

This is the worst thing on the site and it is one missing
call. curl -s
"https://dns-audit.com/api/audit/nonexistent-xyz-9271.com/pdf"
returns 200 and an 81 KB, 13-page report. Its summary page
reads "Your domain has no DMARC record. SPF alone cannot
prevent email spoofing", its biggest risk is "Publish a DMARC
record", and its plan tells the reader to publish a DMARC TXT
record at _dmarc.nonexistent-xyz-9271.com, configure NS
records with the registrar, and publish v=spf1 -all. None of
that was measured. The domain is not in DNS. The JSON API for
the same name refuses correctly:
{"domain":"nonexistent-xyz-9271.com","checks":[],"error":"domain_not_found","error_message":"This
domain does not exist in DNS. Verify the spelling and try
again."}. Reproduced on a second name, typoo-microsft-xyz.com,
same result. Line numbers are from main at 7db71b5.

A PDF carries the site name in the footer of every page and
gets forwarded. A typo in a URL produces a confident,
fabricated audit with that footer on it.

## The cause

server.py:620 defines _preflight_dns_check, which resolves SOA
then NS and returns an error dict for NXDOMAIN, SERVFAIL or
REFUSED, and a timeout. Two of the three entry points call it:
/api/audit at 790 and the SSE stream at 911. The PDF route,
audit_pdf at 1113, never does. It goes straight to
run_full_audit at 1200, and the engine reads a domain that
answers nothing as a domain that publishes nothing, so every
check comes back missing or not configured and the report is
built from that. The error test at 1211 cannot help because
nothing set an error.

## The fix

Call _preflight_dns_check in audit_pdf before the cache lookup
and before _join_or_lead, off the thread the way 790 does, and
when it returns an error return that error to the client
rather than rendering. The route already has the right shape
for this at 1186 to 1192 and again at 1211: a 400 with the
error_message as text/plain. Use the same status and the same
message so the three entry points agree.

Put the guard before the cache read so a nonexistent domain
never lands in the audit cache under its key, and inside the
concurrency reservation and its finally, so the slot is
released on the refusal path.

Then check the whole file for any fourth path that reaches
run_full_audit without the guard, and say in the PR what you
found. There are three call sites today, at 798, 972 and 1200.

## The other half

A refusal is not a failure the reader caused, and 400 with a
bare sentence is what a browser will show as a download error.
Give the PDF route the same wording the JSON route gives, and
confirm by hand what a browser does with it: request the PDF
URL for a nonexistent domain in the local build and say in the
PR what the user actually sees. If it downloads a text file,
say so; do not change the status code to fix the appearance
without telling me first.

## Tests

- A request to /api/audit/<nxdomain>/pdf returns 400, the body
  is the domain_not_found message, and generate_pdf is not
  called. Patch the resolver so the test does not depend on a
  live NXDOMAIN.
- The same for the SERVFAIL and timeout branches of the
  preflight.
- A domain that resolves still returns a PDF with the right
  content type and a non-zero length, so the guard did not
  break the normal path.
- A nonexistent domain requested as a PDF leaves nothing in
  the audit cache under that key.
- Three call sites of run_full_audit, each preceded by a
  preflight call, asserted by reading server.py in the test so
  a fourth entry point cannot be added without one.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
No cache-bust needed unless static/ changes.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA. After
deploy, request the PDF for nonexistent-xyz-9271.com and for
github.com and put both status codes and the first line of
each response in the PR.
Save this doc as docs/history/doc-69.md in the same commit and
add its line to docs/history/README.md.

## Done when

A domain that is not in DNS gets the same refusal from the PDF
endpoint that it gets from the JSON endpoint, no PDF is
rendered for it, a real domain is unaffected, and the suite
passes.
