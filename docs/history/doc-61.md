# Doc 61: The Certificate Transparency check sets the audit's wall time

Measured on the live site, Sept 16: audits of google.com,
github.com, and example.com took 11 to 12 seconds and each
ended with Certificate Transparency "Not checked", while
dns-audit.com took under 3 seconds with CT passing. The
difference is crt.sh. audit_engine.py:3985 to 3993 queries it
with timeout=10, the check runs in Phase 2, and Phase 2 waits
for its slowest member, so a crt.sh timeout adds about 10
seconds to every audit of a domain with a large certificate
history, and produces nothing for it. Line numbers are from
main at 547d947. Nothing about what the check reports changes
when crt.sh does answer.

## 1. Cut the wait

- 3991: timeout=10 becomes timeout=(3, 5): three seconds to
  connect, five to read. crt.sh answers healthy queries in a
  second or two; a domain that has not answered in five
  seconds has not answered in ten either (the three test
  domains above never did). Measure before and after against
  the same three domains and put the wall times in the PR.
- 3985 to 3990: add deduplicate="Y" to the params if crt.sh
  accepts it (its advanced search exposes the option; confirm
  with dns-audit.com that the cert count halves and the active
  count is unchanged). It removes the precertificate
  duplicates the code strips at 4030 anyway, so the response
  is smaller and the server does less work.

## 2. Remember a timeout for a short while

_raw_check_ct at 3918: a timeout is not cached at all (3927 to
3931), so every audit of google.com in a day repeats the wait.
Store a timeout result under the domain with its own TTL,
CT_TIMEOUT_CACHE_TTL = 900, and serve it inside that window
with unavailable_reason "timeout_cached". The stale-cache
fallback at 3928 stays and still wins when a real past result
exists. Keep the 24-hour TTL for successful results.

## 3. Say what happened

result_transformer.py:6878 to 6889: the explanation says
crt.sh "is frequently unavailable", which blames the service
for what is usually the domain's size. Replace the explanation
with: "Certificate Transparency was not assessed. This audit
reads CT data from the public crt.sh service, which did not
answer within five seconds. That is common for domains with
thousands of certificates and says nothing about your
certificates either way. To review them yourself, search this
domain on crt.sh." Keep the link on crt.sh. The detail line at
6886 becomes: "crt.sh did not answer in time. This is a gap in
the audit, not a finding about your domain." For
unavailable_reason "response_too_large" keep the existing
wording.

## Tests

- Patch requests.get to sleep past the read timeout and raise
  Timeout; assert the CT check returns within six seconds and
  the full audit's elapsed_seconds on the Doc 38 fixture is
  under the Phase 2 time of the other checks plus one second.
- Assert a second call for the same domain inside 900 seconds
  does not call requests.get and returns unavailable_reason
  "timeout_cached"; a call after the window does.
- Assert the transformer emits the new explanation for
  "timeout" and "timeout_cached" and the old one for
  "response_too_large".
- The existing CT tests (active validity window, zero active
  on pass, unavailable never passes) keep passing.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
No cache-bust needed; static/ does not change.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA. After
deploy, time an audit of github.com through the live API and
put the number in the PR; it should be well under six seconds.
Save this doc as docs/history/doc-61.md in the same commit and
add its line to docs/history/README.md.

## Done when

An audit of a domain crt.sh cannot answer for finishes in
about the time the other checks take, repeats within 15
minutes do not wait again, the Not checked card says why in
plain words, and the suite passes.
