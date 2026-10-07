Doc 93: Restore ESP selector reach in DKIM discovery, in one
parallel wave

Re-fetch main before starting. Written against 3368a38.

Problem

Commit 8675be4 (Sep 2) cut smart_dkim_check's max_selectors from
200 to 40 and unioned GENERIC_SELECTORS on top of the cap. That
fixed default being unreachable, but it also pushed 157 selectors
out of reach that the 200 cap used to cover. Among them are the
entire MARKETING_PLATFORMS, TRANSACTIONAL_ESP and CRM_PLATFORMS
blocks: k1 to k6 (master index 62 to 67), s1 and s2 (129, 130),
mandrill, hs1, hs2, kl, cm, pm, mailjet, sendgrid, smtpapi and the
rest. Reproduce with:

  m = COMPREHENSIVE_DKIM_SELECTORS
  g = set(GENERIC_SELECTORS)
  [s for s in m[:200] if s not in m[:40] and s not in g]

Those selectors are now probed only when the vendor's include
appears in the domain's SPF. ESPs commonly use their own
Return-Path domain, so the include is often absent. Two false
outcomes follow. A domain on Google plus Mailchimp gets a DKIM
card listing only the Google key. A domain whose only signer is
an ESP falls through to the generic sweep, misses again, and is
told no DKIM was found.

Fix

1. Add ESP_SELECTORS to comprehensive_selectors.py: the fixed name
   selectors from the marketing, transactional, CRM and support
   blocks that a vendor actually uses at the customer's domain.
   Verify each name against the vendor's current DNS setup
   documentation or a live domain before including it. Drop names
   that are not a real convention (office365, googleapps,
   dynect, yousendit and similar are candidates; check, do not
   assume). Where a vendor uses a per account selector that cannot
   be guessed, leave it out and list it in the report. A short,
   verified list beats a long guessed one.

2. In smart_dkim_check, union ESP_SELECTORS into the priority
   wave, on top of the max_selectors cap and deduplicated against
   it, exactly as GENERIC_SELECTORS was handled for default in
   8675be4. They go out in the same _run_wave call as the vendor
   selectors, so they run concurrently, not as a second
   sequential pass. Leave the generic fallback as it is: it still
   runs only when the priority wave finds nothing.

3. Resize _DKIM_PROBE_WIDTH in audit_engine.py so the pool still
   covers the largest single wave times MAX_CONCURRENT_AUDITS.
   The largest wave is now 40 plus len(ESP_SELECTORS), not 40
   plus the generics, since generics run in chunks of 52 after
   the priority wave. State the arithmetic in the comment.
   tests/test_dkim_discovery_starvation.py must still pass.

4. Check how the DKIM_DROP_THRESHOLD logic interacts with a wider
   first wave. A zone that rate limits could now drop more of the
   priority wave. Report what you observe; do not retune the
   threshold without evidence.

Tests

Add tests/test_esp_selectors_reachable.py modelled on
test_proton_selectors_reachable.py: for a domain with no vendor
in SPF or MX, every ESP_SELECTORS entry is in the first wave. Add
one case where the only published key is k1 and assert it is
found. Add one case where Google is detected from MX and k1 is
also published, and assert both keys are found.

Measure before and after

Run from marmot or the droplet, not a cloud container (TXT
lookups time out there). Use tools/live_check.py or an equivalent
harness, 5 runs each, before and after the change, on: a Google
Workspace domain, a Microsoft 365 domain, a domain signing only
with default, and a domain known to sign with an ESP selector at
the apex. Report DKIM wall time p50 and max, tested_count, and
unanswered_count for each. Target: added p50 under one second per
audit. If it misses, report the numbers and stop; do not trim the
list to hit the target without saying what was cut.

Report back

Commit SHA, test count before and after, the final ESP_SELECTORS
list with the source used to verify each name, the vendors left
out because their selectors are per account, and the timing
table.
