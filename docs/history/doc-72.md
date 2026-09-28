# Doc 72: Audit speed, measure then fix the dominant cost

Main at the tip after the Doc 71 index-line PR. Re-fetch before
starting.

## Problem

Live /api/audit on Sept 28: suckless.org 29.2 s, ietf.org 7.0 s.
The Sept 20 review measured audits over 8 s on eight of fourteen
domains and correlated it with the DKIM selector sweep (ietf.org
tests 196 selectors). That correlation is not a measurement.
Establish the cause before changing anything.

## Step 1, measure (report before fixing)

Time each check in run_full_audit (audit_engine.py ~4644) for
suckless.org, ietf.org, openbsd.org, github.com, paypal.com and
example.com, run from the droplet, cache bypassed. For each domain
report wall time per check and which check sets total wall time.
For DKIM also report selectors probed, how many timed out rather
than answered NXDOMAIN, and the resolver timeout and lifetime in
effect (dns_tools.py ~114).

If DKIM is not the dominant cost on the slow domains, stop and
report. Do not proceed to step 2 on a guess.

## Step 2, fix the dominant cost

Likely shape if DKIM dominates: probes against nameservers that
drop queries each wait out the full lifetime. Options, pick by
what step 1 shows:
- a total wall-clock budget for the DKIM sweep, after which
  unanswered probes count as not confirmed (the card already has
  a not confirmed state; use it, do not report no DKIM)
- a shorter per-probe timeout for the generic sweep only, not for
  selectors named by the user or inferred from SPF vendors
- stop the generic sweep early once the zone shows it drops
  queries (several consecutive timeouts)

Correctness outranks speed. These must still be found:
- protonmail, protonmail2, protonmail3 on proton.me
- Mailchimp k2 and k3
- any selector the user types in
Keep or extend the existing reachability tests for these.

Target: every domain above under 10 s, without any real published
key reading as missing. If the target cannot be met without that
trade, report the numbers and stop.

## Tests

- A fixture zone that drops DKIM queries: the audit finishes inside
  the budget and the card says not confirmed, not absent.
- Existing selector reachability tests still pass.
- CI-style venv run of the full suite.

## Housekeeping in the same PR

- Add the Doc 72 line to docs/history/README.md.
- Save this doc as docs/history/doc-72.md.
- Render the SPF lookup budget bar for paypal.com (9 lookups) and
  box.com (8) in light and dark themes at 1280 and 390. Report
  which class each gets and confirm near is visibly different
  from ok in both themes.

## Rules

- No em dashes or double hyphens in any string.
- One commit, one PR.
- After deploy, report /api/health version and live wall times
  for the six domains, before and after.
