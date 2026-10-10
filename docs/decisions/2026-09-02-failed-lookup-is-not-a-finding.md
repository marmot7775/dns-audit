# A failed lookup is not a finding

Date: 2026-09-02. Commit c34d98d; guarded by
tests/test_failed_lookup_is_not_a_missing_record.py and
tests/test_unavailable_checks_never_pass.py.

## Context

`_lookup_txt` collapsed every DNS outcome to an empty list, so NXDOMAIN (no
record) and SERVFAIL (the query failed) reached the caller as the same value.
One SERVFAIL from a domain's nameserver produced "No DMARC policy published"
and "No SPF record published", with fix text telling the owner to publish
records they already had. A retry a minute later said something different
and nothing explained why. A timed-out blocklist query returned the same None
as a clean result, so a failure read as a clean bill of health.

## Decision

A lookup that did not complete gives the card the status `unavailable`,
labelled "Not checked", and says the query did not complete. It is never a
pass, never a fail, and never a missing record. Everything downstream (the
summary, the plan, anomalies, vendor suggestions) treats it as unknown.
RFC 9989 section 4.10.1 draws the same line for the tree walk: a policy
discovery result has to distinguish "no such record" from "a transient DNS
error".

## Consequences

- Some audits show grey "Not checked" cards. That is a gap in the audit, said
  plainly, not a judgement on the domain.
- A new check must distinguish "the answer was no" from "there was no
  answer", and needs a test that fails when it does not.
