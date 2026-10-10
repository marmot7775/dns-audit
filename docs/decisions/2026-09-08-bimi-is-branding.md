# BIMI is branding, not security

Date: 2026-09-08. Commit 0e805a2 (Doc 17 item 6); guarded by
tests/test_bimi_is_optional_branding.py.

## Context

A warning means the owner can and probably should do something. Absent BIMI
was amber on the card, a low item on the roadmap, and a high-severity anomaly:
three nags for declining an optional feature. BIMI shows a logo in some
inboxes. It does not stop spoofing, and it depends on DMARC enforcement,
which is the real control.

## Decision

- Nothing published: information, the grey "Optional, not set up" state,
  never counted as a warning.
- Published but unable to work, for example a record under p=none, where no
  client shows the logo: amber, because the owner did something and it does
  not do what they intended. Its anomaly is medium, not high: the cost is a
  missing logo, and no security property is weakened.

## Consequences

- The same line applies to the other optional protocols: MTA-STS, TLS-RPT,
  DNSSEC, CAA and DANE are grey when absent, and amber or red only when what
  is published is weak or broken.
