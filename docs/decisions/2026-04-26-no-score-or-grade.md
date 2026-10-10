# No score or grade

Date: 2026-04-26. Commits 34df7c1, 2d94736, e09e64d.

## Context

Until April 2026 every audit ended in a letter grade from a 100-point
scorer, `security_scoring.py`: DMARC 25, SPF 20, DKIM 15, best practices 20,
key security 10, vendor intelligence 10. A methodology page explained the
weights. The code did implement them, so the case against the grade is not
that it was fake. The case is that a sum lets points in one place buy back a
failure in another. With SPF at zero, the other five categories still added
up to 80, which the scorer graded A. The number said nothing a reader could
act on.

## Decision

No score, no grade, no weighting. Each check reports its own status: pass,
warning, fail, optional and not set up, or not checked. The summary reports
three things that are each true or false on their own: spoofing protection,
RFC 9989 readiness, and protocol coverage. The scorer and the methodology page
were deleted, and /methodology redirects to /about.

## Consequences

- There is no single number to compare domains by, and no "improve your
  score" framing. The roadmap orders fixes by impact instead.
- A new check adds a card, not a weight.
- The commits that removed the grade do not record the reason; this record
  states the one the code supports. Confirm or correct it.
