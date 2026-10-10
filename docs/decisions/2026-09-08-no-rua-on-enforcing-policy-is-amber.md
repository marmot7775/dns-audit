# No rua on an enforcing policy is amber

Date: 2026-09-08. Commit fdf1e8c (Doc 17 item 3).

## Context

rua is optional: RFC 7489 section 6.3 and RFC 9989 section 4.7. A record with
p=reject and no rua is valid and the policy applies in full. The card first
failed it, which was wrong, then showed it green. Green says there is nothing
to look at, but the owner cannot see what their own enforcing policy is
rejecting, including their own legitimate mail.

## Decision

An enforcing DMARC policy (p=quarantine or p=reject) with no valid rua is
amber, "Could be stronger". It is not a failure, and the verdict still says
the policy applies to everything. A DMARC record counts as broken only when
it has no usable p= and no valid rua=, among the other conditions in
CLAUDE.md, so a missing rua alone never turns it red.

## Consequences

- RFC 9989 "Ready" additionally asks for rua, which the RFC itself does not;
  the README says so.
- A no-mail domain (null MX, v=spf1 -all, p=reject) is not warned about rua:
  there is no mail for reports to describe.
