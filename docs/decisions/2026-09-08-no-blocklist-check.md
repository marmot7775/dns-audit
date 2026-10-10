# No blocklist check

Date: 2026-09-08. Commit aacccd5 (Doc 17 item 7).

## Context

The Blocklist card queried Spamhaus for the domain. It never returned a result
in production: Spamhaus refuses DNSBL queries from public and cloud
resolvers, and this service runs on both, so every live audit showed "Not
checked". Working, it would still have tested the domain list only, not the
sending IPs, so it answered half the question. And a listing is a reputation
event, not a DNS configuration, which is what every other card judges.

## Decision

The check is removed: raw check, card, scope entries, roadmap step, PDF
section and front-end entries. The DNS infrastructure card carries one
information line saying this audit does not check blocklists, why the answer
would not be reliable from here, and where to get one (check.spamhaus.org).

## Consequences

- The README's "What it does not do" says so, and
  tests/test_readme_accuracy.py fails if "Blocklist" reappears elsewhere in
  the README or on a site page.
- Bringing it back would need a resolver Spamhaus answers and a source of
  sending IPs. Both are outside a domain-only audit.
