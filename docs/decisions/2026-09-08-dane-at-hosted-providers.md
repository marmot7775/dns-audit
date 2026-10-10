# DANE at hosted mail providers

Date: 2026-09-08. Commit 989b17e (Doc 17 item 1).

## Context

RFC 7672 section 3 puts the TLSA record at the MX host. When the MX belongs
to a provider, that record is the provider's to publish. The DANE card told
every domain without TLSA to "generate a TLSA record", which for a hosted
domain is an instruction for a name the owner does not control: a warning
nobody can clear.

## Decision

The DANE card reads the MX before it advises.

- Google Workspace: informational, no fix. Google publishes no TLSA for its
  MX hosts and does not sign the zone they sit in, so a Workspace domain
  cannot do DANE by any action of its own. The card names MTA-STS as the
  transport protection that does apply.
- Microsoft 365: inbound DANE exists, but the owner enables it in Exchange
  Online, not by publishing TLSA. The fix follows Microsoft's own procedure
  (enable DNSSEC for the domain, add the mx.microsoft MX, move priorities,
  enable inbound DANE), including its warning to put MTA-STS into testing
  first. Microsoft publishes the TLSA.
- Self-hosted MX: the RFC 7672 advice stands. TLSA at the MX host, and DNSSEC
  first, since TLSA is meaningless without it.

## Consequences

- A hosted domain without DANE is not amber.
- Provider facts were verified against live DNS and vendor documentation on
  the date above. When a provider changes, this card has to be re-verified,
  not just re-tested.
