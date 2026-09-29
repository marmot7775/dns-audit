# Doc 83: DMARC card at p=reject with no DKIM key found

## Context

The p=reject article says a domain at p=reject without DKIM
should not exist, because RFC 9989 sections 7.4 and 8 say a
domain at reject must sign with DKIM and must not rely on SPF
alone. The audit needs to say the same thing when it sees that
combination.

## Step 1: report before changing

Read the DMARC card, the anomaly detector and the plan builder
and report what the audit says today for a domain whose DMARC
policy is p=reject and whose DKIM selector sweep found no key.
Say whether any existing finding, anomaly or plan row already
covers it. If one does, stop and report its wording instead of
adding a second one.

## Step 2: the finding

If nothing covers it, add one warn level finding on the DMARC
card, not a fail, because the sweep cannot prove a domain does
not sign; it can only report that none of the selectors it tried
has a key. Wording, verbatim:

Card line: p=reject with no DKIM key found

What we found: The audit found no DKIM key at any of the
selectors it tried. If this domain signs with a selector the
sweep does not know, enter it in the selector field and run the
audit again. If it does not sign, this record is ahead of the
standard. RFC 9989 says a domain at p=reject must sign its mail
with DKIM and must not rely on SPF alone, because forwarding
breaks SPF and leaves DKIM intact.

Plan row, action: Confirm DKIM signing on every sending platform
before staying at p=reject.

Plan row, why it matters: Any message that passes only on SPF
fails DMARC the moment it is forwarded, and at p=reject the
receiver bounces it.

Plan row, what to change: Turn on DKIM signing with this domain
at every platform that sends as it. If one platform cannot sign,
move the policy to p=quarantine until it can.

Plan row, how to confirm: Every source in the aggregate reports
that belongs to you shows an aligned DKIM pass.

The finding does not fire when the domain sends no mail (null
MX, or an SPF record that authorizes nothing). It does not fire
at p=quarantine or p=none. It fires on a subdomain only if the
subdomain has its own DMARC record at p=reject, not when the
policy is inherited.

The same strings feed the PDF through the plan rows, as with the
other findings. No em dashes, no double hyphens; the string test
that guards generated wording must pass.

## Verification

Unit tests for: fires at p=reject with no key; does not fire when
a key is found; does not fire at p=quarantine; does not fire on a
no mail domain; does not fire on an inherited subdomain policy.
Render a real domain in that state if you can find one, otherwise
the fixture, at 1280 and 390 in both themes. Deploy, then report
main SHA and /api/health.

## What shipped

The finding shipped at f069071 in PR #108 as a grey info note on the
DMARC card titled DKIM required at p=reject, not as a warn level
finding, and with no plan row. This is the settled decision. The
selector probe cannot tell an unsigned domain from one that signs with
a selector it did not guess, so a warning would misstate the domain.
The note changes no card status, health verdict, plan row or summary.

PR #109 at f015ca1 made two changes to that note:

- At p=reject the note replaces the older cross check row (DMARC
  enforcement has a working SPF path, or relies solely on SPF when a
  named selector has no key), so the card states the gap once. At
  p=quarantine the note does not fire and that row stays.
- The exclusion for a reject inherited through sp= is restored. PR #108
  fired on an inherited reject; that was never deliberate, because the
  session that built it did not have this doc. The exclusion is also
  right on its merits: under relaxed alignment a subdomain can sign
  with the parent's keys, which a probe of the subdomain never sees.
