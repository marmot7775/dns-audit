# Doc 76: Inherited subdomains are judged by the policy that
# applies to them

Main at c9820b0. Re-fetch before starting.

## Problem

Doc 75 review, confirmed live on mail.github.com (no DMARC record
at its own name; github.com publishes p=quarantine; sp=reject).
The DMARC card is right: "Effective policy: reject (inherited from
github.com)". Three other surfaces use the parent's record as if it
were the subdomain's own:

1. Advice to publish the parent's record at the subdomain.
   PDF "What to do" (pdf_report.py:730) prints "TXT record at
   _dmarc.mail.github.com" with v=DMARC1; p=quarantine; sp=reject;
   ... and the web Deployment box says "Host:
   _dmarc.mail.github.com / Replace your existing DMARC record."
   There is no record there to replace. result_transformer.py:1034
   and :1103 take the record from dmarc["record"], the parent's.
   Following it would downgrade the subdomain from reject to
   quarantine: a record at the name itself is used and the parent
   is never consulted (RFC 7489 section 6.6.3; RFC 9989 tree walk
   starts at the domain itself).

2. Summary judged on the parent's p, not the effective policy.
   Summary and PDF cover: "Your domain partially blocks spoofed
   email but enforcement could be stronger." Tile: Direct Domain
   Spoofing only partly protected. PDF Attack Surface: "Partial /
   Spoofed mail goes to spam". result_transformer.py:2799 to 2805
   takes the policy == "quarantine" branch from the parent's p;
   verdict at :452. mail.github.com exists, so sp=reject applies.

3. False anomaly. anomaly_detector.py:72 to 82 fires "DMARC is set
   to reject but no SPF record was found. SPF alignment can never
   pass ... Publish an SPF record (e.g. v=spf1 include:your-esp.com
   ~all)". The plan on the same page says publish null SPF
   (v=spf1 -all). The alignment claim is false under relaxed
   alignment (no aspf means r): RFC 7489 section 3.1.2, identifiers
   align when their Organizational Domains match, so a MAIL FROM at
   github.com aligns for mail.github.com.

## Fix

One effective-policy value for the audited name, computed once
and used by every surface:
- record at the name itself: its p
- inherited, name exists: parent's sp if set, else parent's p
- inherited, name does not exist: np, then sp, then p
  (RFC 9989 section 4.7)
The DMARC card already gets this right; reuse its source rather
than adding a second calculation.

Summary, tiles, Attack Surface (web and PDF), cover verdict and
biggest risk read the effective policy.

For an inherited subdomain, DMARC plan rows and the Deployment box
do not offer a record at the subdomain's name. Where a change is
still worth making (a retired tag, a weak sp at the parent), the
row says the change belongs at the organizational domain, names
_dmarc.<org domain> as the host, and the record is the parent's
edited record. When the effective policy is already reject and the
only issue is at the parent, one short line is enough: the policy
is inherited from <org domain> and changes are made there.

Anomaly: drop the no-SPF anomaly when the name has no MX (the plan
row already gives the null SPF advice, so one surface speaks).
Otherwise state only what is true: SPF alignment cannot pass only
when aspf=s; with relaxed alignment, say that mail using this name
as the envelope sender gets no SPF result and relies on DKIM or on
an envelope sender at the organizational domain.

## Tests

Fixture zones, asserting on transformed output (summary, tiles,
attack surface, plan rows, deployment box, anomalies, PDF text):
- inherited subdomain, parent p=quarantine sp=reject: reads as
  reject everywhere; no row or box names _dmarc.<subdomain> as a
  host to publish; no "partially blocks".
- inherited subdomain, parent p=reject no sp: reject everywhere.
- inherited subdomain, parent p=reject sp=none: reads as none, and
  the fix row names the parent as the host.
- subdomain with its own record: unchanged from today.
- no-MX inherited subdomain with no SPF: no anomaly, one null SPF
  plan row.
- aspf=s parent, subdomain with MX and no SPF: anomaly present
  with the strict-alignment wording.

CI-style venv run of the full suite.

## Housekeeping

- Save as docs/history/doc-76.md, add its line to
  docs/history/README.md.
- Cache-bust static assets if app.js changes.

## Rules

- No em dashes or double hyphens in any string.
- One commit, one PR.
- After deploy, report /api/health version and the live
  mail.github.com summary line, Attack Surface row, DMARC plan rows
  and anomalies, web and PDF.
