# Doc 77: Plan records drop retired tags, and readiness agrees
# with the plan

Main at 859e27c. Re-fetch before starting.

## Problem

Three findings from the Doc 75 review, confirmed live.

1. Plan rows put retired tags back. The sp row, the weak-np row
   and the optional np row build their records from the published
   record (result_transformer.py:1099, :1105, :1116, each
   _edit_dmarc_record(dmarc["record"], ...)). So on github.com,
   bbc.co.uk and suckless.org the row "Remove the tags RFC 9989
   retired: pct, ri" is followed by an np row whose record has
   pct=100 and ri=86400 again. Following the rows in order undoes
   the first one.

2. proton.me readiness reads "Action needed" in red while its own
   checklist passes. The enforcing-policy-without-rua warning is
   level "critical" (result_transformer.py:3604),
   _calculate_dmarcbis_health turns any critical warning into
   "misconfigured" (~3901), and :529 maps that to "Action needed".
   rua is optional in RFC 7489 and RFC 9989. The settled rule for
   this site is that a missing rua on an enforcing policy is a
   prominent amber warning, not a failure.

3. Readiness and plan disagree about np. Readiness (~3791): "No
   explicit non-existent subdomain policy. Falls back to
   p=quarantine. Consider adding np= to close potential gaps."
   The plan on the same page: "Purely optional. Subdomains already
   inherit your enforcing policy without it." When the fallback is
   enforcing there is no gap (RFC 9989 section 4.7: np, then sp,
   then p).

## Fix

1. One cleaned base for every proposed DMARC record: the published
   record with the retired tags removed. Use one constant for the
   retired set; audit_engine.py:851 has DEPRECATED_TAGS and
   result_transformer.py repeats ("pct", "rf", "ri") at ~1021,
   3563, 3884, 4187 and 4224. Point them all at one source. Every
   plan row, the record builder, the migration path and the
   Deployment box start from the cleaned base, web and PDF.

2. The no-rua warning on an enforcing policy becomes a warning, not
   critical, so it cannot set readiness to misconfigured. The
   readiness label follows the remaining checks (proton.me should
   read what its JSON status already says, compatible). Update the
   consumer at ~906, which matches level "critical" and title
   "No aggregate reporting", so the "Add aggregate reporting" plan
   row still appears at high priority.

3. Readiness np text: when np is absent and the fallback (sp, then
   p) is quarantine or reject, say np is optional and name the
   value it inherits, matching the plan row's meaning. Only suggest
   adding np when the fallback is none.

## Tests

Asserting on transformed output, web data and PDF text:
- A record with pct and ri and p=reject: no proposed record on any
  surface contains pct, rf or ri.
- p=quarantine, no rua: readiness label is not Action needed, the
  card carries the amber rua warning, the plan has the high
  "Add aggregate reporting" row.
- np absent, sp=reject: readiness text does not say gap or suggest
  closing one; plan row says optional.
- np absent, p=none: readiness still suggests np.
- A grep test: ("pct", "rf", "ri") appears as a literal in one place.

CI-style venv run of the full suite.

## Housekeeping

- Save as
