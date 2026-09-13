# Doc 44: DMARC evaluation grades and verdicts that the RFC does not support

Second doc from the Sept 13 review. Every item changes what a
user is told about a DMARC record. Line numbers are from main
at 72fa144; re-locate by content if they have moved. All
reproductions ran offline through run_full_audit with
tests/conftest.py FakeZone; write the new tests the same way,
through the transformer, not with hand built cards.

## 1. Any syntax error grades the card fail, including ones receivers must ignore

result_transformer.py:1817 to 1824: if raw has any
syntax_errors or any error severity issue, status becomes
fail. Every entry _raw_check_dmarc puts in syntax_errors is
severity error. RFC 9989 section 4.8: unknown tags MUST be
ignored, and syntax errors in the rest of the record are
discarded in favour of defaults. The record stays valid and p=
still applies.

Reproduced: "v=DMARC1; p=reject; rua=mailto:d@example.test;
foo=bar" renders a red Fail card whose own verdict line reads
"p=reject (authentication failures are rejected)". Same for
adkim=x, fo=2, pct=abc, ri=-5, rf=iodef. The executive
summary, biggest risk box, and PDF cover inherit the fail.

Fix: keep each of these as a warning detail, and grade the
card warn. Reserve fail for what actually invalidates the
record: v=DMARC1 not first, no usable p with no valid rua,
more than one record at the name, or a record the parser
cannot read at all. While there: audit_engine.py:1792 and 2040
say "No policy tag. Every DMARC record requires p=" and fail
the strict validation, but the recovery block at 1348 to 1400
already implements the p tag rule in RFC 9989 section 4.7
(absent p with a valid rua is treated as p=none). Make the
strict validator agree with the recovery block: absent p with
valid rua is a warning that names the rule, not a structural
failure.

Test: the six records above each produce status warn with
p=reject in the verdict; "v=DMARC1; rua=mailto:d@example.test"
produces warn with an effective policy of none; "p=reject;
v=DMARC1" and two records at _dmarc still fail.

## 2. A tag order rule RFC 9989 does not have

audit_engine.py:1278 to 1286 adds a syntax error when p is not
the second tag, citing RFC 7489. RFC 9989 section 4.8 ABNF is
dmarc-version followed by any tags in any order. Reproduced:
"v=DMARC1; rua=mailto:d@example.test; p=reject" is a fail card
with the detail "RFC 7489 requires the policy tag (p=) to
appear immediately after v=DMARC1". Delete the block. Only v
must be first, which check 2 at 1774 already enforces.

## 3. Whitespace around the equals sign is rejected

audit_engine.py:1748 and 2009 match each token with
^key=value$ and no whitespace around the equals. RFC 9989
section 4.8: equals = *WSP "=" *WSP. Reproduced: "v=DMARC1; p
= reject; rua=mailto:d@example.test" gives MALFORMED_TAG and
P_MISSING in the strict validator, summary "This record has
errors that RFC 9989-compliant receivers will reject", while
the main card on the same page passes it. Fix: \s*=\s* in both
regexes. Test: that record passes strict validation with no
structural error.

## 4. The tree walk and the DMARC card do not agree on what a DMARC record is

dmarc_tree_walk.py:186 filters with
txt.strip().startswith("v=DMARC1"); the DMARC check, the
subdomain probe, and checks_extra all use
dns_tools.is_dmarc_version_tag, which allows the whitespace
RFC 9989 section 5.4 allows. dmarc_tree_walk.py:184 also
decodes with no errors="replace", so one undecodable byte
turns a level into LOOKUP_FAILED. Reproduced: a subdomain
publishing "v = DMARC1; p=none" under a parent at p=reject:
the card says p=none, the tree walk section on the same page
says policy inherited from the parent, reject. Fix: use
is_dmarc_version_tag and errors="replace", as the comment at
audit_engine.py:4468 says was done everywhere else.

## 5. A non-existent subdomain skips sp and lands on p

dmarc_tree_walk.py:550 to 556: when the Author Domain does not
exist and np is absent, the walk applies p directly. RFC 9989
section 4.7, np: if np is absent, the sp policy applies when
sp is present, otherwise p. Reproduced: ghost.parent.test
under "v=DMARC1; p=reject; sp=quarantine" gives "Effective
policy: reject" and "Applied tag: p= from parent.test". The
site's own tag table on the same page says np falls back to sp
then p. Fix: in the not author_exists branch, check sp before
p and label the applied tag accordingly. Test: the record
above yields quarantine via sp for a name that does not exist.

## 6. A clean p=reject domain is told it only partly blocks spoofing

result_transformer.py:2484 to 2492: when np is absent, the
Non-Existent Subdomain vector is partial and amber with the
note "Protected by fallback, but not explicitly. RFC 9989
recommends setting np= directly." RFC 9989 section 4.7 marks
np OPTIONAL and recommends nothing of the kind; absent np
falls to sp then p, so a p=reject domain already rejects
invented subdomains. The vector's own detail line says
"Invented subdomains ... are blocked."

That one partial drives everything above it. Reproduced on
"v=DMARC1; p=reject; rua=..." with SPF and DKIM:
build_executive_summary at 339 prints "Your domain partially
blocks spoofed email but enforcement could be stronger", the
attack surface at 2566 onward prints "Moderate Risk", and the
easiest path line says an invented subdomain is open "because
there is no np policy", while page 3 of the same PDF calls np
"Purely optional".

Fix: status protected, colour green, when the effective policy
for non-existent subdomains is reject, whether it came from
np, sp, or p. Keep the suggestion to make it explicit as an
info line, not as a lower status. Then 339 and the easiest
path branch never fire for this case.

Two related colour disagreements on the same page:

- The attack surface block at 2566 to 2570 grades a published
  p=none record "Critical Risk" in red, which app.js:1652
  renders as a red tag on a card whose header pill is amber
  Warning. Doc 38 made the Spoofing Protection tile amber
  "Monitoring only" for the same record. Make the block match:
  a published record at p=none is moderate, amber; red is for
  no usable record.
- The RFC 9989 readiness block inside the DMARC card
  (app.js:2406 to 2418) maps non_compliant to a red "Needs
  Update" tag while the executive summary tile for the same
  result reads "In Progress" in amber
  (result_transformer.py:407 to 409). One label and one colour
  per result: have the card block read the tile's label and
  colour from the executive summary instead of keeping its own
  table.

## 7. Doc 38's warn rules that the transformer never implemented

Doc 38 defined warn as "published and working but weak:
p=none, pct below 100, sp weaker than p, SPF ~all, DKIM
1024-bit key, MTA-STS mode testing, DMARC without rua".
CLAUDE.md repeats it. Three are not implemented and one is
over-implemented:

- SPF ~all: result_transformer.py:4159 lists it as a good
  detail and 4203 grades pass. "v=spf1 mx ~all" is a green
  card.
- sp weaker than p: 2031 adds a warning detail only.
  "v=DMARC1; p=reject; sp=none; rua=..." is a green Pass card.
- MTA-STS mode testing: 5507 passes the raw ok status straight
  through, and 5569 prints "Monitoring TLS, not yet enforcing"
  on a green card.
- The other direction: 1809 grades p=none without rua as fail
  with the comment "critical failure". A published record that
  enforces nothing and reports nothing is weak, not broken;
  Doc 38 puts both halves under warn.

Fix all four so status follows the rule.
tests/test_doc38_status_semantics.py:171 and 323 hand build
cards with status warn and never run the transformer, which is
how this stayed green; rewrite those cases to run
run_full_audit on a fixture zone and assert the status the
transformer produces.

## 8. pct wording assumes quarantine, and the pct impact line is wrong for reject

result_transformer.py:2049 to 2053: for a record at p=none the
pct detail says "RFC 9989 receivers ignore pct and quarantine
all of them", which describes a quarantine policy. At p=none
nothing is applied to any fraction. Gate the sentence on the
policy: at none, "pct has no effect at p=none: there is no
action to apply to a fraction of failing mail. Remove it; RFC
9989 removed the tag." At quarantine, the current sentence. At
reject, "RFC 7489 receivers reject the selected fraction and
quarantine the rest (RFC 7489 section 6.6.4); RFC 9989
receivers ignore pct and reject all of them."

audit_engine.py:240 to 244, BUSINESS_RISK DMARC_PCT_LOW: "so a
fraction of spoofed mail still reaches inboxes" is wrong at
reject, where the unselected fraction is quarantined, and
result_transformer.py:2401 already says so. Replace with:
"Partial enforcement applies the published policy to only part
of the failing mail; the rest gets the next weaker treatment,
quarantine under p=reject and none under p=quarantine."

## 9. The subdomain callout counts names that do not exist as real

result_transformer.py:1428 to 1431 prints "affects
{total_exposed} real subdomains, not just theoretical ones"
where total_exposed counts every probed name. On the fixture
it says 20 real subdomains above a table where 19 rows say
Exists: No, and on an empty domain it says "0 subdomains
discovered ... 20 subdomains exposed". Use the count of names
that exist (the exposed_exist and exposed_mail fields the
transformer already computes) and name them when there are
three or fewer: "affects 1 subdomain that exists,
mail.example.test".

## 10. The fix tells the reader to review reports the record does not request

result_transformer.py:2110: for "v=DMARC1; p=none" with no rua
the fix reads "Review your DMARC aggregate reports to identify
all legitimate senders..." while the details on the same card
say no reports are being received. Gate it: when rua is
absent, "Add an rua address first; without it there are no
reports to review. Then review them until every legitimate
sender aligns before moving to p=quarantine."

## 11. The tag table prints tags that are not in the record as if they were

result_transformer.py:2947 to 2949 (rf) and the matching ri
branch: when the tag is absent, the row prints a value
("afrf", "86400") with a Deprecated badge, so a record that
contains neither rf nor ri shows two rows a reader will go
looking for. sp, np, ruf, and t on the same table correctly
print "(absent)". Do the same for rf and ri: value "(absent)",
no badge, explanation "Not in this record. RFC 9989 removed
the tag."

Terminology while there: the same tags are called "Deprecated"
in the table column, at 3272 to 3274, at 3470 ("Deprecated
tags: pct"), and at 3889 to 3890, and "Removed" in the pct row
and the article. RFC 9989 Appendix C.5.2 is titled Tags
Removed. Use "removed" everywhere: the badge, the finding
title at 3272 ("Removed tags present"), the reason at 3470
("Removed tags: pct"), and the two builder lines.

## Tests

One fixture zone per item, run through run_full_audit,
asserting on the transformed card, the executive summary
verdict, and the attack surface overall where the item touches
them. Assert on rendered PDF text for items 6 and 11, since
both showed up on the cover or in the tag table.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since app.js changes.
Update the Doc 38 status paragraph in CLAUDE.md if any wording
there no longer matches.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-44.md in the same commit.

## Done when

A valid record with an unknown or malformed optional tag is a
warning, not a failure; tag order and whitespace follow RFC
9989 section 4.8; the tree walk reads records the way the card
does and falls back np, sp, p; a p=reject domain without np is
fully protected on every surface; the four Doc 38 warn rules
produce warn; pct wording matches the policy; the subdomain
count counts subdomains that exist; the no-rua fix does not
point at reports; and the tag table shows absent tags as
absent.
