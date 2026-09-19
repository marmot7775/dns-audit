# Doc 62: Explicit SPF qualifiers get a valid record failed

Reproduced on the live site at 22268d6. bbc.co.uk publishes
one TXT string: v=spf1 ip4:212.58.224.0/19 ip4:132.185.0.0/16
+include:spf.sis.bbc.co.uk +include:spf.messagelabs.com ~all.
The audit shows the record as "... /16 +
include:spf.sis.bbc.co.uk + include:spf.messagelabs.com ~all",
grades SPF fail, and prints three false statements: "The SPF
record has mechanisms jammed together without spaces, likely
caused by multi-string TXT record configuration in DNS", two
rows of "'' is not a recognized SPF mechanism or modifier",
and a HIGH priority "Ensure each mechanism in the SPF record
is separated by a space". The PDF's SPF mechanism table gets
two rows whose mechanism is a bare +. The record is valid RFC
7208; an explicit + qualifier on include is legal and common.
Line numbers are from main at 22268d6.

## The cause

spf_recursive.py:26 repair_spf_missing_spaces exists for
jammed multi-string TXT records such as
v=spf1ip4:1.2.3.0/22include:example.com~all. Its pattern at
line 61 is (?<=\S) followed by the SPLIT_BEFORE alternatives,
so it inserts a space before include:, ip4:, ip6:, exists:,
redirect=, and exp= whenever the preceding character is not
whitespace. A qualifier character is not whitespace, so
+include: becomes "+ include:", and the same happens for -, ~,
and ? on any of those mechanisms. The stray qualifier then
parses as an empty mechanism at audit_engine.py:2615, and the
record is reported malformed at audit_engine.py:2429 to 2445.
Confirm with python3 -c "from spf_recursive import
repair_spf_missing_spaces as r; print(r('v=spf1 -ip4:1.2.3.4
?include:x.com -all'))", which returns "v=spf1 - ip4:1.2.3.4 ?
include:x.com -all".

## The fix

Change the lookbehind so a split happens only when the
preceding character could end a mechanism token: not
whitespace and not one of the four qualifier characters.
(?<=[^\s+~?-]) does it. A hostname label cannot end in a
hyphen and an IP or CIDR cannot end in any of the four, so
nothing legitimate is lost. Leave the SPLIT_BEFORE list, the
-all guard, and the v=spf1 rule as they are.

Then check the rest of the SPF path for the same assumption:
anywhere a mechanism is matched by prefix without allowing an
optional qualifier first. The parser at audit_engine.py:2459
onward strips the qualifier, so it should be fine, but confirm
that include, ip4, ip6, exists, and redirect with an explicit
+ or - each parse to the same mechanism name and target as the
unqualified form, and that a qualified include is followed in
the recursive lookup count.

## Tests

In tests/test_spf_repair_token_boundary.py add cases:

- The bbc.co.uk record above comes back unchanged with
  malformed False.
- "v=spf1 -ip4:1.2.3.4 ?include:x.com ~exists:%{i}.x.com
  +redirect=y.com" comes back unchanged with malformed False.
- The jammed cases the function exists for still repair:
  "v=spf1ip4:1.2.3.0/22include:example.com~all" and "v=spf1
  ip4:1.2.3.4~all".
- A full audit against a fake zone publishing the bbc.co.uk
  record grades SPF pass or warn on its real properties only
  (the /16 breadth warning is fine), with no "jammed together"
  issue, no empty mechanism issue, no space-separation item in
  Priorities, and the record shown verbatim.
- The PDF for that fixture has no mechanism row whose name is
  a bare qualifier.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
No cache-bust needed; static/ does not change.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA. After
deploy, audit bbc.co.uk through the live API and confirm the
SPF card no longer reports the record as malformed; put the
before and after status in the PR.
Save this doc as docs/history/doc-62.md in the same commit and
add its line to docs/history/README.md.

## Done when

A record with explicit qualifiers on include, ip4, ip6,
exists, or redirect is shown as published, graded on what it
says, and produces no malformed-record finding; jammed records
still repair; and the suite passes.
