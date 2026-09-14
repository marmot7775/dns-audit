# Doc 49: Dead code, dead output, and audit speed

Seventh doc from the Sept 13 review. Nothing here changes what
a user reads; it removes code that runs for no reader, fixes
two features that silently never worked, and makes a single
audit faster. Line numbers are from main at e1f3506; search
for the quoted name if one has moved. Before deleting
anything, grep the whole repo including tests, static/app.js,
and pdf_report.py for the name, and treat a hit in a test that
exists only to exercise the dead code as confirmation, not as
a use.

## 1. Output computed on every audit that nothing reads

- remediation_plan: audit_engine.py:5486 calls
  build_remediation_plan (remediation_planner.py, 418 lines)
  on every audit and the result goes into the JSON at 5489
  onward. Zero reads in app.js or pdf_report.py. Remove the
  call, the field, and the module. anomaly_detector.py imports
  _is_ed25519 from it; move that helper to dkim_formatter.py
  first.
- ttl_map at 5635: unread. Remove.
- errors at the top level: Doc 43 made its strings fixed, and
  nothing reads it. Remove the field.
- priority_fixes: Doc 38 kept it for one release. Remove it
  and its builder.
- Per-check fields: for each of dane_deep, mta_sts_deep,
  tls_rpt_deep, records_found, and any other key a transform
  function emits, grep app.js and pdf_report.py. Remove the
  ones neither reads. Keep fix (the PDF renders it),
  configured, unavailable_kind, and anything the executive
  summary or roadmap consumes.
- Sub-object fields the front end never reads:
  security_roadmap.summary, total, unread_protocols,
  unscoped_protocols; report_chain.report_auth_issues;
  report_destinations[].authorization_record;
  subdomains[].category, policy_source, dmarc_record;
  change_detection.first_seen, message; vendors[].confidence;
  executive_summary.biggest_risk_severity. Same rule: remove
  what neither app.js nor pdf_report.py reads, unless a test
  asserts on it for a reason the test states.
- The vendor intelligence report and the fingerprinter's own
  report object are built per audit and read by nothing;
  _fingerprint_mta_sts and _fingerprint_bimi in
  advanced_fingerprinting.py produce no signals at all. Remove
  the report generation and the two empty methods.

Say in the commit message which JSON fields left the API.

## 2. Two features that never worked

- dns_snapshots.py:151 stores dnssec.get("dnskey_record"),
  which _raw_check_dnssec never sets, and 138 onward reads the
  DANE result's "record" key where the check emits "records".
  So DNSSEC and DANE change tracking have never stored a row,
  result_transformer.py's dnssec change type is unreachable,
  and the current_value it computes is unused. Fix the two
  keys so both protocols are tracked, and add a test that
  stores and re-reads a snapshot for each.
- static/app.js:3916 _initComparisonMode returns at once
  because it looks up #results-banner and the element is
  #domain-banner, so _renderComparison and about 130 lines
  plus 15 CSS rules (.comparison-*, .compare-btn) have never
  run. This is a feature nobody has seen; do not revive it.
  Delete the two functions, their CSS, and the call at 925.

## 3. Functions and branches nothing calls

Delete, with any test that exists only to exercise them:

- spf_execution_engine.py:471 build_dmarc_roadmap (246 lines;
  it also still carries "2-4 weeks" strings that the site's
  rules forbid).
- dns_snapshots.py:175 get_history.
- pdf_report.py:150 _sev.
- spf_recursive.py:139 _get_spf_record.
- spf_intelligence.py:246 get_prioritized_selectors (only its
  __main__ block calls it; remove that block too).
- dns_tools.py:312 audit_dns_security (only named in the
  pdf_report.py module docstring, with a dkim_selectors
  keyword that does not exist; fix that docstring).
- mx_check.py:139 _check_ptr and the ptr_results and fcrdns
  fields it fills at 342; nothing reads them, and item 5 below
  measures what they cost. Also the deep_scan path and
  _check_starttls at 225 onward, which no production caller
  enables.
- audit_engine.py:1026 the "*" in domain branch
  (DOMAIN_PATTERN already rejects wildcards), and the v=DMARC
  without the 1 branch a few lines below the version gate,
  which cannot be reached.
- The two-part TLD fallback tables at audit_engine.py:667 and
  dmarc_tree_walk.py:95, dead while tldextract is a pinned
  dependency, as their own comments say. Remove the tables and
  the fallback path.
- static/app.js:209, the #edu-toggle block for elements no
  page contains, and the .edu-* CSS family it was for. Unused
  locals: val near the DKIM revoked text, _toastQueue at 3584,
  and catClass at 2857 and 3072, which is computed and never
  applied to the element (that is why the .se-vendor-* rules
  never match; either apply the class or delete both the local
  and the rules).

## 4. Dead and duplicated CSS

static/style.css is 8,500 lines and 203 KB. The reviewer's
static pass found 113 rules (about 16 KB) whose selectors
match nothing in any HTML file or any string in app.js,
articles.js, or theme.js, and a runtime pass over every page
and state found 306 of 1,433 selectors that never matched.
Reproduce the static pass: parse the stylesheet, extract every
class and id from each selector, and call a selector dead when
no token appears in the HTML or the three JS files, allowing
any class that starts with a prefix used in a template string
such as tag-, es-color-, sua-row-. Then delete what is dead,
checking each one by hand against the runtime states the
static pass cannot see (comparison mode is gone by item 2; the
change-detection diff, the SPF over-limit state, and the DKIM
red rating are real states to keep).

Known dead families to start with: .footer-linkedin (if any
copy survived Doc 48), .dbis-section a.audit-cta,
.dbis-hero-cta, .dbis-walk* (declared twice, at about 4625 and
8004), .dbis-prose-list, .dbis-hero, .dbis-target,
.dbis-footer-cta, .details-toggle, .edu-*, .ha-* (the header
analyzer, 24 rules), .fix-block and siblings,
.resilience-pass/warn/fail/info, .sr-only, .selector-wrapper,
.audit-trust, the twelve static stagger rules for
.result-card:nth-child that app.js overrides.

Duplicates: 34 selector pairs are declared twice, eight with
identical bodies (.result-card[data-status=pass|warn|fail] at
about 1409 and 1436; the .dbis-walk-step family). Later
identical selectors override earlier ones for body,
.container, .site-header, .site-footer, .recent-audits-list,
.about-page h1, .theme-toggle, and the header rules at 640;
the article block at about 7982 onward is a second copy of the
one at 4498 with small differences. Keep one copy of each, the
later one where they differ. Mobile rules are split between
max-width 600px (14 blocks) and 640px (13 blocks); pick one
breakpoint. There are 32 !important declarations; remove each
one that a specificity fix can replace.

## 5. Audit speed

Measure first: run run_full_audit against a fixture zone with
a fixed 100 ms sleep per fake DNS query (the reviewer used a
Google-hosted style zone with five MX hosts carrying A and
AAAA, four NS, and an SPF include chain) and record total time
and time per phase. The reviewer measured 6.7 s total, with
the MX check taking 3.1 s of it and Phase 1 taking 4.8 s.

- MX: with _check_ptr gone (item 3), resolve the MX hosts' A
  and AAAA with _probe_executor.map instead of one after
  another (mx_check.py around 327). The reviewer measured the
  MX check dropping from 3.1 s to 1.1 s with the PTR lookups
  alone removed.
- Phase 1: run_full_audit runs the tree walk, DMARC, MX, SPF,
  and the hoisted DNSSEC check one after another
  (audit_engine.py from about 4700 to 4877). Only
  transform_spf depends on MX, and only for has_mx;
  _raw_check_spf itself does not read MX. Submit the five raw
  checks together and transform afterwards. Keep the deadline
  handling that is there now.
- Nameservers: _raw_check_nameservers at 3527 resolves A then
  AAAA then a direct SOA per nameserver in series, with a 3 s
  timeout each. Run the per-nameserver work through
  _probe_executor the way _check_report_authorization already
  does.
- Resolvers: dns_tools.py builds a template resolver with
  configure=False at 94 to 99; confirm get_resolver and
  get_dnssec_resolver at 115 and 124 and every other
  dns.resolver.Resolver() construction in the repo copy from
  that template rather than re-reading /etc/resolv.conf. The
  reviewer counted 45 reads per audit.

Measure again after and put both numbers in the PR
description. Add a test that the MX check makes no PTR
queries, and a test with sleeping fake lookups that asserts
Phase 1 wall time is less than the sum of its checks.

## 6. Duplicated helpers and stale comments

- _lookup_ttl exists twice, identical (checks_extra.py:158,
  audit_engine.py:424); _lookup_txt exists twice with
  different failure semantics; _get_resolver wrappers exist in
  four modules; _make_issue exists in mx_check and
  checks_extra. Move one copy of each identical helper to
  dns_tools.py and import it; leave the two _lookup_txt
  variants but give each a docstring saying how they differ.
- The DNSKEY processing block is copied verbatim at two places
  in _raw_check_dnssec, and the nameserver and DNSSEC anomaly
  blocks are copied in anomaly_detector.py. Extract each into
  a function.
- Comments that describe code that is gone: audit_engine.py:6
  "Assembles results for the security scorer" (there is no
  scorer); pdf_report.py:12 to 22 wires a function and keyword
  that do not exist; checks_extra.py:27 says "we target 3.9+"
  while requirements say 3.10; server.py:124 to 126 cite line
  numbers that Doc 50 will remove. Fix the first three here.
- Do not refactor the long functions in this doc. For the
  record, these exceed 200 lines: run_full_audit,
  _raw_check_dmarc, transform_dmarc, transform_dkim,
  _build_resilience_analysis, _raw_check_dnssec,
  _raw_check_spf, build_executive_summary, _build_tag_entry,
  check_bimi, transform_spf, transform_dane, detect_anomalies,
  _raw_check_nameservers, _detect_dangerous_combinations,
  _raw_check_ct_uncached, smart_dkim_check, audit_stream,
  _validate_dmarc_strict, _build_attack_surface,
  _dmarc_deep_dive, _assess_dmarcbis_readiness,
  _raw_check_dane. Splitting _raw_check_dmarc's twelve
  near-identical validate-and-emit blocks into a tag table
  would be the first one worth doing, in its own doc.

## Tests

The suite count will drop by the tests that only exercised
deleted code; list them in the PR description. Add a test that
walks every module with ast, collects top-level function
names, and fails if a name is referenced nowhere else in the
repo (tests included), with an allowlist for FastAPI route
handlers and __main__ entry points, so dead functions cannot
accumulate again.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since app.js and style.css change.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-49.md in the same commit.

## Done when

No function, module, JSON field, or CSS rule exists that
nothing reads; DNSSEC and DANE change tracking store rows; the
comparison and educational remnants are gone; the audit
against the timed fixture is measurably faster and the PR says
by how much; the helpers exist once; and the dead-function
test passes.
