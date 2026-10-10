# Proposal: a checks package, one module per protocol

Status: proposed, not started. Written 2026-10-09. The split runs in its own
session, because it touches every verdict path. See
[Correctness before refactoring](../decisions/2026-09-14-correctness-before-refactoring.md).

## Why

`audit_engine.py` is 7,024 lines and `result_transformer.py` 9,832. A change
to one protocol means reading through every other protocol's code, and a
merge conflict in one file blocks unrelated work. Today the DMARC code alone
is about 1,800 lines in the engine and 1,900 in the transformer, in two
files, with the other twelve protocols in between.

## Shape

```
checks/
  __init__.py        REGISTRY: protocol key -> (raw check, transform, scope keys)
  common.py          _lookup_txt, _run_with_timeout, _issue_to_detail, _map_status,
                     _lookup_unavailable_card, PILL_* and the other shared card helpers
  dmarc.py           raw check, strict and legacy validators, readiness, inheritance,
                     report authorization, tag breakdown, dangerous combinations, card
  spf.py             raw check, suggested record, hosted SPF, include cost, card
  dkim.py            selector discovery glue, key analysis, card
  mx.py              mx_check.check_mx moves here, with transform_mx
  mta_sts.py         checks_extra.check_mta_sts with transform_mta_sts
  tls_rpt.py         checks_extra.check_tls_rpt with transform_tls_rpt
  bimi.py            checks_extra.check_bimi with transform_bimi
  dnssec.py          resolver, bogus probe, raw check, card
  caa.py             tree climb, raw check, card
  nameservers.py     raw check, serial helpers, card
  dane.py            raw check, card, hosted-provider branches
  ct.py              crt.sh cache, raw check, card
  aprf.py            draft-standard check and card
audit_engine.py      run_full_audit only: scope, phases, deadline, cross-check layers
summary.py           build_executive_summary, build_security_roadmap,
                     build_consistency_findings, build_change_detection
```

Each protocol module owns both halves: what it reads from DNS and what it
tells the reader about it. The engine keeps orchestration only.

## Module map

Sizes are from an AST pass over main at 746c5a1 (top-level functions only).

| Protocol | From audit_engine.py | From result_transformer.py | Lines, about |
|---|---|---|---|
| DMARC | `_raw_check_dmarc`, `_validate_dmarc_strict`, `_validate_dmarc_legacy`, `_assess_dmarcbis_readiness`, `_enrich_dmarc_inheritance`, `_check_report_authorization`, `_report_org_domain`, `_get_org_domain`, `_is_rua_syntactically_valid` | `transform_dmarc`, `_build_dmarc_tag_breakdown`, `_detect_dangerous_combinations`, `_build_strict_validation`, `_calculate_dmarcbis_health`, `_build_dmarcbis_card_data`, `_build_why_dmarcbis`, `_dmarc_end_state`, `_edit_dmarc_record`, `_dmarc_pct_kept`, `_pct_kept_note` | 3,600 |
| SPF | `_raw_check_spf`, `_build_suggested_spf`, `_spf_managed_by`, `_spf_terms`, `_spf_authorization_sources`, `_spf_tree_names`, `_needs_apex_spf_include`, `_vendor_in_spf_tree`, `_spf_include_cost`, `_publishes_null_spf`, `_has_sending_spf` | `transform_spf`, `_build_spf_deep_analysis`, `_spf_card_band`, `_extract_spf_all`, `_is_null_spf` | 1,200 |
| DKIM | `_live_dkim_selectors` | `transform_dkim`, `_transform_dkim_card`, `_build_dkim_key_analysis`, `_split_dkim_selectors`, `_dkim_retired_detail`, `_is_microsoft_dkim_cname`, `attach_reject_dkim_note` | 960 |
| DNSSEC | `_raw_check_dnssec`, `_probe_dnssec_bogus`, `_get_dnssec_resolver` | `transform_dnssec`, `_transform_dnssec_card` | 660 |
| Certificate Transparency | `_raw_check_ct`, `_raw_check_ct_uncached`, `_parse_ct_timestamp`, the `_*_cached_ct*` helpers | `transform_ct` | 600 |
| Nameservers | `_raw_check_nameservers` | `transform_nameservers`, `_ns_serial_*` | 550 |
| DANE | `_raw_check_dane` | `transform_dane`, `_transform_dane_card` | 500 |
| CAA | `_raw_check_caa`, `_caa_tree` | `transform_caa` | 340 |
| APRF | `_raw_check_aprf`, `_parse_aprf`, `_aprf_*` | `transform_aprf`, `_aprf_card`, `_aprf_list` | 320 |
| MX, MTA-STS, TLS-RPT, BIMI | `_publishes_null_mx`, `_has_working_mx` (raw checks are already in mx_check.py and checks_extra.py) | `transform_mx`, `transform_mta_sts`, `transform_tls_rpt`, `transform_bimi` | 630 here, plus those two modules |
| Summary | | `build_executive_summary` (685), `build_security_roadmap` (742), `build_consistency_findings`, `build_change_detection` | 1,600 |
| Stays in the engine | `run_full_audit` (1,155), `_build_resilience_analysis` (505), `_build_provider_intelligence`, vendor and subdomain helpers, scope and timeout helpers | | 2,500 |

## How to do it safely

1. Before moving anything, pin the output: run every scope against the
   FakeZone fixtures and a recorded set of real-domain raw results, and save
   the full result dicts as golden files. The split must reproduce them byte
   for byte.
2. Move one protocol per pull request, starting with the smallest (CAA), so
   the pattern is settled before DMARC.
3. Keep the old names importable from `audit_engine` and `result_transformer`
   for one release, because 122 test files import from them. Remove the
   re-exports in a final pull request.
4. No wording, threshold or status changes ride along. A defect found while
   moving code goes in its own pull request with its own test.

## Open questions

- `_build_resilience_analysis` (505 lines) reads DMARC, SPF and DKIM
  together. It stays in the engine here; it could be its own module.
- `spf_execution_engine.py`, `spf_recursive.py` and `spf_intelligence.py`
  could fold into `checks/spf.py` or stay as its helpers.
