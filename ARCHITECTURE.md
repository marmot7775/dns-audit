# Architecture

dns-audit reads a domain's public DNS, judges each record against its RFC,
and returns cards a person can act on. One FastAPI process, no database
beyond a DNS snapshot table, no accounts. Why things are the way they are:
[docs/decisions](docs/decisions/).

## Pipeline

1. **Request.** `server.py` normalizes the domain (`dns_tools.normalize_domain`),
   applies the per-IP rate limit and the concurrency budget, and answers from
   the five-minute cache or joins an audit already in flight for the same
   domain, selector and scope.
2. **Phase 1.** `audit_engine.run_full_audit` runs the RFC 9989 tree walk,
   DMARC, MX, SPF and DNSSEC side by side. Later checks need their answers:
   whether the domain takes mail, which vendors SPF and MX name.
3. **Phase 2.** DKIM, MTA-STS, TLS-RPT, BIMI, CAA, nameservers, DANE,
   Certificate Transparency and APRF run in parallel, each under its own
   timeout, inside one deadline for the whole audit.
4. **Cards.** Each raw result goes through its `transform_*` function in
   `result_transformer.py`, which sets the status, pill, verdict, details and
   fix. The engine then adds the cross-check layers: no-mail domains, DMARC
   evaluation, vendors, anomalies, resilience, change detection.
5. **Summary and plan.** `build_executive_summary` and `build_security_roadmap`
   read only the finished cards, so the headline cannot say what a card does
   not.
6. **Output.** JSON (`/api/audit`), progress events (`/api/audit/stream`) that
   `static/app.js` renders, or a PDF from `pdf_report.generate_pdf` built from
   the same result dict.

## Modules

```
server.py                  FastAPI app, SSE, rate limiting, caching
config.py                  Settings from the environment
audit_engine.py            Raw checks for DMARC, SPF, DNSSEC, CAA, NS, DANE, CT, APRF; orchestration and timeouts
result_transformer.py      Raw results to cards, summary, roadmap
pdf_report.py              PDF report
dns_tools.py               Domain normalization, resolvers
dns_snapshots.py           DNS record history for change detection
dmarc_tree_walk.py         RFC 9989 tree walk
spf_recursive.py           SPF lookup counter
spf_execution_engine.py    SPF trace, DMARC evaluation summary
spf_intelligence.py        DKIM selector discovery from SPF vendors
checks_extra.py            MTA-STS, TLS-RPT, BIMI
mx_check.py                MX analysis
dkim_formatter.py          DKIM key analysis
comprehensive_selectors.py Known DKIM selectors
advanced_fingerprinting.py Vendor fingerprinting
vendor_patterns.py         Vendor table: SPF, MX, DKIM CNAME, selector names
anomaly_detector.py        Cross-check anomalies
ua_classify.py             Browser and bot labels for the audit log

static/                    App shell, app.js, style.css, theme.js, articles
tools/                     Operator scripts: live_check.py, rewrite_audit_log_ua.py, gen_requirements.py
deploy/                    systemd unit template
```

## Rules the code keeps

- A failed lookup is reported as not checked, never as a finding. A timeout,
  SERVFAIL or unreachable service gives the card status `unavailable`; it is
  not a missing record and it never passes.
- A verdict shows the record it read. Every card carries the record it
  judged in `record`, so the reader can check the verdict against DNS.
  DNSSEC, which judges DS and DNSKEY sets, shows them in its details instead.
- A check outside the requested scope is left out of the result. The summary
  treats it as not assessed, never as passed.
- An optional protocol that is not published is `absent`, grey, and never
  counted as a warning.
- DMARC is judged against RFC 9989 and RFC 7489 side by side, because most
  receivers still run 7489.
- One uvicorn worker. The cache, rate limiter and in-flight map are per
  process ([decision](docs/decisions/2026-09-04-single-worker.md)).
- No personal data in logs: the audit log keeps domain, scope, timing and
  coarse browser labels, never an IP address.
