# One worker process

Date: 2026-09-04. Commit 6713f25; `_warn_if_multiple_workers()` in server.py.

## Context

All coordination state in `server.py` is a module-level global, private to
one process: the per-IP rate limit table (`_rate_limits`), the concurrency
budget (`_active_audits`), the single-flight registry (`_inflight`), the
result cache (`_cache`) and the health probe memo (`_health_cache`).

With N workers each process gets its own copy. The concurrency cap becomes N
times `MAX_CONCURRENT_AUDITS`, each IP gets N times its rate limit, two
workers can run the same audit at once, and the health probe stops
deduplicating. Nothing errors, nothing logs, no test catches it. The site
quietly stops enforcing its own limits.

## Decision

The service runs exactly one uvicorn process. `deploy/dns-auditor.service`
passes no `--workers` flag and nothing sets `WEB_CONCURRENCY`. `server.py`
checks at import and logs an error naming what breaks if it finds more than
one worker.

## Consequences

- Scaling out means first moving the cache, rate limiter, concurrency budget
  and in-flight map to shared storage such as Redis.
- Every new piece of shared state makes this more load bearing, not less.
- Related: uvicorn trusts proxy headers from 127.0.0.1 only, so a client
  cannot spoof its way past the rate limiter. tests/test_proxy_headers_trust.py
  pins it.
