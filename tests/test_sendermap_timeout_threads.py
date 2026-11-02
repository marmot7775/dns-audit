"""A Sendermap map past its budget does not raise the thread count above the
audit thread ceiling (issue 269).

The Sentry error "RuntimeError: can't start new thread" on /api/audit came
from threads that outlived the audit that started them. Every map question
runs on the one bounded pool in sendermap_adapter, which AUDIT_THREAD_CEILING
counts, so a map that times out leaves at most that pool's workers behind.
"""
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import audit_engine  # noqa: E402
import dns_tools  # noqa: E402
import sendermap_adapter  # noqa: E402


class _Hangs:
    """A resolver whose every question takes longer than the map's budget."""

    def resolve(self, name, rdtype, *args, **kwargs):
        time.sleep(1.5)
        raise dns_tools.dns.resolver.NXDOMAIN()


def _sendermap_threads():
    return [t for t in threading.enumerate() if t.name.startswith("sendermap")]


def test_timed_out_maps_stay_inside_the_ceiling(monkeypatch):
    monkeypatch.setattr(dns_tools, "get_resolver", lambda *a, **k: _Hangs())
    baseline = threading.active_count()
    audits = audit_engine._MAX_CONCURRENT_AUDITS * 3  # more maps than the cap allows
    results = []

    def one_audit(i):
        results.append(audit_engine._run_with_timeout(
            sendermap_adapter.map_senders, f"hang{i}.example", 0.3, timeout=5))

    workers = [threading.Thread(target=one_audit, args=(i,)) for i in range(audits)]
    peak = 0
    for w in workers:
        w.start()
    while any(w.is_alive() for w in workers):
        peak = max(peak, threading.active_count())
        time.sleep(0.02)
    for w in workers:
        w.join()
    peak = max(peak, threading.active_count())

    assert results == [None] * audits, "every map should have given up"
    pool = sendermap_adapter.MAX_CONCURRENT_AUDITS * sendermap_adapter.MAP_THREADS
    assert len(_sendermap_threads()) <= pool
    # The harness' own audit threads and the shared executor's workers are
    # counted by the ceiling; the map's lookups add nothing beyond the pool.
    assert peak - baseline <= audits + audit_engine._shared_executor._max_workers + pool
    assert peak < audit_engine.AUDIT_THREAD_CEILING
