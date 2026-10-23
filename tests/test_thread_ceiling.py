"""The audit pools' thread ceiling and the unit's task limit (Doc 102).

2026-10-15: every audit on the droplet failed with "can't start new thread".
The three audit pools could hold 1112 threads, ThreadPoolExecutor never
retires an idle worker, and the unit's default TasksMax was 1107. These pin
the ceiling, the startup warning, the health fields, and the chunked DKIM
priority wave that let the DKIM pool shrink from 688 to 416 workers.
"""
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

from conftest import FakeZone, fake_dns
from test_dkim_discovery_starvation import DKIM_RECORD
import audit_engine
import server as server_module
import spf_intelligence
from comprehensive_selectors import COMPREHENSIVE_DKIM_SELECTORS, ESP_SELECTORS
from config import MAX_CONCURRENT_AUDITS

DOMAIN = "threads.test"
UNIT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "deploy", "dns-auditor.service")


def test_ceiling_is_the_sum_of_the_three_pools_and_the_maps():
    """Each audit's sender map runs on a pool of MAP_THREADS of its own."""
    from sendermap_adapter import MAP_THREADS
    assert audit_engine.AUDIT_THREAD_CEILING == (
        audit_engine._shared_executor._max_workers
        + audit_engine._probe_executor._max_workers
        + audit_engine._dkim_executor._max_workers
        + MAX_CONCURRENT_AUDITS * MAP_THREADS)
    # The maps' share is one bounded pool, not a pool per map, so a map that
    # outlives its budget cannot push the process past the ceiling.
    from sendermap_adapter import _MAP_EXECUTOR
    assert _MAP_EXECUTOR._max_workers == MAX_CONCURRENT_AUDITS * MAP_THREADS


def test_dkim_pool_holds_a_fallback_chunk_per_audit():
    assert audit_engine._dkim_executor._max_workers >= (
        MAX_CONCURRENT_AUDITS * spf_intelligence.DKIM_FALLBACK_CHUNK)
    assert spf_intelligence.DKIM_WAVE_CHUNK >= spf_intelligence.DKIM_FALLBACK_CHUNK


def test_unit_file_task_limit_clears_the_ceiling():
    limit = next(int(line.split("=", 1)[1]) for line in open(UNIT)
                 if line.startswith("TasksMax="))
    assert limit >= audit_engine.AUDIT_THREAD_CEILING + server_module._THREAD_OVERHEAD


def test_health_reports_threads_and_ceiling(monkeypatch):
    monkeypatch.setitem(server_module._health_cache, "ok", True)
    monkeypatch.setitem(server_module._health_cache, "expires", time.time() + 60)
    monkeypatch.setitem(server_module._negative_probe_cache, "error", None)
    monkeypatch.setitem(server_module._negative_probe_cache, "expires", time.time() + 60)
    body = TestClient(server_module.app).get("/api/health").json()
    assert body["status"] == "ok"
    assert isinstance(body["threads"], int) and body["threads"] > 0
    assert body["thread_ceiling"] == audit_engine.AUDIT_THREAD_CEILING


def _warnings(monkeypatch):
    seen = []
    monkeypatch.setattr(server_module.log, "warning", lambda msg, *a: seen.append(msg % a))
    return seen


def test_startup_warns_when_the_task_limit_is_too_low(tmp_path, monkeypatch):
    seen = _warnings(monkeypatch)
    too_low = audit_engine.AUDIT_THREAD_CEILING + server_module._THREAD_OVERHEAD - 1
    low = tmp_path / "pids.max"
    low.write_text(f"{too_low}\n")
    assert server_module._check_thread_headroom(low) == too_low
    assert len(seen) == 1
    assert str(too_low) in seen[0] and str(audit_engine.AUDIT_THREAD_CEILING) in seen[0]


def test_startup_is_quiet_with_room_unlimited_or_no_cgroup(tmp_path, monkeypatch):
    seen = _warnings(monkeypatch)
    ok = tmp_path / "ok"
    ok.write_text("4096\n")
    unlimited = tmp_path / "max"
    unlimited.write_text("max\n")
    assert server_module._check_thread_headroom(ok) == 4096
    assert server_module._check_thread_headroom(unlimited) is None
    assert server_module._check_thread_headroom(tmp_path / "missing") is None
    assert seen == []


class _CountingZone(FakeZone):
    """Records how many DKIM probes are in flight at once."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lock = threading.Lock()
        self.in_flight = 0
        self.peak = 0
        self.selectors = set()

    def resolve(self, name, rdtype="A", *args, **kwargs):
        key = self._key(name, rdtype)
        if "._domainkey." not in key[0]:
            return super().resolve(name, rdtype, *args, **kwargs)
        with self._lock:
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
            self.selectors.add(key[0].split("._domainkey.")[0])
        try:
            time.sleep(0.02)
            return super().resolve(name, rdtype, *args, **kwargs)
        finally:
            with self._lock:
                self.in_flight -= 1


def _zone(keys=()):
    records = {DOMAIN: {"MX": [(10, f"mail.{DOMAIN}")], "TXT": ["v=spf1 mx -all"]}}
    for sel in keys:
        records[f"{sel}._domainkey.{DOMAIN}"] = {"TXT": [DKIM_RECORD]}
    return _CountingZone(records)


def test_priority_wave_runs_in_full_but_in_chunks():
    zone = _zone(keys=["selector2"])
    pool = ThreadPoolExecutor(max_workers=300)
    try:
        with fake_dns(zone):
            result = spf_intelligence.smart_dkim_check(
                DOMAIN, "v=spf1 mx -all", mx_hosts=[f"mail.{DOMAIN}"], executor=pool)
    finally:
        pool.shutdown(wait=True)
    assert [s["selector"] for s in result["found_selectors"]] == ["selector2"]
    # One audit never holds more than one chunk of probe threads.
    assert 0 < zone.peak <= spf_intelligence.DKIM_WAVE_CHUNK, zone.peak
    # And every ESP selector in the priority wave was still asked.
    assert set(ESP_SELECTORS) <= zone.selectors


def test_priority_chunks_stop_at_max_found():
    many = list(COMPREHENSIVE_DKIM_SELECTORS) + list(ESP_SELECTORS)
    zone = _zone(keys=many)
    pool = ThreadPoolExecutor(max_workers=300)
    try:
        with fake_dns(zone):
            result = spf_intelligence.smart_dkim_check(
                DOMAIN, "v=spf1 mx -all", mx_hosts=[f"mail.{DOMAIN}"], executor=pool)
    finally:
        pool.shutdown(wait=True)
    assert len(result["found_selectors"]) == spf_intelligence.DKIM_MAX_FOUND
    # The first chunk found enough, so no second chunk went out. The
    # wildcard canary is a probe of its own, not part of a wave.
    probed = {s for s in zone.selectors if not s.startswith("_dkimwildcard")}
    assert len(probed) <= spf_intelligence.DKIM_WAVE_CHUNK, len(probed)
