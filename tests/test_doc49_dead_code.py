"""Doc 49: dead code, dead output, and audit speed.

Guards for what the doc removed and fixed:

- no top-level function in the repo is referenced nowhere, so dead helpers
  cannot accumulate again
- the JSON fields that had no reader stay out of the API
- DNSSEC and DANE change tracking store rows and read them back (both read
  keys the checks never set, so neither had ever stored one)
- the MX check makes no PTR queries
- Phase 1's five raw checks run side by side, not one after another
"""
import ast
import os
import pathlib
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns
import audit_engine
import dns_snapshots
import mx_check

ROOT = pathlib.Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Dead functions
# ---------------------------------------------------------------------------

def _is_route_handler(fn):
    """FastAPI registers these by decorator; nothing calls them by name."""
    return any(ast.unparse(d).startswith(("app.", "router.")) for d in fn.decorator_list)


def _main_block_names(tree):
    """Names a module's `if __name__ == "__main__":` block uses: entry points."""
    names = set()
    for node in tree.body:
        if isinstance(node, ast.If) and "__main__" in ast.unparse(node.test):
            names |= {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
    return names


def _references():
    """Every name the repo's Python code uses, tests included.

    Names, attribute accesses and imports count, and so does a string that
    names the function, the way patch("module.name") and
    monkeypatch.setattr(module, "name") do. Comments and prose do not.
    """
    refs = set()
    for path in sorted(ROOT.glob("*.py")) + sorted((ROOT / "tests").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Name):
                refs.add(node.id)
            elif isinstance(node, ast.Attribute):
                refs.add(node.attr)
            elif isinstance(node, ast.alias):
                refs.add(node.name.split(".")[-1])
                if node.asname:
                    refs.add(node.asname)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value.strip()
                if value.isidentifier():
                    refs.add(value)
                elif "." in value and " " not in value:
                    refs.add(value.rsplit(".", 1)[-1])
    return refs


def test_every_top_level_function_is_referenced_somewhere():
    refs = _references()
    dead = []
    for path in sorted(ROOT.glob("*.py")):
        tree = ast.parse(path.read_text())
        entry_points = _main_block_names(tree)
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name.startswith("__") or _is_route_handler(node):
                continue
            if node.name in entry_points:
                continue
            if node.name not in refs:
                dead.append(f"{path.name}:{node.lineno} {node.name}")
    assert not dead, (
        "top-level functions nothing references; delete them (and any test "
        "that exists only to exercise them):\n  " + "\n  ".join(dead)
    )


# ---------------------------------------------------------------------------
# JSON fields that left the API
# ---------------------------------------------------------------------------

DOMAIN = "doc49.test"


def _zone(dnskey_alg=13, tlsa_cert="aa" * 32):
    return FakeZone({
        DOMAIN: {
            "MX": [(10, f"mail.{DOMAIN}")],
            "TXT": ["v=spf1 mx -all"],
            "A": ["203.0.113.50"],
            "NS": [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"],
            "DNSKEY": [dnskey_alg],
        },
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@ext-{DOMAIN}"]},
        f"mail.{DOMAIN}": {"A": ["203.0.113.51"], "AAAA": ["2001:db8::51"]},
        "51.113.0.203.in-addr.arpa": {"PTR": [f"mail.{DOMAIN}"]},
        f"_25._tcp.mail.{DOMAIN}": {"TLSA": [(3, 1, 1, tlsa_cert)]},
        f"ns1.{DOMAIN}": {"A": ["203.0.113.53"]},
        f"ns2.{DOMAIN}": {"A": ["198.51.100.53"]},
    })


@pytest.fixture
def snapshot_db(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    monkeypatch.setattr(dns_snapshots, "_DB_PATH", path)
    dns_snapshots._local.conn = None
    yield path
    dns_snapshots._local.conn = None
    if os.path.exists(path):
        os.unlink(path)


def test_fields_with_no_reader_stay_out_of_the_response(audit, snapshot_db):
    result = audit(_zone(), DOMAIN)

    for field in ("priority_fixes", "remediation_plan", "ttl_map", "errors"):
        assert field not in result, field
    for field in ("total", "unread_protocols", "unscoped_protocols"):
        assert field not in result["security_roadmap"], field
    for field in ("first_seen", "message"):
        assert field not in result["change_detection"], field
    for card in result["checks"]:
        for field in ("dane_deep", "mta_sts_deep", "tls_rpt_deep"):
            assert field not in card, (card["name"], field)
    chain = result.get("report_chain") or {}
    assert "report_auth_issues" not in chain
    for dest in chain.get("report_destinations") or []:
        assert "authorization_record" not in dest
    for sub in (result.get("subdomain_audit") or {}).get("subdomains") or []:
        for field in ("category", "category_label", "policy_source",
                      "dmarc_record", "effective_policy"):
            assert field not in sub, field
    for provider in (result.get("provider_intelligence") or {}).get("primary_providers") or []:
        assert "badge_class" not in provider


# ---------------------------------------------------------------------------
# DNSSEC and DANE change tracking
# ---------------------------------------------------------------------------

def test_dnssec_and_dane_snapshots_are_stored_and_read_back(audit, snapshot_db):
    audit(_zone(dnskey_alg=13, tlsa_cert="aa" * 32), DOMAIN)

    history = dns_snapshots.get_all_history(DOMAIN)
    assert "dnssec" in history, f"no DNSSEC row stored: {sorted(history)}"
    assert "13" in history["dnssec"][0]["record_value"]
    dane_type = f"dane:mail.{DOMAIN}"
    assert dane_type in history, f"no DANE row stored: {sorted(history)}"
    assert history[dane_type][0]["record_value"].startswith("3 1 1 " + "aa" * 32)


def test_dnssec_and_dane_changes_reach_the_change_detection(audit, snapshot_db, monkeypatch):
    audit(_zone(dnskey_alg=13, tlsa_cert="aa" * 32), DOMAIN)
    # The snapshot table's timestamps have one second resolution; the second
    # row must sort as newer than the first.
    conn = dns_snapshots._get_conn()
    conn.execute("UPDATE dns_snapshots SET timestamp = datetime(timestamp, '-1 minute')")
    conn.commit()
    result = audit(_zone(dnskey_alg=8, tlsa_cert="bb" * 32), DOMAIN)

    changes = result["change_detection"]["changes"]
    types = {c["record_type"] for c in changes}
    assert "dnssec" in types, f"DNSSEC change not reported: {types}"
    assert f"dane:mail.{DOMAIN}" in types, f"DANE change not reported: {types}"
    dane = next(c for c in changes if c["record_type"] == f"dane:mail.{DOMAIN}")
    assert dane["record_label"] == f"DANE (mail.{DOMAIN})"
    assert "bb" * 32 in dane["new_value"] and "aa" * 32 in dane["old_value"]


# ---------------------------------------------------------------------------
# MX: no PTR queries
# ---------------------------------------------------------------------------

def test_the_mx_check_makes_no_ptr_queries():
    zone = _zone()
    with fake_dns(zone):
        result = mx_check.check_mx(DOMAIN)

    assert result["mx_details"][0]["ips"] == ["203.0.113.51", "2001:db8::51"]
    assert "ptr_results" not in result["mx_details"][0]
    ptr = [q for q in zone.queries if q[1] == "PTR"]
    assert ptr == [], f"the MX check queried PTR: {ptr}"


def test_the_mx_check_gives_the_same_answer_with_and_without_a_pool():
    from concurrent.futures import ThreadPoolExecutor

    with fake_dns(_zone()):
        serial = mx_check.check_mx(DOMAIN)
    with ThreadPoolExecutor(4) as pool, fake_dns(_zone()):
        pooled = mx_check.check_mx(DOMAIN, executor=pool)
    assert serial == pooled


# ---------------------------------------------------------------------------
# Phase 1 runs its checks side by side
# ---------------------------------------------------------------------------

class _SlowZone(FakeZone):
    """Every lookup takes a fixed time, the way a real round trip does."""

    DELAY = 0.03

    def resolve(self, name, rdtype="A", *args, **kwargs):
        time.sleep(self.DELAY)
        return super().resolve(name, rdtype, *args, **kwargs)


PHASE1 = ("dmarc_tree_walk", "_raw_check_dmarc", "check_mx",
          "_raw_check_spf", "_raw_check_dnssec")


def test_phase1_wall_time_is_less_than_the_sum_of_its_checks(monkeypatch, snapshot_db):
    spans = {}
    lock = threading.Lock()

    def _timed(name, func):
        def wrapper(*args, **kwargs):
            start = time.monotonic()
            try:
                return func(*args, **kwargs)
            finally:
                with lock:
                    spans[name] = (start, time.monotonic())
        return wrapper

    for name in PHASE1:
        monkeypatch.setattr(audit_engine, name, _timed(name, getattr(audit_engine, name)))

    zone = _SlowZone()
    zone._records.update(_zone()._records)
    with fake_dns(zone):
        audit_engine.run_full_audit(DOMAIN, scope="complete")

    assert set(spans) == set(PHASE1), f"not every Phase 1 check ran: {sorted(spans)}"
    wall = max(end for _, end in spans.values()) - min(start for start, _ in spans.values())
    total = sum(end - start for start, end in spans.values())
    assert wall < total, (
        f"Phase 1 took {wall:.2f}s against {total:.2f}s of checks: they ran one "
        f"after another"
    )
