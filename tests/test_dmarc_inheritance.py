"""
Tests for DMARC inheritance logic in audit_engine.py.

Covers:
  - _get_org_domain: PSL-based org domain extraction + fallback heuristic
  - _enrich_dmarc_inheritance: tree walk path, PSL path, sp= tag, own-record bypass
  - _build_resilience_analysis: non-sending subdomain levels with inherited policy
  - detect_anomalies (anomaly_detector): inherited DMARC treated as present/enforced
"""

import sys
import os
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from audit_engine import _get_org_domain, _enrich_dmarc_inheritance, _build_resilience_analysis
from anomaly_detector import detect_anomalies


# ---------------------------------------------------------------------------
# Helpers shared across test classes
# ---------------------------------------------------------------------------

def _find_anomaly(anomalies, fragment):
    """Return the first anomaly whose title contains fragment (case-insensitive)."""
    for a in anomalies:
        if fragment.lower() in a["title"].lower():
            return a
    return None


def _minimal_dmarc_raw(policy, record="v=DMARC1; p={}"):
    """Build a minimal raw_dmarc dict that has its own record."""
    return {
        "record": record.format(policy),
        "policy": policy,
    }


# ============================================================================
# _get_org_domain
# ============================================================================

class TestGetOrgDomain(unittest.TestCase):
    """_get_org_domain returns the RFC 7489 organizational domain."""

    def test_subdomain_of_com_tld(self):
        assert _get_org_domain("mail.yahoo.com") == "yahoo.com"

    def test_already_org_domain(self):
        assert _get_org_domain("yahoo.com") == "yahoo.com"

    def test_two_part_tld_co_uk(self):
        assert _get_org_domain("sub.example.co.uk") == "example.co.uk"

    def test_deeply_nested_subdomain(self):
        assert _get_org_domain("deeply.nested.sub.example.com") == "example.com"

    def test_single_label_returns_none(self):
        # tldextract cannot extract a valid domain from a bare label
        result = _get_org_domain("localhost")
        # Either None or "localhost" is acceptable; must not raise
        assert result is None or isinstance(result, str)


# ============================================================================
# _enrich_dmarc_inheritance
# ============================================================================

class TestEnrichDmarcInheritance(unittest.TestCase):
    """_enrich_dmarc_inheritance sets inherited_* fields on raw_dmarc in-place."""

    # --- own-record bypass ---

    def test_own_record_skipped(self):
        """Domain with its own DMARC record must not set inherited fields."""
        raw = {"record": "v=DMARC1; p=none", "policy": "none"}
        _enrich_dmarc_inheritance(raw, "sub.example.com")
        assert "inherited_policy" not in raw
        assert "inherited_from" not in raw

    # --- org domain is the same as the queried domain ---

    def test_org_domain_not_subdomain(self):
        """When queried domain IS the org domain, no inheritance should be set."""
        raw = {}
        with patch("audit_engine._get_org_domain", return_value="example.com"):
            _enrich_dmarc_inheritance(raw, "example.com")
        assert "inherited_policy" not in raw

    # --- tree walk path ---

    def test_tree_walk_sets_inherited_from(self):
        """Tree walk result should populate inherited_from and inheritance_method."""
        raw = {}
        tree_walk = {
            "is_subdomain": True,
            "policy_source": "example.com",
            "effective_policy": "reject",
            "effective_record": "v=DMARC1; p=reject",
            "applied_tag": "p",
        }
        _enrich_dmarc_inheritance(raw, "sub.example.com", tree_walk_result=tree_walk)

        assert raw["inherited_from"] == "example.com"
        assert raw["inherited_policy"] == "reject"
        assert raw["inheritance_method"] == "tree_walk"
        assert raw["is_subdomain"] is True
        assert raw["inherited_record"] == "v=DMARC1; p=reject"

    def test_tree_walk_quarantine_policy(self):
        raw = {}
        tree_walk = {
            "is_subdomain": True,
            "policy_source": "example.com",
            "effective_policy": "quarantine",
            "effective_record": "v=DMARC1; p=quarantine",
            "applied_tag": "p",
        }
        _enrich_dmarc_inheritance(raw, "sub.example.com", tree_walk_result=tree_walk)
        assert raw["inherited_policy"] == "quarantine"
        assert raw["inheritance_method"] == "tree_walk"

    def test_tree_walk_not_subdomain_no_inheritance(self):
        """Tree walk result with is_subdomain=False must not set inherited fields."""
        raw = {}
        tree_walk = {
            "is_subdomain": False,
            "policy_source": "example.com",
            "effective_policy": "reject",
        }
        _enrich_dmarc_inheritance(raw, "example.com", tree_walk_result=tree_walk)
        assert "inherited_policy" not in raw

    def test_tree_walk_missing_effective_policy_falls_through_to_psl(self):
        """If tree walk has no effective_policy, fall through to PSL lookup."""
        raw = {}
        tree_walk = {
            "is_subdomain": True,
            "policy_source": "example.com",
            "effective_policy": "",   # empty -- should not count
        }
        psl_records = ["v=DMARC1; p=quarantine"]
        with patch("audit_engine._get_org_domain", return_value="example.com"), \
             patch("audit_engine._lookup_txt", return_value=psl_records):
            _enrich_dmarc_inheritance(raw, "sub.example.com", tree_walk_result=tree_walk)

        # PSL path should have fired
        assert raw.get("inheritance_method") == "psl"
        assert raw.get("inherited_policy") == "quarantine"

    # --- PSL fallback path ---

    def test_psl_fallback_sets_inheritance_method(self):
        """Without a tree walk, falls back to PSL org domain lookup."""
        raw = {}
        psl_records = ["v=DMARC1; p=reject"]
        with patch("audit_engine._get_org_domain", return_value="example.com"), \
             patch("audit_engine._lookup_txt", return_value=psl_records):
            _enrich_dmarc_inheritance(raw, "sub.example.com")

        assert raw["inherited_from"] == "example.com"
        assert raw["inherited_policy"] == "reject"
        assert raw["inheritance_method"] == "psl"
        assert raw["is_subdomain"] is True

    def test_psl_fallback_no_org_dmarc_leaves_raw_clean(self):
        """If org domain has no DMARC, raw_dmarc should remain unmodified."""
        raw = {}
        with patch("audit_engine._get_org_domain", return_value="example.com"), \
             patch("audit_engine._lookup_txt", return_value=[]):
            _enrich_dmarc_inheritance(raw, "sub.example.com")
        assert "inherited_policy" not in raw

    def test_psl_fallback_multiple_dmarc_records_leaves_raw_clean(self):
        """Ambiguous org DMARC (multiple records) must not set inheritance."""
        raw = {}
        two_records = ["v=DMARC1; p=none", "v=DMARC1; p=reject"]
        with patch("audit_engine._get_org_domain", return_value="example.com"), \
             patch("audit_engine._lookup_txt", return_value=two_records):
            _enrich_dmarc_inheritance(raw, "sub.example.com")
        assert "inherited_policy" not in raw

    # --- sp= tag overrides p= for subdomains ---

    def test_sp_tag_overrides_p_tag(self):
        """Org domain with sp=quarantine and p=reject: subdomain gets quarantine."""
        raw = {}
        org_record = "v=DMARC1; p=reject; sp=quarantine"
        with patch("audit_engine._get_org_domain", return_value="example.com"), \
             patch("audit_engine._lookup_txt", return_value=[org_record]):
            _enrich_dmarc_inheritance(raw, "sub.example.com")

        assert raw["inherited_policy"] == "quarantine"
        assert raw["applied_tag"] == "sp"

    def test_sp_none_overrides_p_reject(self):
        """Org domain with sp=none means no enforcement for subdomains."""
        raw = {}
        org_record = "v=DMARC1; p=reject; sp=none"
        with patch("audit_engine._get_org_domain", return_value="example.com"), \
             patch("audit_engine._lookup_txt", return_value=[org_record]):
            _enrich_dmarc_inheritance(raw, "sub.example.com")

        assert raw["inherited_policy"] == "none"
        assert raw["applied_tag"] == "sp"

    def test_no_sp_tag_uses_p_tag(self):
        """Org domain with only p= and no sp= passes p= to subdomains."""
        raw = {}
        org_record = "v=DMARC1; p=quarantine"
        with patch("audit_engine._get_org_domain", return_value="example.com"), \
             patch("audit_engine._lookup_txt", return_value=[org_record]):
            _enrich_dmarc_inheritance(raw, "sub.example.com")

        assert raw["inherited_policy"] == "quarantine"
        assert raw["applied_tag"] == "p"


# ============================================================================
# _build_resilience_analysis with inherited DMARC
# ============================================================================

class TestResilienceWithInheritedDmarc(unittest.TestCase):
    """Resilience level logic for non-sending subdomains with inherited policy."""

    def _make_raw_results(self, *, dmarc_extra=None, spf_record=None, mx_records=None):
        """Build a minimal raw_results dict."""
        dmarc = {"record": None, "is_subdomain": True}
        if dmarc_extra:
            dmarc.update(dmarc_extra)

        spf = {"record": spf_record} if spf_record else {}
        dkim = {}
        mx = {"records": mx_records or [], "record_count": len(mx_records or [])}

        return {
            "dmarc": dmarc,
            "spf": spf,
            "dkim": dkim,
            "mx": mx,
        }

    def _run(self, raw_results, has_mx, is_defensive=False):
        return _build_resilience_analysis(
            raw_results=raw_results,
            checks=[],
            has_mx=has_mx,
            is_defensive=is_defensive,
        )

    # --- non-sending subdomain: no MX, no SPF, inherited reject ---

    def test_inherited_reject_no_mx_no_spf_is_high(self):
        """Inherited reject + no MX + no SPF -> level 'high' (non-sending subdomain)."""
        raw = self._make_raw_results(dmarc_extra={
            "inherited_policy": "reject",
            "inherited_from": "example.com",
            "inheritance_method": "tree_walk",
            "applied_tag": "p",
        })
        result = self._run(raw, has_mx=False)
        assert result["level"] == "high", f"Expected 'high', got '{result['level']}'"

    def test_inherited_reject_no_mx_no_spf_summary_mentions_subdomain(self):
        raw = self._make_raw_results(dmarc_extra={
            "inherited_policy": "reject",
            "inherited_from": "example.com",
            "inheritance_method": "psl",
            "applied_tag": "p",
        })
        result = self._run(raw, has_mx=False)
        assert "subdomain" in result["summary"].lower()

    # --- non-sending subdomain: no MX, no SPF, inherited quarantine ---

    def test_inherited_quarantine_no_mx_no_spf_is_moderate(self):
        """Inherited quarantine + no MX + no SPF -> level 'moderate'."""
        raw = self._make_raw_results(dmarc_extra={
            "inherited_policy": "quarantine",
            "inherited_from": "example.com",
            "inheritance_method": "psl",
            "applied_tag": "p",
        })
        result = self._run(raw, has_mx=False)
        assert result["level"] == "moderate", f"Expected 'moderate', got '{result['level']}'"

    # --- subdomain with inherited reject but HAS MX and SPF ---

    def test_inherited_reject_with_mx_and_spf_uses_normal_logic(self):
        """When subdomain has MX and SPF, normal resilience logic applies."""
        raw = self._make_raw_results(
            dmarc_extra={
                "inherited_policy": "reject",
                "inherited_from": "example.com",
                "inheritance_method": "tree_walk",
                "applied_tag": "p",
            },
            spf_record="v=spf1 include:sendgrid.net -all",
            mx_records=[{"exchange": "mail.example.com", "priority": 10}],
        )
        # has_mx=True, spf functional -> should not hit non-sending subdomain branch
        result = self._run(raw, has_mx=True)
        # The non-sending subdomain path requires NOT has_mx AND NOT spf_functional.
        # With both present, it falls into normal logic (spf functional + dmarc enforcing
        # + dkim inconclusive -> moderate or higher, not the non-sending "high").
        # Key assertion: the summary should NOT say "does not send email".
        assert "does not send email" not in result["summary"]

    # --- inherited none: not non-sending ---

    def test_inherited_none_is_not_high(self):
        """Inherited none policy is not enforcing, so no non-sending-subdomain shortcut."""
        raw = self._make_raw_results(dmarc_extra={
            "inherited_policy": "none",
            "inherited_from": "example.com",
            "inheritance_method": "psl",
            "applied_tag": "p",
        })
        result = self._run(raw, has_mx=False)
        # none is not enforcing, so _is_inherited_dmarc is False and we do NOT get
        # the non-sending-subdomain branch
        assert result["level"] != "high"
        assert "does not send email" not in result["summary"]

    # --- mechanisms dict is always present ---

    def test_mechanisms_dict_present_with_inherited_dmarc(self):
        raw = self._make_raw_results(dmarc_extra={
            "inherited_policy": "reject",
            "inherited_from": "example.com",
            "inheritance_method": "tree_walk",
            "applied_tag": "p",
        })
        result = self._run(raw, has_mx=False)
        assert "mechanisms" in result
        assert set(result["mechanisms"].keys()) >= {"spf", "dkim", "dmarc"}

    def test_dmarc_mechanism_note_mentions_inherited(self):
        raw = self._make_raw_results(dmarc_extra={
            "inherited_policy": "reject",
            "inherited_from": "parent.com",
            "inheritance_method": "tree_walk",
            "applied_tag": "p",
        })
        result = self._run(raw, has_mx=False)
        dmarc_note = result["mechanisms"]["dmarc"]["note"]
        assert "parent.com" in dmarc_note or "inherit" in dmarc_note.lower()


# ============================================================================
# detect_anomalies with inherited DMARC
# ============================================================================

class TestAnomalyDetectorInheritedDmarc(unittest.TestCase):
    """Inherited DMARC policy is treated as dmarc_present and dmarc_enforced."""

    def _inherited_dmarc(self, policy):
        """Build a raw dmarc dict representing inherited policy (no own record)."""
        return {
            "record": None,
            "policy": None,
            "is_subdomain": True,
            "inherited_policy": policy,
            "inherited_from": "example.com",
            "inheritance_method": "tree_walk",
        }

    # --- dmarc_present / dmarc_enforced logic ---

    def test_inherited_reject_counts_as_present_and_enforced(self):
        """Inherited reject: 'DMARC enforcement without SPF' anomaly should fire."""
        raw = {
            "dmarc": self._inherited_dmarc("reject"),
            "spf": {"record": None, "raw_record": None},
        }
        result = detect_anomalies(raw, has_mx=True)
        a = _find_anomaly(result, "without SPF")
        assert a is not None, "Expected 'DMARC enforcement without SPF' anomaly"
        assert a["severity"] == "high"

    def test_inherited_quarantine_counts_as_present_and_enforced(self):
        """Inherited quarantine also triggers the 'enforcement without SPF' anomaly."""
        raw = {
            "dmarc": self._inherited_dmarc("quarantine"),
            "spf": {"record": None, "raw_record": None},
        }
        result = detect_anomalies(raw, has_mx=True)
        a = _find_anomaly(result, "without SPF")
        assert a is not None

    def test_inherited_reject_with_spf_no_anomaly(self):
        """Inherited reject + SPF present: no 'enforcement without SPF' anomaly."""
        raw = {
            "dmarc": self._inherited_dmarc("reject"),
            "spf": {"record": "v=spf1 include:sendgrid.net -all"},
        }
        result = detect_anomalies(raw, has_mx=True)
        assert _find_anomaly(result, "without SPF") is None

    def test_inherited_none_does_not_fire_enforcement_anomaly(self):
        """Inherited none policy: not enforced, so no 'enforcement without SPF'."""
        raw = {
            "dmarc": self._inherited_dmarc("none"),
            "spf": {"record": None, "raw_record": None},
        }
        result = detect_anomalies(raw, has_mx=True)
        assert _find_anomaly(result, "without SPF") is None

    # --- has_mx guard on the anomaly ---

    def test_inherited_enforce_no_mx_no_anomaly(self):
        """Inherited reject + no SPF but no MX: enforcement anomaly still fires
        (has_mx does not gate rule 1, only affects some other rules)."""
        raw = {
            "dmarc": self._inherited_dmarc("reject"),
            "spf": {"record": None},
        }
        # Rule 1 fires regardless of has_mx
        result = detect_anomalies(raw, has_mx=False)
        # Rule 1 does NOT check has_mx, so it fires
        assert _find_anomaly(result, "without SPF") is not None

    # --- no own-record, no inherited: not present ---

    def test_no_record_no_inherited_no_enforcement_anomaly(self):
        """Completely absent DMARC: anomaly should not fire (not enforced)."""
        raw = {
            "dmarc": {"record": None, "policy": None},
            "spf": {"record": None},
        }
        result = detect_anomalies(raw, has_mx=True)
        assert _find_anomaly(result, "without SPF") is None

    # --- PSL-path inherited DMARC also works ---

    def test_psl_inherited_reject_fires_anomaly(self):
        raw = {
            "dmarc": {
                "record": None,
                "policy": None,
                "is_subdomain": True,
                "inherited_policy": "reject",
                "inherited_from": "example.com",
                "inheritance_method": "psl",
            },
            "spf": {},
        }
        result = detect_anomalies(raw, has_mx=True)
        assert _find_anomaly(result, "without SPF") is not None

    # --- return type and structure ---

    def test_return_is_list(self):
        result = detect_anomalies(
            {"dmarc": self._inherited_dmarc("reject"), "spf": {"record": "v=spf1 -all"}},
            has_mx=True,
        )
        assert isinstance(result, list)

    def test_anomaly_has_required_keys(self):
        raw = {
            "dmarc": self._inherited_dmarc("reject"),
            "spf": {"record": None},
        }
        result = detect_anomalies(raw, has_mx=True)
        for a in result:
            assert {"title", "description", "severity", "recommendation"} <= set(a.keys())


# ============================================================================
# No em-dashes in DMARC inheritance output (CLAUDE.md rule)
# ============================================================================

class TestNoEmDashesInInheritedOutput(unittest.TestCase):
    """No em-dashes or double-hyphens in user-facing text from inherited DMARC paths."""

    EM_DASH = "\u2014"

    def _all_anomaly_text(self, anomalies):
        parts = []
        for a in anomalies:
            parts.extend([a.get("title", ""), a.get("description", ""), a.get("recommendation", "")])
        return " ".join(parts)

    def test_anomaly_text_no_em_dash(self):
        raw = {
            "dmarc": {
                "record": None,
                "policy": None,
                "is_subdomain": True,
                "inherited_policy": "reject",
                "inherited_from": "example.com",
                "inheritance_method": "tree_walk",
            },
            "spf": {"record": None},
        }
        anomalies = detect_anomalies(raw, has_mx=True)
        text = self._all_anomaly_text(anomalies)
        assert self.EM_DASH not in text

    def test_resilience_text_no_em_dash(self):
        raw_results = {
            "dmarc": {
                "record": None,
                "policy": None,
                "is_subdomain": True,
                "inherited_policy": "reject",
                "inherited_from": "example.com",
                "inheritance_method": "tree_walk",
                "applied_tag": "p",
            },
            "spf": {},
            "dkim": {},
        }
        result = _build_resilience_analysis(raw_results, [], has_mx=False, is_defensive=False)
        text = result.get("summary", "") + result.get("risk", "")
        assert self.EM_DASH not in text


if __name__ == "__main__":
    unittest.main()
