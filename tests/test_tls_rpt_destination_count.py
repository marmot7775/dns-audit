"""Regression test for TLS-RPT destinations reaching the card.

Bug 43: a deep panel read raw["destinations"], but the check emits
"report_destinations". The panel had no reader and left in Doc 49; the card
verdict reads the same field and is what this pins.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from result_transformer import transform_tls_rpt


def _raw(record, destinations):
    return {
        "status": "ok",
        "record": record,
        "report_destinations": destinations,
        "issues": [],
        "ttl": 3600,
    }


def test_card_counts_every_destination():
    destinations = ["mailto:a@example.com", "mailto:b@example.com"]
    card = transform_tls_rpt(
        _raw("v=TLSRPTv1; rua=mailto:a@example.com,mailto:b@example.com", destinations),
        "example.com",
    )
    assert "2 destinations" in card["verdict"]
