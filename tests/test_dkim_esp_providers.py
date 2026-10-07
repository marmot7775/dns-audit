"""The DKIM card names the email service behind each ESP key it finds.

Doc 93 put ESP_SELECTORS in the first wave on every domain, but a key was
tagged with a vendor only when SPF or MX named that vendor. casper.com
(Google in SPF, Mailchimp, Mandrill, SendGrid and Campaign Monitor keys
found by name) read "Sending providers detected: Google Workspace", and
the key table called its SendGrid s1/s2 keys "Generic (Exchange)".
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from comprehensive_selectors import ESP_SELECTORS
from result_transformer import (
    _DKIM_SELECTOR_PROVIDERS,
    _build_dkim_key_analysis,
    transform_dkim,
)
from test_dkim_discovery_starvation import DKIM_RECORD

DOMAIN = "esp.test"


def _raw(selectors, vendors=None, method="spf_intelligent"):
    vendors = vendors or {}
    return {
        "configured": True,
        "status": "pass",
        "discovery_method": method,
        "tested_count": 86,
        "found_selectors": [
            {"selector": s, "record": DKIM_RECORD, "vendor": vendors.get(s)}
            for s in selectors
        ],
        "issues": [],
    }


def test_every_esp_selector_but_api_names_a_vendor():
    """api is the one ESP name too common to credit to Elastic Email."""
    unnamed = [s for s in ESP_SELECTORS if s not in _DKIM_SELECTOR_PROVIDERS]
    assert unnamed == ["api"]


def test_sendgrid_s1_s2_are_not_generic():
    assert _DKIM_SELECTOR_PROVIDERS["s1"] == "SendGrid"
    assert _DKIM_SELECTOR_PROVIDERS["s2"] == "SendGrid"
    assert not any("." in k for k in _DKIM_SELECTOR_PROVIDERS)


def test_card_lists_providers_found_by_selector_name():
    raw = _raw(["google", "k1", "s1", "mandrill", "cm"],
               vendors={"google": "Google Workspace"})
    card = transform_dkim(raw, DOMAIN)
    assert ("Sending providers detected: Campaign Monitor, Google Workspace, "
            "Mailchimp, Mandrill, SendGrid.") in card["explanation"]
    texts = " ".join(d["text"] for d in card["details"])
    assert "k1:" in texts and "(Mailchimp)" in texts
    assert "(SendGrid)" in texts


def test_spf_vendor_tag_wins_over_the_name():
    raw = _raw(["s1"], vendors={"s1": "Some Relay"})
    card = transform_dkim(raw, DOMAIN)
    assert "Sending providers detected: Some Relay." in card["explanation"]


def test_generic_names_are_not_a_provider():
    card = transform_dkim(_raw(["default"], method="blind_loop"), DOMAIN)
    assert "Sending providers detected" not in card["explanation"]


def test_unattributed_api_key_names_no_provider():
    card = transform_dkim(_raw(["api", "intercom"]), DOMAIN)
    assert "Sending providers detected: Intercom." in card["explanation"]
    keys = {k["selector"]: k["provider"] for k in _build_dkim_key_analysis(
        _raw(["api", "intercom"]))["keys"]}
    assert keys == {"api": None, "intercom": "Intercom"}


def test_discovery_sentence_mentions_the_esp_names():
    card = transform_dkim(_raw(["k1"]), DOMAIN)
    assert "SPF-based sender discovery" not in card["explanation"]
    assert "the fixed selectors common email services use" in card["explanation"]


def test_retired_key_names_no_sending_provider():
    raw = _raw(["s1"])
    raw["found_selectors"].append({"selector": "k1", "record": "v=DKIM1; k=rsa; p=", "vendor": None})
    card = transform_dkim(raw, DOMAIN)
    assert "Sending providers detected: SendGrid." in card["explanation"]
    assert "Mailchimp" not in card["explanation"]


def test_key_table_never_says_generic():
    keys = _build_dkim_key_analysis(_raw(["default"], method="blind_loop"))["keys"]
    assert keys[0]["provider"] is None
