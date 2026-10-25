import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dns_tools import normalize_domain


def test_normalize_domain_lowercases_and_strips_url_email_and_trailing_dot():
    assert normalize_domain("EXAMPLE.com") == "example.com"
    assert normalize_domain("https://www.example.com/path") == "www.example.com"
    assert normalize_domain("user@example.com") == "example.com"
    assert normalize_domain("example.com.") == "example.com"
    assert normalize_domain("") == ""


def test_normalize_domain_strips_the_scheme():
    assert normalize_domain("http://example.com") == "example.com"
    assert normalize_domain("https://example.com") == "example.com"


def test_normalize_domain_with_query():
    assert normalize_domain("example.com/page?q=1") == "example.com"


def test_normalize_domain_strips_the_port():
    assert normalize_domain("example.com:443") == "example.com"
    assert normalize_domain("https://example.com:8080/path") == "example.com"


def test_normalize_domain_edge_cases():
    assert normalize_domain("https://www.example.com/page?q=test") == "www.example.com"
    assert normalize_domain("user@gmail.com") == "gmail.com"
    assert normalize_domain("example.com.") == "example.com"
    assert normalize_domain("example.com:443") == "example.com"


def test_normalize_domain_converts_idn_to_punycode():
    # Internationalized domain name converts to punycode
    assert normalize_domain("münchen.de") == "xn--mnchen-3ya.de"
    assert normalize_domain("BÜCHER.de") == "xn--bcher-kva.de"


def test_normalize_domain_invalid_no_exception():
    # Best-effort: invalid IDN passes through (lowercased) for downstream validation.
    assert normalize_domain("not a domain") == "not a domain"


def test_normalize_domain_ignores_an_at_sign_in_the_url_path_or_query():
    # Only an "@" in the authority part names the host. One in the path or
    # the query used to win, so the wrong domain was audited silently.
    assert normalize_domain("https://example.com/contact?to=a@example.net") == "example.com"
    assert normalize_domain("https://medium.example/@someone") == "medium.example"
    assert normalize_domain("example.com/@x") == "example.com"
    assert normalize_domain("example.com#a@example.net") == "example.com"
    # An address and userinfo still resolve to the host after the "@".
    assert normalize_domain("mailto:someone@example.org") == "example.org"
    assert normalize_domain("https://user@example.org/path") == "example.org"
