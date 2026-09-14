"""Doc 43 item 5: text from a DNS record must not become markup in a card.

The explanation is rendered through app.js sanitizeHtml, whose allowlist
keeps <a>. A TLS-RPT rua value was appended to the explanation unescaped, so
whoever publishes _smtp._tls could plant a labelled link inside the card's
own prose.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns
import checks_extra
from result_transformer import transform_tls_rpt

DOMAIN = "rua-markup.test"
PAYLOAD = "mailto:<a href=https://evil.test/verify>Click here to verify your DMARC now</a>"


def test_tls_rpt_rua_markup_is_literal_text_in_the_explanation():
    zone = FakeZone({
        DOMAIN: {"MX": [(10, f"mail.{DOMAIN}")], "A": ["203.0.113.60"]},
        f"_smtp._tls.{DOMAIN}": {"TXT": [f"v=TLSRPTv1; rua={PAYLOAD}"]},
    })
    with fake_dns(zone):
        raw = checks_extra.check_tls_rpt(DOMAIN)
    assert PAYLOAD in raw["report_destinations"], "the record must reach the card"

    explanation = transform_tls_rpt(raw, DOMAIN)["explanation"]

    assert "<a href=https://evil.test" not in explanation
    assert ("&lt;a href=https://evil.test/verify&gt;Click here to verify your "
            "DMARC now&lt;/a&gt;") in explanation
    # The card's own RFC link is still markup.
    assert '<a href="https://datatracker.ietf.org/doc/html/rfc8460"' in explanation
