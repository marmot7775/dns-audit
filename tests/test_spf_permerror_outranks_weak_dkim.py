"""An SPF lookup PermError is the biggest risk, not a 1024-bit DKIM key.

gitlab.com (13 SPF lookups), lyft.com and clickup.com all publish an SPF
record past the 10-lookup limit and a 1024-bit DKIM key. The roadmap added
the weak-key row before the SPF over-limit row, both ranked high, and the
sort only looks at priority, so the executive summary named "Rotate the weak
DKIM key" as the biggest risk. Past 10 lookups receivers return PermError for
every message (RFC 7208 section 4.6.4), the same outcome as a duplicate SPF
record, which was already critical. The over-limit row is now critical too.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DOMAIN = "gl.test"


def _rsa_key_record(bits):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    der = (rsa.generate_private_key(public_exponent=65537, key_size=bits)
           .public_key()
           .public_bytes(serialization.Encoding.DER,
                         serialization.PublicFormat.SubjectPublicKeyInfo))
    return "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()


def _zone(lookups):
    zone = {
        DOMAIN: {
            "MX": [(10, f"mail.{DOMAIN}")],
            "TXT": ["v=spf1 " + " ".join(f"a:h{i}.{DOMAIN}" for i in range(lookups)) + " ~all"],
            "A": ["203.0.113.1"],
        },
        f"_dmarc.{DOMAIN}": {"TXT": [f"v=DMARC1; p=reject; rua=mailto:d@{DOMAIN}"]},
        f"mail.{DOMAIN}": {"A": ["203.0.113.2"]},
        f"default._domainkey.{DOMAIN}": {"TXT": [_rsa_key_record(1024)]},
    }
    for i in range(lookups):
        zone[f"h{i}.{DOMAIN}"] = {"A": ["203.0.113.3"]}
    return zone


def test_spf_over_limit_is_the_biggest_risk(audit):
    result = audit(_zone(13), DOMAIN)
    items = result["security_roadmap"]["items"]

    spf_rows = [i for i in items if i["protocol"] == "SPF" and "SPF lookups" in i["action"]]
    assert len(spf_rows) == 1, spf_rows
    assert spf_rows[0]["priority"] == "critical"

    # The weak key is still on the plan, below the PermError.
    dkim_rows = [i for i in items if i["protocol"] == "DKIM" and "weak DKIM key" in i["action"]]
    assert dkim_rows, items
    assert items.index(spf_rows[0]) < items.index(dkim_rows[0])

    summary = result["executive_summary"]
    assert summary["biggest_risk"] == "Reduce SPF lookups (13/10)", summary["biggest_risk"]
