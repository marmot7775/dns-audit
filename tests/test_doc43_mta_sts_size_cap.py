"""Doc 43 item 2: the MTA-STS policy fetch stops at 64 KB.

It used to read resp.text, which loads and gunzips the whole body, so a
domain serving a huge or gzip-bombed policy made every audit of it allocate
the lot in the single worker. The fetch now streams with a cap the way the
BIMI logo fetch does.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns
import checks_extra
from result_transformer import transform_mta_sts

DOMAIN = "bigpolicy.test"
CHUNK = 8192


class _BigPolicyResponse:
    """A 200 KB policy that counts how much of itself was pulled."""

    status_code = 200
    headers = {"Content-Type": "text/plain"}
    encoding = None

    def __init__(self, size):
        self._size = size
        self.consumed = 0
        self.closed = False

    @property
    def text(self):
        raise AssertionError("resp.text loads the whole body; the fetch must stream")

    @property
    def content(self):
        raise AssertionError("resp.content loads the whole body; the fetch must stream")

    def iter_content(self, chunk_size=CHUNK):
        while self.consumed < self._size:
            n = min(chunk_size, self._size - self.consumed)
            self.consumed += n
            yield b"a" * n

    def close(self):
        self.closed = True


def _zone():
    return FakeZone({
        DOMAIN: {"MX": [(10, f"mail.{DOMAIN}")], "A": ["203.0.113.70"]},
        f"_mta-sts.{DOMAIN}": {"TXT": ["v=STSv1; id=20260913"]},
    })


def test_oversized_policy_is_a_finding_not_a_read():
    resp = _BigPolicyResponse(200 * 1024)
    with fake_dns(_zone()), \
            patch.object(checks_extra, "_safe_fetch", return_value=resp) as fetch:
        raw = checks_extra.check_mta_sts(DOMAIN)

    assert fetch.call_args.kwargs.get("stream") is True

    finding = [i for i in raw["issues"]
               if i["issue"] == "Policy file larger than 64 KB, not read"]
    assert len(finding) == 1 and finding[0]["severity"] == "error"
    assert raw["status"] == "error"
    assert raw["policy"] is None and raw["policy_mode"] is None, (
        "nothing past the cap may be parsed as a policy")
    assert transform_mta_sts(raw, DOMAIN)["status"] == "fail"

    # Knowing a body is over the cap takes seeing the byte after it, so the
    # read can pass the cap by at most the one chunk that crossed it, and
    # never goes on to the rest of the 200 KB.
    assert resp.consumed <= checks_extra.MTA_STS_POLICY_MAX_BYTES + CHUNK
    assert resp.consumed < 200 * 1024
    assert resp.closed


def test_policy_at_the_cap_is_still_read():
    """Control: a policy that fits is parsed, not reported as oversized."""
    policy = "version: STSv1\nmode: enforce\nmx: mail.bigpolicy.test\nmax_age: 604800\n"
    with fake_dns(_zone(), mta_sts_policy=policy):
        raw = checks_extra.check_mta_sts(DOMAIN)
    assert raw["policy_mode"] == "enforce"
    assert not any("larger than 64 KB" in i["issue"] for i in raw["issues"])
