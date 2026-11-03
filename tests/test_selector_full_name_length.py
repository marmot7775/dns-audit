"""The queried name <selector>._domainkey.<domain> must fit in 253 characters.

A selector under the 253 cap could still make a name dnspython refuses
(NameTooLong), and the card said "Selector ... not found" in red for a
name DNS cannot hold. All three endpoints refuse it with a 400 instead.
"""
import pytest
from fastapi.testclient import TestClient

DOMAIN = "t.test"
# 4 labels of 60 plus 3 dots: 243 characters, valid on its own.
LONG = ".".join(["a" * 60] * 4)


@pytest.fixture
def client():
    import server
    return TestClient(server.app)


@pytest.mark.parametrize("path", ["/api/audit", "/api/audit/stream", f"/api/audit/{DOMAIN}/pdf"])
def test_selector_that_overflows_the_full_name_is_refused(client, path):
    params = {"selector": LONG}
    if "{" not in path and not path.endswith("/pdf"):
        params["domain"] = DOMAIN
    resp = client.get(path, params=params)
    assert resp.status_code == 400, resp.text[:200]
    assert "longer than 253 characters" in resp.json()["detail"]


def test_selector_that_fits_is_not_refused_for_length():
    import server
    assert server._validate_selector("a" * 60, DOMAIN) == "a" * 60
    assert server._validate_selector(" s1 ", DOMAIN) == "s1"
