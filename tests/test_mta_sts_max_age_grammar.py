"""RFC 8461 section 3.2: max_age is 1*10DIGIT, from 0 to 31557600.

int() accepted "-5" (graded a short-max_age warning) and "1_000_000"
(graded pass), neither of which the grammar allows.
"""
from unittest.mock import patch

import pytest

import checks_extra


def _issues(max_age):
    text = f"version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: {max_age}\n"
    with patch.object(checks_extra, "_lookup_records", return_value=["10 mx.example.com."]):
        policy, issues = checks_extra._validate_mta_sts_policy(text, "example.com")
    return policy, issues


@pytest.mark.parametrize("value", ["-5", "+604800", "1_000_000", "604800.0", "12345678901"])
def test_max_age_outside_the_grammar_is_an_error(value):
    policy, issues = _issues(value)
    errors = [i for i in issues if i["severity"] == "error"]
    assert errors, issues
    assert "max_age" in errors[0]["issue"]


def test_a_plain_max_age_still_passes():
    policy, issues = _issues("604800")
    assert policy["max_age"] == 604800
    assert not [i for i in issues if i["severity"] in ("error", "warning")], issues
