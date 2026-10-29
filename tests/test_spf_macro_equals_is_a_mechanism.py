"""A mechanism whose macro uses "=" as a delimiter is not a modifier.

RFC 7208 section 7.1 allows "=" among the macro delimiters, so
exists:%{l=}.%{d}._spf.example.com is an exists mechanism. The syntax check
took any term with "=" in it for a modifier and reported an unknown modifier
named "exists:%{l".
"""
from unittest.mock import patch

import audit_engine
import spf_recursive

DOMAIN = "example.com"
RECORD = "v=spf1 exists:%{l=}.%{d}._spf.example.com -all"


def _raw_spf():
    with patch.object(audit_engine, "_lookup_txt", return_value=[RECORD]), \
         patch.object(audit_engine, "_lookup_ttl", return_value=None), \
         patch.object(spf_recursive, "_lookup_spf",
                      return_value={"record": RECORD,
                                    "status": spf_recursive.SPF_FOUND,
                                    "error": None}):
        return audit_engine._raw_check_spf(DOMAIN)


def test_macro_with_equals_delimiter_is_not_an_unknown_modifier():
    raw = _raw_spf()
    assert not any("modifier" in i["issue"].lower() for i in raw["issues"]), raw["issues"]
    assert not raw["syntax_errors"]
