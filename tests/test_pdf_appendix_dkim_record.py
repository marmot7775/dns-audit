"""The PDF appendix prints the complete DKIM record.

The Checks section shortens a long p= value to its first 24 characters, and
the appendix key table carries selector, bits and rotation but not the key,
so the report lost the evidence behind the card. The appendix now prints the
whole record, and Checks keeps the short form.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_pdf_two_parts import _pages, _rsa_key_record, _run, _zone  # noqa: E402


def _squash(text):
    return "".join(text.split())


@pytest.fixture(scope="module")
def pages_and_key():
    record = _rsa_key_record()
    p_value = record.split("p=", 1)[1]
    assert len(p_value) > 300  # a 2048 bit key
    return _pages(_run(_zone(record))), p_value


def test_appendix_holds_the_whole_p_value(pages_and_key):
    pages, p_value = pages_and_key
    text = " ".join(pages)
    start = text.index("Complete DKIM record")
    assert p_value in _squash(text[start:])


def test_checks_section_keeps_the_shortened_value(pages_and_key):
    pages, p_value = pages_and_key
    text = " ".join(pages)
    # Part 1 (the Checks section included) ends where the Part 2 divider starts.
    checks = text[:text.index("Part 2: Appendix")]
    assert p_value[:24] + "..." in _squash(checks)
    assert p_value not in _squash(checks)
