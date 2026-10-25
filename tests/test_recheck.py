"""Recheck (2026-10-25): what changed since the last audit in this browser.

The page keeps, in localStorage only, the latest two audits of each domain
and scope, and shows what got fixed, what is new, and which checks moved.
A re-render of the same result compares with the audit before it.
"""
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_dmarc_grades import RUA, _run
from test_ui_consistency_a11y import _page, _render, browser  # noqa: F401


def _data(audit, dmarc, at):
    d = json.loads(json.dumps(_run(audit, dmarc, scope="deliverability"), default=str))
    d["audited_at"] = at
    return d


def test_the_first_audit_shows_no_comparison(browser, audit):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, _data(audit, f"v=DMARC1; p=none; {RUA}", "2026-10-20T10:00:00Z"))
        assert page.locator(".recheck").count() == 0
        assert not errors, errors
    finally:
        ctx.close()


def test_a_fix_shows_as_fixed_and_better(browser, audit):  # noqa: F811
    broken = _data(audit, None, "2026-10-20T10:00:00Z")
    fixed = _data(audit, f"v=DMARC1; p=none; {RUA}", "2026-10-24T10:00:00Z")
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, broken)
        _render(page, fixed)
        text = page.inner_text(".recheck")
        assert text.startswith("Since your last check on")
        assert "FIXED" in text.upper()
        assert "Spoofing policy (DMARC): Needs fixing to Pass" in text
        # A re-render of the same result still compares with the one before.
        _render(page, copy.deepcopy(fixed))
        assert "Needs fixing to Pass" in page.inner_text(".recheck")
        stored = page.evaluate("() => JSON.parse(localStorage.getItem('auditHistory'))")
        assert list(stored) == ["doc44.test|deliverability"]
        assert not errors, errors
    finally:
        ctx.close()


def test_a_regression_shows_as_new_and_worse(browser, audit):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, _data(audit, f"v=DMARC1; p=none; {RUA}", "2026-10-20T10:00:00Z"))
        _render(page, _data(audit, None, "2026-10-24T10:00:00Z"))
        text = page.inner_text(".recheck").upper()
        assert "NEW (" in text and "WORSE (" in text
    finally:
        ctx.close()


def test_the_same_result_twice_says_nothing_changed(browser, audit):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, _data(audit, f"v=DMARC1; p=none; {RUA}", "2026-10-20T10:00:00Z"))
        _render(page, _data(audit, f"v=DMARC1; p=none; {RUA}", "2026-10-24T10:00:00Z"))
        assert "Nothing changed." in page.inner_text(".recheck")
    finally:
        ctx.close()


def test_clear_removes_the_history_too(browser, audit):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, _data(audit, f"v=DMARC1; p=none; {RUA}", "2026-10-20T10:00:00Z"))
        page.click(".recent-audits-clear")
        assert page.evaluate("() => localStorage.getItem('auditHistory')") is None
    finally:
        ctx.close()
