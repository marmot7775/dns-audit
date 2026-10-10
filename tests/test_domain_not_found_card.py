"""A domain that does not exist gets a plain "Domain not found" card.

The card read "Audit Failed" in the fail colour with a Try Again button,
for what is nearly always a typo: Try Again ran the same name and failed
the same way. The heading is neutral, there is no retry, and the cursor
goes back to the domain field with the name selected for correction.
Other errors keep "Audit Failed" and Try Again.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_ui_consistency_a11y import _page, browser  # noqa: E402,F401

MESSAGE = "This domain does not exist in DNS. Verify the spelling and try again."


def _show(page, error):
    page.evaluate("""([error, message]) => {
        document.getElementById('domain-input').value = 'example.comds';
        renderResults({domain: 'example.comds', checks: [], error, error_message: message});
    }""", [error, MESSAGE])
    return page.evaluate("""() => {
        const card = document.querySelector('#loading-section .loading-card');
        const title = card.querySelector('.error-title');
        return {title: title.textContent.trim(), color: getComputedStyle(title).color,
                retry: !!card.querySelector('#retry-btn'),
                focused: document.activeElement && document.activeElement.id};
    }""")


def test_missing_domain_is_not_an_audit_failure(browser):  # noqa: F811
    for theme in ("dark", "light"):
        ctx, page, errors = _page(browser, theme, 1280)
        try:
            shown = _show(page, "domain_not_found")
            text = page.evaluate("getComputedStyle(document.body).color")
            assert shown["title"] == "Domain not found"
            assert shown["color"] == text, "heading should use the body text colour, not red"
            assert not shown["retry"]
            assert shown["focused"] == "domain-input"
            assert errors == []
        finally:
            ctx.close()


def test_other_errors_keep_try_again(browser):  # noqa: F811
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        shown = _show(page, "timeout")
        assert shown["title"] == "Audit Failed"
        assert shown["retry"]
    finally:
        ctx.close()
