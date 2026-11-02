"""Doc 90: the results contact note, rendered in a real page. The source scan
in test_contact_alias.py cannot see wrong renderResults() arguments or wrong
DOM visibility, so these cases render a result and read the note."""
import copy

# Reuse the browser suite's fixtures and helpers.
import test_ui_consistency_a11y as ui

_page, _render = ui._page, ui._render
browser = ui.browser
fixture_result = ui.fixture_result


def _note(browser, data):
    ctx, page, _errors = _page(browser, "dark", 1280)
    try:
        _render(page, data, open_checks=False)
        return page.evaluate("""() => {
            const n = document.getElementById('results-contact-note');
            return {text: n.textContent, hidden: n.classList.contains('is-hidden'),
                    shown: n.offsetParent !== null};
        }""")
    finally:
        ctx.close()


def _clean(data):
    d = copy.deepcopy(data)
    for c in d.get("checks", []):
        c["status"] = "pass"
    d["defensive_dns"] = False
    d["defensive_signals"] = []
    return d


def test_failing_audit_shows_the_help_note(browser, fixture_result):
    d = copy.deepcopy(fixture_result)
    d["checks"][0]["status"] = "fail"
    note = _note(browser, d)
    assert note["shown"] and not note["hidden"]
    assert "If you'd like help with these changes" in note["text"]
    assert "Message me on LinkedIn" in note["text"]


def test_clean_audit_of_a_mail_domain_shows_the_clean_note(browser, fixture_result):
    note = _note(browser, _clean(fixture_result))
    assert note["shown"] and not note["hidden"], note
    assert "No problems found in this domain's DNS." in note["text"]
    assert "Message me on LinkedIn" in note["text"]


def test_null_spf_and_null_mx_domains_get_no_note(browser, fixture_result):
    for signal in ("null_spf", "null_mx"):
        d = _clean(fixture_result)
        d["defensive_signals"] = [signal]
        note = _note(browser, d)
        assert note["hidden"] and note["text"] == "", signal
