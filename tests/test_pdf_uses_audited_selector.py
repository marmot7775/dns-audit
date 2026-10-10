"""The PDF button asks for the audit the page shows.

It took the domain from the result but the DKIM selector from the input,
so editing the selector after a run gave a PDF for a different selector
than the results on screen. The selector is now captured when the audit
starts, beside the result it produces.
"""
import os
import re

APP_JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "static", "app.js")


def _source():
    with open(APP_JS, encoding="utf-8") as f:
        return f.read()


def _pdf_handler(src):
    start = src.index("document.getElementById('pdf-btn').addEventListener")
    return src[start:src.index("});", start)]


def test_pdf_handler_does_not_read_the_selector_input():
    handler = _pdf_handler(_source())
    assert "selector-input" not in handler
    assert "domainInput" not in handler
    assert "lastAuditSelector" in handler and "lastAuditData.domain" in handler


def test_selector_is_stored_with_the_result_it_produced():
    """Set where lastAuditData is set, not when a run starts: a run that
    fails or is overtaken must not leave its selector beside an older
    result."""
    src = _source()
    render = src[src.index("function renderResults("):]
    render = render[:render.index("\n}\n")]
    assert re.search(r"lastAuditData = data;\s*lastAuditSelector = selector;", render)
    run = src[src.index("async function runAudit("):src.index("function renderResults(")]
    assert "lastAuditSelector" not in run
    assert run.count("renderResults(") == run.count(", selectorVal)")
