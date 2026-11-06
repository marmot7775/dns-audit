"""The privacy page's "Last updated" date must not predate its last body edit."""
import re
from datetime import datetime
from pathlib import Path

PAGE = Path(__file__).resolve().parent.parent / "static" / "privacy.html"
# Date of the most recent body edit (the DNS lookup paragraph, 2026-11-05).
LAST_BODY_EDIT = datetime(2026, 11, 5)


def test_last_updated_not_before_last_body_edit():
    m = re.search(r"Last updated:</strong>\s*(\d{1,2} \w+ \d{4})", PAGE.read_text())
    assert m, "Last updated line missing"
    assert datetime.strptime(m.group(1), "%d %B %Y") >= LAST_BODY_EDIT
