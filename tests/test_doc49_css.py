"""Doc 49 item 4: static/style.css carries no dead rules and no restated
selectors, uses one mobile breakpoint, and keeps !important only where
nothing else can win (inline styles set from JS, the reduced-motion and
print overrides).

The dead-rule pass is the one the doc describes: every class and id a
selector names must appear somewhere in the pages, the three scripts or the
Python that emits HTML, or start with a prefix app.js builds class names
from in a template or a concatenation.
"""
import glob
import os
import re
from collections import Counter

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO, "static")


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _css():
    return re.sub(r"/\*.*?\*/", "", _read(os.path.join(STATIC, "style.css")), flags=re.S)


def _rules(css):
    """(context, selector, body) for each rule, one level of @media deep."""
    out = []
    pos = 0
    ctx = ""
    depth = 0
    buf_start = 0
    stack = []
    for m in re.finditer(r"[{}]", css):
        if m.group() == "{":
            prelude = css[buf_start:m.start()].strip()
            stack.append(prelude)
            buf_start = m.end()
            depth += 1
        else:
            prelude = stack.pop()
            depth -= 1
            if not prelude.startswith("@"):
                ctx = " ".join(p for p in stack if p.startswith("@"))
                out.append((ctx, " ".join(prelude.split()), css[m.start() - 1:m.start()]))
            buf_start = m.end()
    return out


def _corpus():
    files = (glob.glob(os.path.join(STATIC, "*.html"))
             + glob.glob(os.path.join(STATIC, "articles", "*.html"))
             + [os.path.join(STATIC, f) for f in ("app.js", "articles.js", "theme.js")]
             + glob.glob(os.path.join(REPO, "*.py")))
    return {f: _read(f) for f in files}


def test_no_selector_names_a_class_or_id_nothing_emits():
    corpus = _corpus()
    tokens = set()
    for text in corpus.values():
        tokens.update(re.findall(r"[A-Za-z_][\w-]*", text))
    prefixes = set()
    for name in ("app.js", "articles.js", "theme.js"):
        js = corpus[os.path.join(STATIC, name)]
        prefixes.update(re.findall(r"""([A-Za-z][\w-]*-)(?:['"]\s*\+|\$\{)""", js))

    dead = []
    for ctx, sel, _ in _rules(_css()):
        if sel.startswith("@") or "font-face" in ctx:
            continue
        for part in sel.split(","):
            names = re.findall(r"[.#]([A-Za-z_][\w-]*)", re.sub(r"\[[^\]]*\]", "", part))
            missing = [n for n in names
                       if n not in tokens and not any(n.startswith(p) for p in prefixes)]
            if missing:
                dead.append(f"{part.strip()} ({', '.join(missing)})")
    assert not dead, "selectors that match nothing any page or script emits:\n" + "\n".join(dead)


# A selector list shared on purpose: the tier tags' one uppercase rule, the
# tree walk's animation shorthand followed by per-line delays, the iOS input
# reset, and the Doc 38 prose rule shared by the About page and the articles.
_SHARED = {".tag-critical", ".tag-high", ".tag-medium", ".tag-low",
           ".tw-animated.tree-walk-simple .tw-simple-body",
           ".tw-animated.tree-walk-simple .tw-simple-policy",
           ".tw-animated.tree-walk-simple .tw-footnote",
           ".domain-input", ".about-page p"}


def test_no_selector_is_declared_twice_in_the_same_context():
    seen = Counter()
    for ctx, sel, _ in _rules(_css()):
        for part in sel.split(","):
            seen[(ctx, part.strip())] += 1
    twice = sorted(f"{c or 'top level'}: {s}" for (c, s), n in seen.items()
                   if n > 1 and s not in _SHARED)
    assert not twice, "declared more than once:\n" + "\n".join(twice)


def test_one_mobile_breakpoint():
    css = _css()
    assert "max-width: 600px)" not in css
    assert css.count("@media (max-width: 640px)") >= 20


def test_important_only_where_specificity_cannot_win():
    css = _css()
    lines = [l.strip() for l in css.splitlines() if "!important" in l]
    # reduced motion (6), print (2), and the progress bar whose width app.js
    # writes as an inline style (1)
    assert len(lines) == 9, lines
    assert "width: 100% !important;" in lines


def test_families_doc_49_removed_are_gone():
    css = _css()
    for gone in (".comparison-", ".compare-btn", ".edu-", ".se-vendor-", ".ha-",
                 ".dbis-walk", ".dbis-hero", ".fix-block", ".details-toggle",
                 ".resilience-pass", ".selector-wrapper", ".audit-trust",
                 ".result-card:nth-child(1)"):
        assert gone not in css, gone
    # still used by app.js
    assert ".sr-only" in css
