"""Doc 48: UI defects, consistency, and accessibility.

Static checks read the shipped files. Browser checks render the Doc 38
fixture zone in headless Chromium through renderResults() and measure the
page; they skip where Chromium is not installed, and CI installs it.
"""
import base64
import glob
import json
import mimetypes
import os
import re
import struct
import sys
import zlib
from urllib.parse import urlparse

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conftest import FakeZone, fake_dns  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(REPO_ROOT, "static")
PAGES = sorted(glob.glob(os.path.join(STATIC, "*.html"))
               + glob.glob(os.path.join(STATIC, "articles", "*.html")))

DOMAIN = "doc48.test"


def _read(*parts):
    with open(os.path.join(REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _css():
    return _read("static", "style.css")


def _rules(css):
    """(selector, body) for every innermost rule."""
    return [(m.group(1).strip(), m.group(2)) for m in re.finditer(r"([^{}]*)\{([^{}]*)\}", css)]


# ---------------------------------------------------------------
# Every CSS variable used is defined
# ---------------------------------------------------------------

# Set per element from app.js with style.setProperty, never in a token block.
SET_FROM_JS = {"--line-delay"}


def _token_blocks(css):
    root = re.search(r"(?m)^:root \{(.*?)^\}", css, re.S).group(1)
    media = re.search(r':root:where\(:not\(\[data-theme="dark"\]\)\) \{(.*?)\}', css, re.S).group(1)
    light = re.search(r':root:where\(\[data-theme="light"\]\) \{(.*?)\}', css, re.S).group(1)
    return root, media, light


def test_every_css_variable_used_is_defined_in_the_token_blocks():
    css = _css()
    defined = set()
    for block in _token_blocks(css):
        defined |= set(re.findall(r"(--[\w-]+)\s*:", block))
    used = set(re.findall(r"var\((--[\w-]+)", css))
    missing = sorted(used - defined - SET_FROM_JS)
    assert missing == [], f"var() names no token block defines: {missing}"


def test_radius_sm_is_defined_in_both_theme_blocks():
    for block in _token_blocks(_css()):
        assert re.search(r"--radius-sm:\s*4px;", block) or "--radius:" not in block
    root, media, light = _token_blocks(_css())
    assert "--radius-sm: 4px" in root
    assert "--radius-sm: 4px" in media and "--radius-sm: 4px" in light


# ---------------------------------------------------------------
# Consistency: one radius scale, one link style, one copy button
# ---------------------------------------------------------------

def test_every_border_radius_is_a_token():
    allowed = {"var(--radius-sm)", "var(--radius)", "var(--radius-lg)", "0", "50%"}
    bad = []
    for value in re.findall(r"(?<![-\w])border(?:-[a-z]+)*-radius:\s*([^;}]+)", _css()):
        parts = set(value.replace("!important", "").split())
        if not parts <= allowed:
            bad.append(value.strip())
    assert bad == [], f"literal radii left: {sorted(set(bad))}"


def test_links_are_underlined_not_border_bottomed():
    offenders = []
    for sel, body in _rules(_css()):
        last = sel.split(",")[-1].strip()
        if re.search(r"(^|\s)a(:hover|:focus-visible)?$", last) and re.search(
                r"border-bottom(-color)?:\s*(?!none)", body):
            offenders.append(sel)
    assert offenders == [], offenders


def test_one_copy_button_style():
    assert ".rcb-result-record .copy-btn" not in _css()


def test_listed_live_surfaces_carry_no_hex_colours():
    selectors = [".copy-btn", ".copy-btn:hover", ".copy-btn.copied", ".rec-keyword",
                 ".rec-value", ".rec-safe", ".rec-warn", ".rec-danger", ".rec-muted",
                 ".audit-input-card", ".input-unified .input-wrapper", ".rb-value",
                 ".spfd-cost", ".rb-chain-active", ".advisory-warning", ".advisory-info",
                 ".ttl-long"]
    css = _css()
    for sel, body in _rules(css):
        bare = re.sub(r":where\([^)]*\)\)?\s*", "", sel).strip()
        if bare in selectors:
            assert not re.search(r"#[0-9a-fA-F]{3,8}\b", body), (sel, body)


def test_no_invalid_var_suffix_declarations():
    # var(--warn)44 is not a colour; the whole declaration was dropped.
    assert not re.search(r"var\(--[\w-]+\)[0-9a-fA-F]{2}\b", _css())


def test_dbis_page_matches_about_page_measure():
    css = _css()
    assert re.search(r"\.dbis-page \{ max-width: 68ch;", css)
    assert re.search(r"\.about-page \{ max-width: 68ch;", css)


def test_footer_linkedin_rules_are_gone():
    assert "footer-linkedin" not in _css()


# ---------------------------------------------------------------
# Icons: one SVG set, no glyphs
# ---------------------------------------------------------------

def test_icon_set_has_the_new_icons_and_no_glyph_icons_remain():
    js = _read("static", "app.js")
    for name in ("mail", "history", "book", "'arrow-right'", "'arrow-up'", "swap"):
        assert re.search(rf"^\s*{re.escape(name)}: iconSvg\(", js, re.M), name
    for glyph in ("&#128203;", "&#9993;", "&#8635;", "&#128218;", "&#10140;",
                  "&#8644;", "'\\u2191'", "Audit \\u2192"):
        assert glyph not in js, glyph


# ---------------------------------------------------------------
# Pages: skip link, main landmark, preloads, hidden decorative SVGs
# ---------------------------------------------------------------

@pytest.mark.parametrize("page", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_every_page_has_a_skip_link_and_a_main_landmark(page):
    html = open(page, encoding="utf-8").read()
    body = html.split("<body>", 1)[1]
    assert body.lstrip().startswith('<a href="#main-content" class="skip-to-content">'), (
        "the skip link must be the first thing in <body>")
    assert len(re.findall(r'<main\b[^>]*\bid="main-content"', html)) == 1
    assert html.count("<main") == 1


@pytest.mark.parametrize("page", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_every_page_preloads_the_two_latin_fonts(page):
    html = open(page, encoding="utf-8").read()
    head = html.split("</head>", 1)[0]
    for font in ("dm-sans-normal-latin.woff2", "jetbrains-mono-latin.woff2"):
        assert re.search(rf'<link rel="preload" href="/static/fonts/{font}" as="font" '
                         r'type="font/woff2" crossorigin>', head), font


@pytest.mark.parametrize("page", PAGES, ids=lambda p: os.path.relpath(p, STATIC))
def test_every_svg_on_the_pages_is_hidden_from_assistive_technology(page):
    html = open(page, encoding="utf-8").read()
    bare = [s for s in re.findall(r"<svg\b[^>]*>", html) if 'aria-hidden="true"' not in s]
    assert bare == [], bare


def test_footer_brand_line_has_no_hard_break():
    for page in PAGES:
        assert "open-source DNS<br>" not in open(page, encoding="utf-8").read(), page


# ---------------------------------------------------------------
# The two PNG icons decode
# ---------------------------------------------------------------

def _png_chunks(data):
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    pos = 8
    while pos < len(data):
        length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        crc = struct.unpack(">I", data[pos + 8 + length:pos + 12 + length])[0]
        yield ctype, body, crc
        pos += 12 + length


@pytest.mark.parametrize("name,size", [("apple-touch-icon.png", 180), ("favicon-32.png", 32)])
def test_png_icons_decode(name, size):
    data = open(os.path.join(STATIC, name), "rb").read()
    for ctype, body, crc in _png_chunks(data):
        assert zlib.crc32(ctype + body) & 0xFFFFFFFF == crc, f"{name}: bad CRC on {ctype!r}"
    width, height = struct.unpack(">II", data[16:24])
    assert (width, height) == (size, size)
    pil = pytest.importorskip("PIL.Image")
    img = pil.open(os.path.join(STATIC, name))
    img.load()
    assert img.size == (size, size)


# ---------------------------------------------------------------
# Backend: Priorities rows, the empty-roadmap summary, strings
# ---------------------------------------------------------------

def _dkim_p():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    return base64.b64encode(key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


_P = _dkim_p()


def _zone(dmarc="v=DMARC1; p=none; pct=50; rua=mailto:d@" + DOMAIN, spf="v=spf1 mx -all",
          ns=("ns1", "ns2"), extra=None, ad_flag=False):
    records = {
        DOMAIN: {"MX": [(10, f"mx1.{DOMAIN}"), (20, f"mx2.{DOMAIN}")],
                 "TXT": [spf], "A": ["203.0.113.10"],
                 "NS": [f"{n}.{DOMAIN}" for n in ns]},
        f"s1._domainkey.{DOMAIN}": {"TXT": ["v=DKIM1; k=rsa; p=" + _P]},
        f"mx1.{DOMAIN}": {"A": ["203.0.113.11"]},
        f"mx2.{DOMAIN}": {"A": ["203.0.113.12"]},
        f"_dmarc.{DOMAIN}": {"TXT": [dmarc]},
    }
    for i, n in enumerate(ns):
        records[f"{n}.{DOMAIN}"] = {"A": [("203.0.113.53", "198.51.100.53")[i % 2]]}
    records.update(extra or {})
    return FakeZone(records, ad_flag=ad_flag)


def _run(zone, **kw):
    import audit_engine
    with fake_dns(zone, **kw):
        return audit_engine.run_full_audit(DOMAIN, dkim_selector="s1", scope="complete")


def _clean_result():
    extra = {
        f"_mta-sts.{DOMAIN}": {"TXT": ["v=STSv1; id=20260913"]},
        f"_smtp._tls.{DOMAIN}": {"TXT": [f"v=TLSRPTv1; rua=mailto:tls@{DOMAIN}"]},
        f"_25._tcp.mx1.{DOMAIN}": {"TLSA": [(3, 1, 1, "ab" * 32)]},
        f"_25._tcp.mx2.{DOMAIN}": {"TLSA": [(3, 1, 1, "cd" * 32)]},
    }
    policy = (f"version: STSv1\nmode: enforce\nmx: mx1.{DOMAIN}\nmx: mx2.{DOMAIN}\n"
              "max_age: 604800\n")
    return _run(_zone(dmarc=f"v=DMARC1; p=reject; np=reject; rua=mailto:d@{DOMAIN}",
                      extra=extra, ad_flag=True), mta_sts_policy=policy)


def test_every_fail_or_warn_card_has_a_priorities_row():
    # SPF ~all is a warn card that no specific roadmap rule covers; one
    # nameserver is a red Nameservers card.
    result = _run(_zone(spf="v=spf1 mx ~all", ns=("ns1",)))
    rows = {i["protocol"] for i in result["security_roadmap"]["items"]}
    flagged = {c["name"] for c in result["checks"] if c["status"] in ("fail", "warn")}
    assert {"SPF", "Nameservers"} <= flagged
    assert flagged <= rows, f"cards with no Priorities row: {sorted(flagged - rows)}"


def test_nameservers_row_carries_the_cards_own_fix_text():
    from result_transformer import build_security_roadmap
    for status in ("fail", "warn"):
        card = {"name": "Nameservers", "status": status, "configured": True,
                "fix": "Add at least one <strong>secondary</strong> nameserver."}
        rm = build_security_roadmap([card])
        ns = [i for i in rm["items"] if i["protocol"] == "Nameservers"]
        assert len(ns) == 1, rm["items"]
        assert ns[0]["action"] == "Add at least one secondary nameserver."
        assert ns[0]["status"] == status
    rm = build_security_roadmap([{"name": "Nameservers", "status": "pass", "fix": None}])
    assert not [i for i in rm["items"] if i["protocol"] == "Nameservers"]


def test_a_recommendation_on_a_passing_card_gets_the_info_status():
    from result_transformer import build_security_roadmap
    dmarc = {"name": "DMARC", "status": "pass", "configured": True,
             "record": "v=DMARC1; p=reject; np=reject; pct=100",
             "tag_breakdown": {"health": {"status": "compatible",
                                          "reasons": ["removed tags: pct"]}}}
    rm = build_security_roadmap([dmarc])
    # Doc 64: the row says what to do, not which health reason produced it.
    row = next(i for i in rm["items"]
               if i["action"] == "Remove the tag RFC 9989 retired: pct")
    assert row["status"] == "info"
    assert all(i["status"] != "pass" for i in rm["items"])


def test_an_empty_roadmap_gets_its_own_biggest_risk_sentence():
    result = _clean_result()
    assert result["security_roadmap"]["items"] == []
    assert (result["executive_summary"]["biggest_risk"]
            == "Nothing to fix. Every check the audit could assess passed.")


def test_the_five_strings_doc_47_left_are_replaced():
    rt = _read("result_transformer.py")
    ae = _read("audit_engine.py")
    for gone in ("better inbox placement", "is delivered as if", "silently stripped"):
        assert gone not in rt, gone
    assert "Anyone can send email that" not in ae
    assert ("Google and Yahoo require a DMARC record from bulk senders; \"\n"
            "            \"an enforcing policy also lets receivers act on mail that fails.") in rt
    assert rt.count("receives no policy at all") == 5
    assert "falls back to plaintext and nothing tells you." in rt
    assert "Receivers have no policy for \"\n            \"mail that fails authentication" in ae
    import audit_engine
    assert audit_engine.BUSINESS_RISK["DMARC_NO_RUA"] == (
        "Without aggregate reports you cannot see who is sending as your domain "
        "or whether their mail passes.")


# ---------------------------------------------------------------
# Browser
# ---------------------------------------------------------------

def _serve(route):
    url = urlparse(route.request.url)
    if url.hostname != "dns-audit.test":
        return route.abort()
    path = url.path
    if path.startswith("/static/"):
        local = os.path.join(REPO_ROOT, path.lstrip("/"))
    elif path in ("", "/"):
        local = os.path.join(STATIC, "index.html")
    else:
        local = os.path.join(STATIC, path.strip("/") + ".html")
        if not os.path.isfile(local):
            local = os.path.join(STATIC, path.strip("/"), "index.html")
    if not os.path.isfile(local):
        return route.fulfill(status=404, body="")
    with open(local, "rb") as f:
        body = f.read()
    route.fulfill(status=200, body=body,
                  headers={"content-type": mimetypes.guess_type(local)[0] or "text/html"})


@pytest.fixture(scope="module")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # no browser build or missing system libraries
            pytest.skip(f"chromium is not available here: {exc}")
        yield b
        b.close()


@pytest.fixture(scope="module")
def fixture_result():
    # The Doc 38 fixture: DMARC p=none pct=50, two MX, nothing optional.
    return json.loads(json.dumps(_run(_zone()), default=str))


def _page(browser, theme, width, path="/"):
    ctx = browser.new_context(viewport={"width": width, "height": 900})
    ctx.add_init_script(f"try{{localStorage.setItem('theme','{theme}')}}catch(e){{}}")
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.route("**/*", _serve)
    page.goto("http://dns-audit.test" + path)
    return ctx, page, errors


def _render(page, data):
    page.evaluate("""d => {
        document.getElementById('domain-input').value = d.domain;
        document.querySelector('.audit-input-section').classList.add('compact');
        renderResults(d);
    }""", data)
    page.wait_for_selector("#results-list .result-card", state="visible")
    page.wait_for_timeout(800)


CONTRAST_JS = r"""([sel, pseudo]) => {
    const parse = c => {
        const m = c.match(/rgba?\(([^)]+)\)/);
        if (!m) return null;
        const p = m[1].split(/[\s,\/]+/).filter(Boolean).map(Number);
        return {r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1};
    };
    const over = (t, b) => {
        const a = t.a + b.a * (1 - t.a);
        const mix = k => (t[k] * t.a + b[k] * b.a * (1 - t.a)) / a;
        return {r: mix('r'), g: mix('g'), b: mix('b'), a};
    };
    const el = document.querySelector(sel);
    if (!el) return null;
    const layers = [];
    for (let e = el; e; e = e.parentElement) {
        const c = parse(getComputedStyle(e).backgroundColor);
        if (c && c.a > 0) layers.push(c);
        if (c && c.a >= 1) break;
    }
    let bg = {r: 255, g: 255, b: 255, a: 1};
    for (let i = layers.length - 1; i >= 0; i--) bg = over(layers[i], bg);
    let fg = parse(getComputedStyle(el, pseudo || null).color);
    if (fg.a < 1) fg = over(fg, bg);
    const lum = c => {
        const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
        return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const l1 = lum(fg), l2 = lum(bg);
    return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
}"""


def _rects_overlap(a, b, tol=0.5):
    return (a["left"] < b["right"] - tol and b["left"] < a["right"] - tol
            and a["top"] < b["bottom"] - tol and b["top"] < a["bottom"] - tol)


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_nothing_overlaps_the_run_audit_button_at_1280(browser, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        page.fill("#domain-input", "example.com")
        page.dispatch_event("#domain-input", "input")
        page.wait_for_selector("#domain-valid-indicator.valid")
        hits = page.evaluate("""() => {
            const btn = document.getElementById('audit-btn');
            const b = btn.getBoundingClientRect();
            const out = [];
            for (const el of document.querySelectorAll('.input-wrapper *')) {
                if (btn.contains(el) || el.contains(btn)) continue;
                const r = el.getBoundingClientRect();
                if (!r.width || !r.height) continue;
                if (r.left < b.right - 0.5 && b.left < r.right - 0.5 &&
                    r.top < b.bottom - 0.5 && b.top < r.bottom - 0.5)
                    out.push(el.id || el.className.baseVal || el.className);
            }
            return out;
        }""")
        assert hits == [], f"overlapping the Run Audit button: {hits}"
        assert errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_record_text_stays_left_of_the_copy_button_at_390(browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 390)
    try:
        _render(page, fixture_result)
        pairs = page.evaluate("""() => [...document.querySelectorAll('.record-block')]
            .filter(b => b.offsetParent && b.querySelector('.copy-btn'))
            .map(b => {
                const r = b.getBoundingClientRect();
                const pad = parseFloat(getComputedStyle(b).paddingRight);
                const c = b.querySelector('.copy-btn').getBoundingClientRect();
                return {textRight: r.right - pad, copyLeft: c.left,
                        blockBottom: r.bottom, copyBottom: c.bottom};
            })""")
        assert pairs, "the fixture rendered no record block with a copy button"
        for p in pairs:
            assert p["textRight"] <= p["copyLeft"], p
            assert p["copyBottom"] <= p["blockBottom"] + 0.5, f"copy button hangs out: {p}"
        assert errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("width", [1280, 390])
def test_results_render_without_layout_defects(browser, fixture_result, theme, width):
    ctx, page, errors = _page(browser, theme, width)
    try:
        _render(page, fixture_result)
        m = page.evaluate("""() => {
            const lh = el => parseFloat(getComputedStyle(el).lineHeight) ||
                             parseFloat(getComputedStyle(el).fontSize) * 1.3;
            const labels = [...document.querySelectorAll('.banner-actions .share-btn span')]
                .map(s => s.getBoundingClientRect().height / lh(s));
            const desc = document.querySelector('.footer-brand-desc');
            return {
                labelLines: labels,
                brandLines: desc.getBoundingClientRect().height / lh(desc),
                focusableInButtons: document.querySelectorAll(
                    '[role="button"] [tabindex], [role="button"] a[href], [role="button"] button, ' +
                    '[role="button"] input').length,
                h1: [...document.querySelectorAll('h1')].filter(h => h.offsetParent)
                    .map(h => h.textContent.trim()),
                h4: [...document.querySelectorAll('#check-dmarc h4')].map(h => h.textContent.trim()),
                cardsExpanded: document.querySelectorAll('.result-card.expanded').length,
                headersOpen: document.querySelectorAll(
                    '.result-header[aria-expanded="true"]').length,
                describedBy: [...document.querySelectorAll('.result-header[aria-describedby]')]
                    .every(h => document.getElementById(h.getAttribute('aria-describedby'))),
                tipsFocusable: document.querySelectorAll('.protocol-name-tip[tabindex]').length,
                expandedNoControls: document.querySelectorAll('[aria-expanded]:not([aria-controls])').length,
            };
        }""")
        assert all(n < 1.5 for n in m["labelLines"]), f"a banner label wraps: {m['labelLines']}"
        assert m["brandLines"] < 2.5, f"footer brand line runs to {m['brandLines']:.1f} lines"
        assert m["focusableInButtons"] == 0
        assert m["tipsFocusable"] == 0
        assert m["describedBy"]
        assert m["h1"] == [DOMAIN], m["h1"]
        assert {"Strict Record Validation", "DMARC Record Breakdown",
                "DMARC Policy Discovery (Tree Walk)", "DMARC Evaluation"} <= set(m["h4"]), m["h4"]
        # Doc 63: every card renders collapsed, whatever its status.
        assert m["cardsExpanded"] == 0 and m["headersOpen"] == 0
        assert m["expandedNoControls"] == 0
        assert errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_no_font_or_radius_falls_back_on_an_undefined_variable(browser, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        got = page.evaluate("""() => {
            const host = document.getElementById('main-content');
            const probe = (cls, tag) => {
                const el = document.createElement(tag || 'div');
                el.className = cls;
                el.textContent = 'x';
                host.appendChild(el);
                const cs = getComputedStyle(el);
                return {font: cs.fontFamily, radius: cs.borderTopLeftRadius};
            };
            return {ttl: probe('ttl-value', 'span'), diff: probe('cd-diff'),
                    clear: probe('recent-audits-clear', 'button'),
                    rerun: probe('cache-rerun-btn', 'button'),
                    rid: probe('request-id-value', 'code')};
        }""")
        assert got["ttl"]["font"].startswith('"JetBrains Mono"'), got["ttl"]
        assert got["diff"]["font"].startswith('"JetBrains Mono"'), got["diff"]
        for k in ("clear", "rerun", "rid"):
            assert got[k]["radius"] == "4px", (k, got[k])
    finally:
        ctx.close()


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_three_contrast_failures_now_pass(browser, fixture_result, theme):
    ctx, page, errors = _page(browser, theme, 1280)
    try:
        placeholder = page.evaluate(CONTRAST_JS, ["#domain-input", "::placeholder"])
        _render(page, fixture_result)
        # Put one of each tag on its warn surface inside a real card body, so
        # the ancestors composite the way they do on a live page.
        page.evaluate("""() => {
            const body = document.querySelector('#check-dmarc .result-body-inner');
            body.insertAdjacentHTML('beforeend',
                '<div class="record-breakdown"><div class="rb-verdict rb-verdict-monitoring">' +
                '<span class="tag tag-warn" id="doc48-tag-warn">Monitoring</span></div></div>' +
                '<div class="anomaly-card anomaly-warn">' +
                '<span class="tag tag-high" id="doc48-tag-high">High</span></div>');
        }""")
        warn = page.evaluate(CONTRAST_JS, ["#doc48-tag-warn", None])
        high = page.evaluate(CONTRAST_JS, ["#doc48-tag-high", None])
        # Doc 50 removed the terminal chip, and with it the .logo-flag probe.
        for name, ratio in (("placeholder", placeholder),
                            ("tag-warn on monitoring verdict", warn),
                            ("tag-high on warn anomaly", high)):
            assert ratio is not None and ratio >= 4.5, f"{theme}: {name} is {ratio:.2f}:1"
    finally:
        ctx.close()


@pytest.mark.parametrize("path", ["/", "/about", "/privacy", "/articles/",
                                  "/articles/dmarcbis", "/articles/dnssec",
                                  "/articles/dane", "/static/404.html"])
def test_every_page_renders_a_skip_link_and_one_main_landmark(browser, path):
    ctx, page, errors = _page(browser, "dark", 390, path)
    try:
        got = page.evaluate("""() => ({
            first: document.body.firstElementChild.matches('a.skip-to-content[href="#main-content"]'),
            mains: document.querySelectorAll('main#main-content').length,
            footerLinkPad: [...document.querySelectorAll('.footer-attribution .footer-link')]
                .map(a => getComputedStyle(a).paddingRight),
        })""")
        assert got["first"] and got["mains"] == 1, got
        assert set(got["footerLinkPad"]) == {"0px"}, got
    finally:
        ctx.close()


def _open_spec_toggle(page):
    """Doc 63 filed the toggle under Details: card, Details, first section."""
    page.click("#check-dmarc .result-header")
    page.click('#check-dmarc .card-details > [role="heading"] > .cd-header')
    page.click('#check-dmarc .cd-subsection > [role="heading"] > .cd-header')


def test_spec_toggle_works_on_a_second_audit(browser, fixture_result):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        _render(page, fixture_result)
        _open_spec_toggle(page)
        page.click(".st-seg-legacy")
        _render(page, fixture_result)
        _open_spec_toggle(page)
        page.click(".st-seg-legacy")
        assert page.get_attribute(".st-seg-legacy", "aria-checked") == "true"
        assert errors == []
    finally:
        ctx.close()


def test_r_before_any_audit_keeps_the_typed_domain(browser):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        page.fill("#domain-input", "example.com")
        page.focus(".scope-btn[data-scope='dmarc']")
        page.keyboard.press("r")
        page.wait_for_timeout(600)
        assert page.input_value("#domain-input") == "example.com"
    finally:
        ctx.close()


def test_csv_export_of_a_result_with_no_checks_does_not_throw(browser):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        page.evaluate("""() => { URL.createObjectURL = () => 'blob:x';
                                 HTMLAnchorElement.prototype.click = () => {}; }""")
        page.evaluate("() => _exportToCSV({domain: 'doc48.test', checks: [], security_roadmap: {items: []}})")
        assert errors == []
    finally:
        ctx.close()


def test_tree_walk_tells_a_failed_lookup_from_no_record(browser):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        html = page.evaluate("""() => renderTreeWalk({
            is_subdomain: true, policy_source: null, walk_incomplete: true,
            steps: [
                {domain: 'a.doc48.test', query: '_dmarc.a.doc48.test', found: false,
                 lookup_failed: true, label: 'Author Domain'},
                {domain: 'doc48.test', query: '_dmarc.doc48.test', found: false,
                 lookup_failed: false, label: 'Organizational Domain'},
            ]})""")
        assert "Lookup failed" in html and "status-icon unavailable" in html
        assert html.count("No DMARC record") == 1
        assert "did not complete" in html
    finally:
        ctx.close()


def test_view_priorities_button_only_with_rows(browser, fixture_result):
    ctx, page, errors = _page(browser, "dark", 1280)
    try:
        es = fixture_result["executive_summary"]
        with_rows = page.evaluate("([es, rm]) => renderExecutiveSummary(es, rm)",
                                  [es, {"items": [{"protocol": "DMARC"}]}])
        without = page.evaluate("([es, rm]) => renderExecutiveSummary(es, rm)",
                                [es, {"items": []}])
        # Doc 64 renamed the section and the button that scrolls to it.
        assert "What to do" in with_rows
        assert "What to do" not in without
    finally:
        ctx.close()
