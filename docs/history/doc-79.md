# Doc 79: Details content fits its panel at every width

Main at bce461c. Re-fetch before starting.

## Problem

Doc 75 review, measured with cards and every Details panel open.
No page scrolls sideways, but long unbroken values inside Details
are cut off at the panel edge by an ancestor with overflow hidden,
so the reader cannot see or select the end of them:

- ietf.org at 820: Record Builder rua tag
  "rua=mailto:dmarc_agg@vali.email,mailto:dmarc-report@ietf.org"
  ends at x=877, panel clips at x=762.
- paypal.com at 390: rua value ends at x=446, panel clips at 348.
- bbc.co.uk at 320: rua tag ends at x=330, panel clips at 282.
- github.com at 320: SPF Lookup Budget tree include names cut to
  "spf.protecti", "_netblocks.g", "mail.zendesk", "sendgrid.ne";
  record text cut at "v=spf1 ip4:192.30.252.".
- At 390 and 320, every .cd-header-count summary is ellipsized
  (style.css ~6027, white-space nowrap), e.g. "Record found at the
  domain itself" shown as a fragment.

Both themes measure the same.

## Fix

Find the clipping ancestor for each case rather than patching the
leaf. Then apply the site's rule for wide content:
- Values a reader copies (records, tag values, URIs, host names)
  wrap with overflow-wrap anywhere, or sit in their own
  overflow-x auto container, whichever the surrounding component
  already uses. Tag chips may wrap inside the chip.
- SPF tree nodes: the include name wraps or the tree scrolls
  inside its own container; the page body never scrolls sideways.
- .cd-header-count may wrap to a second line under the title at
  narrow widths instead of ellipsizing. Keep the header tap target
  at least 44 px.

Do not remove overflow hidden where it drives the card open and
close animation (.result-body); fix the inner element instead.

## Tests

Playwright at 1280, 820, 390 and 320, both themes, all cards and
Details panels open, for github.com, paypal.com, bbc.co.uk and
ietf.org fixtures or live:
- no element inside a card has a right edge past its clipping
  ancestor's right edge
- no .cd-header-count has scrollWidth greater than clientWidth
- document scrollWidth equals viewport width
CI-style venv run of the full suite.

## Housekeeping

- Save as docs/history/doc-79.md, add its index line.
- Cache-bust static assets.

## Rules

- No em dashes or double hyphens in any string.
- One commit, one PR.
- After deploy, report /api/health version and the four measured
  cases above, before and after, with a screenshot check at 320.
