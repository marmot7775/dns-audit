# Doc 78: No-mail domains, dispositions and small wording

Main at 5a587e7. Re-fetch before starting.

## Findings (Doc 75 review, confirmed live)

1. example.com (null MX, v=spf1 -all). DMARC Evaluation says
   "SPF is configured with strict alignment, providing a path to
   DMARC pass"; SPF row "Configured / strict / alignment
   possible" (spf_execution_engine.py ~351). v=spf1 -all
   authorizes no host, so SPF cannot pass. Say instead that SPF
   authorizes no servers, which is correct for a domain that
   sends no mail. The same panel ends with the RFC 9989 mailing
   list note (app.js ~3327); omit it on a no-mail domain.

2. example.com. DKIM card: N/A, not applicable. Authentication
   resilience: "DKIM Inconclusive ... DKIM may well be configured
   with selectors this audit did not test". audit_engine.py ~5790
   to 5835 sets dkim_status inconclusive without checking the
   no-mail flag. On a no-mail domain, resilience treats DKIM as
   not applicable, matching the card.

3. "no action requested" beside an enforcing policy (app.js ~3340
   maps disposition none). paypal.com, bbc.co.uk and box.com read
   "policy: reject / no action requested". The disposition is what
   happens to mail that passes; beside the policy it reads as the
   policy's effect. Label it so it cannot be misread, for example
   "passing mail is delivered normally", or show the disposition
   only for the failing case.

4. BIMI plan row prints "&lt;svg&gt;" literally, web and PDF
   (paypal.com, bbc.co.uk). checks_extra.py ~1208 stores escaped
   text; result_transformer.py ~1054 copies it into the row without
   _roadmap_fix_text (~794), then both surfaces escape again. Route
   it through _roadmap_fix_text like the other rows.

5. Lowercase RFC labels in link chips: "rfc7208" (app.js ~3255),
   "rfc9990 &sect;4" (~3404), "rfc9989" (~3336). Write them as the
   rest of the page does: RFC 7208, RFC 9990 section 4.

## Tests

- Null MX fixture with v=spf1 -all: no "path to DMARC pass", no
  mailing list note, resilience DKIM not inconclusive.
- p=reject fixture: no "no action requested" text.
- BIMI fixture: plan row text and PDF text contain <svg>, never
  &lt;svg&gt;.
- Rendered page: no link text matching ^rfc\d.
- CI-style venv run of the full suite.

## Housekeeping

- Save as docs/history/doc-78.md, add its index line.
- Repair doc-77.md: append the missing tail below and remove the
  cut-off note from its index line.
- Cache-bust static assets.

Missing tail of doc-77.md:
  - Save as docs/history/doc-77.md, add its line to
    docs/history/README.md.
  - Cache-bust static assets if app.js changes.
  ## Rules
  - No em dashes or double hyphens in any string.
  - One commit, one PR.
  - After deploy, report /api/health version, every proposed DMARC
    record on live bbc.co.uk and github.com (web and PDF), and the
    proton.me readiness label and np line.

## Rules

- No em dashes or double hyphens in any string.
- One commit, one PR.
- After deploy, report /api/health version and the five findings
  as they now read live (example.com, paypal.com), web and PDF.
