# dns-audit

## Stack
- **Backend:** Python, FastAPI (server.py), uvicorn
- **Frontend:** Vanilla HTML/CSS/JS (static/)
- **Server:** Ubuntu on DigitalOcean (DROPLET_HOST), Cloudflare DNS
- **Domain:** dns-audit.com

## Key files
- `server.py` -- FastAPI app, SSE streaming, caching, rate limiting
- `audit_engine.py` -- orchestrates all 12 security checks
- `result_transformer.py` -- transforms raw results into frontend card format
- `static/app.js` -- frontend logic, SSE client, result rendering
- `static/style.css` -- all styles, responsive breakpoints in one file
- `static/index.html` -- single-page app shell
- `comprehensive_selectors.py` -- DKIM selector list for auto-discovery
- `dns_tools.py` -- domain normalization, audit entry point

## Rules
- NEVER use em-dashes (—) or double-hyphens ( -- ) in user-facing text. Rewrite the sentence instead.
- Card statuses (Doc 38) are four states plus "unavailable". fail, red: an
  essential record (DMARC, SPF, DKIM when a selector is named, MX on a mail
  domain, nameservers) is missing, or any record is broken. A DMARC record is
  broken only when v=DMARC1 is not first, it has no usable p= and no valid
  rua=, more than one record is published, a tag is duplicated, or no parser
  can read it (Doc 44). warn, amber: published and working but weak (p=none
  with or without rua, pct below 100, sp weaker than p, DMARC without rua, a
  DMARC tag receivers ignore under RFC 9989 section 4.8 such as an unknown
  tag or a malformed optional value, a 1024-bit DKIM key, MTA-STS mode
  testing). SPF ~all and -all both pass: DMARC is the policy layer, so the
  softfail/hardfail choice is the operator's. The DMARC attack surface block goes red only when the card
  fails. pass, green: published and correct. absent, grey: an optional
  protocol (MTA-STS, TLS-RPT, DNSSEC, CAA, DANE, BIMI) is not published; its
  pill says "Not configured", it has its own counter, and it is never counted
  as a warning. unavailable, grey with its own icon and "Not checked": the
  lookup did not complete. The neutral state adds no colour: on the web it
  uses the existing --text-tertiary (text and icons) and --border (tag
  background) tokens, and in the PDF NEUTRAL_CLR (#5a6678, --text-tertiary
  light) and NEUTRAL_BG (#f1f3f6) in pdf_report.py.
- Fail color is --fail (dark #e5484d, light #c93a3f) for fills, borders and
  icons. Doc 35 moved it off #ef4444: the stock red-500 was chosen for
  clarity in isolation and fought the rest of the palette once the greens
  and ambers were calmed down; #e5484d reads just as clearly and sits
  inside the same family. Text in the fail colour uses --fail-text (dark
  #f0767a, light #b3282d) because the fill colour on the card surface is
  under 4.5:1. Same pattern for the other surfaces that carry white text:
  --primary-solid, --pass-solid, --fail-solid, --warn-contrast and
  --dmarcbis-contrast exist so white-on-blue, white-on-green, white-on-red,
  text-on-amber and text-on-teal all clear 4.5:1 in both themes.
  tests/test_palette_contrast.py computes every one of these pairs
  from style.css and fails the build if any drops below 4.5:1, and checks
  that the two light-theme token blocks carry identical values. Dark theme
  default, light mode via prefers-color-scheme.
  A header toggle (static/theme.js, loaded in <head> on every page) saves a
  choice under the localStorage key `theme` and sets data-theme on <html>,
  which overrides prefers-color-scheme. The light-mode rules in style.css
  exist twice for that reason: once inside the media query scoped to
  :not([data-theme="dark"]), once scoped to [data-theme="light"].
- All touch targets must be 44px minimum on mobile
- Text contrast must pass WCAG AA (4.5:1 ratio)
- No personal data in logs (GDPR-safe)
- When editing static/privacy.html body content, update the "Last updated" date in the same commit.

## Architecture
- API: /api/audit (JSON), /api/audit/stream (SSE), /api/audit/{domain}/pdf
- 6 audit scopes: complete, email_full, dmarc, transport, dns_infra, security_scan
- Server-side scope filtering skips unneeded checks
- Cache key format: "domain:selector:scope" (5 min TTL)
- Audit log: audit.log (JSON-lines, GDPR-safe). Fields: ts, domain, scope,
  duration_s, checks, ua, bot, source, status, vid, plus error when status is
  not "ok" and ref when a Referer was sent. Fields are added, never renamed or
  removed, so older entries carry fewer of them.
  - `ua` is coarse labels only, "<browser family> / <OS family>", never a raw
    user-agent string and never a version number. Browser families: Chrome,
    Firefox, Safari, Edge, other, bot/tool, unknown. OS families: Windows,
    macOS, Linux, iOS, Android, other, unknown.
  - `bot` is a boolean derived in `ua_classify.is_bot()` from the full user
    agent, and it has to be computed before `ua_summary()` reduces the string.
    The labels do not carry enough to tell a crawler from a person, so any
    reader that tries to re-derive bot status from `ua` gets nothing. Read the
    `bot` field.
  - `tools/rewrite_audit_log_ua.py` applies the same transformation to stored
    history (audit.log and audit.log.N). It backs up originals, leaves entries that
    already have a bot flag alone, and prints before and after line counts.

## Single worker by design
The service runs exactly one uvicorn process. `deploy/dns-auditor.service`
passes no `--workers` flag and nothing sets `WEB_CONCURRENCY`, and that has
to stay true.

Every piece of coordination state in `server.py` is a module level global,
private to one process:

- `_rate_limits`: per IP rate limit table
- `_active_audits`: concurrency budget
- `_inflight`: single flight audit registry
- `_cache`: audit result cache
- `_health_cache`: health probe memo

Start N workers and each process gets its own copy of all five. The
concurrency cap becomes N times `MAX_CONCURRENT_AUDITS` instead of
`MAX_CONCURRENT_AUDITS`. Each IP gets N times the intended requests per
window, because each worker keeps a separate rate limit table. Two workers run
the same audit at the same moment despite the single flight registry, because
neither can see the other's `_inflight` dict. The health cache stops
deduplicating its DNS lookup. Nothing errors, nothing logs at request time,
and no test catches it. The site quietly stops enforcing its own limits.

`_inflight` and `_health_cache` are recent additions, so this assumption is
getting more load bearing over time, not less.

Scaling out means moving the cache, the rate limiter, the concurrency budget
and the in flight map to shared storage (Redis or equivalent) first. Until
that is done, one worker is the only correct configuration.

`server.py` defends itself: `_warn_if_multiple_workers()` runs at import,
reads the worker count from `WEB_CONCURRENCY` or from a workers flag on its
own or its supervisor's command line, and logs an error naming everything
that breaks. A comment protects a reader; the warning protects the person who
did not read.

Related: uvicorn runs without `--proxy-headers` on purpose. That is what keeps
`request.client.host` equal to nginx's loopback address, which is the whole
basis of the `X-Real-IP` trust check in `_get_client_ip`. Turning the flag on
would let a client supply its own peer address and walk past the rate
limiter. Read the docstring on `_get_client_ip` before touching it.

## Deploy
DROPLET_HOST and DEPLOY_USER are placeholders. The real values live in
deploy.local.md at the repo root, a local file that .gitignore keeps out of
the repo; substitute them before running anything below.
deploy/dns-auditor.service is a template for the same reason.

git push && ssh DEPLOY_USER@DROPLET_HOST "cd dns-security-auditor && git pull && ~/.venv/bin/pip install -r requirements.txt && sudo systemctl restart dns-auditor"
The droplet directory keeps the old name on purpose: the repo became dns-audit in Doc 54, the checkout on the server did not move.

The pip install step matters: the server's venv is not kept in sync with
requirements.txt automatically, so a new or bumped dependency (e.g.
cryptography, added for DNSSEC/RSA key generation) installs fine in a
fresh CI venv but crash-loops the live service if this step is skipped.

Python versions: the droplet runs Python 3.12.3 (`python3 --version` on the
server, read during the Doc 51 deploy on 2026-09-14). CI runs the tests on
3.11 and the security scans on 3.12. pyproject.toml's floor is 3.10, the
lowest version every pinned dependency installs on. Read the droplet's
version again after an OS upgrade and update this paragraph.

Confirm the restart took: `curl -s https://dns-audit.com/api/health` reports
`version`, the short commit SHA of the running process. The cache-busting
`?v=` strings cannot answer this. They are rewritten only when a file under
`static/` changes, so a commit that touches only Python leaves every asset URL
on the previous build and a skipped restart is indistinguishable from a
successful one from outside.

## Origin firewall
The droplet accepts ports 80 and 443 only from Cloudflare's published
ranges, so nobody can reach the origin around Cloudflare's rate limiting,
WAF and email obfuscation. Port 22 is not part of this and its rules stay
as they are. The rules were added with these two commands; rerun them when
Cloudflare changes its ranges:

```bash
ssh DEPLOY_USER@DROPLET_HOST 'for r in $(curl -s https://www.cloudflare.com/ips-v4) $(curl -s https://www.cloudflare.com/ips-v6); do sudo ufw prepend allow proto tcp from "$r" to any port 80,443 comment cloudflare; done'
ssh DEPLOY_USER@DROPLET_HOST 'sudo ufw deny proto tcp from any to any port 80,443'
```

Check `sudo ufw status` lists the cloudflare rules before running the
second command: if the curl in the first one failed, the deny would take the
site down. `prepend` keeps every allow above the deny, so a range added on a
refresh still matches, and ufw skips rules that already exist. A range
Cloudflare drops has to be removed by hand (`sudo ufw status numbered`, then
`sudo ufw delete N`). Verify from outside afterwards: `curl -s -o /dev/null
-w '%{http_code}' https://dns-audit.com/api/health` prints 200, and the same
request with `--resolve dns-audit.com:443:DROPLET_HOST` times out.

## Cache-busting
After any change to `static/style.css`, `static/app.js`, `static/articles.js` or `static/theme.js`, run this command before committing, OR include it as the final step of your commit. It handles any alphanumeric version string and rewrites both CSS and JS references across every static HTML page:

```bash
NEW=$(git rev-parse --short HEAD) && for f in static/*.html static/articles/*.html; do
  sed -i -E "s|(style\.css\|app\.js\|articles\.js\|theme\.js)\?v=[a-zA-Z0-9]+|\1?v=$NEW|g" "$f"
done
```

The glob must include `static/articles/`. `static/*.html` does not match
nested paths, so an earlier version of this loop updated only the four
top-level pages and left the four article pages pinned to an older build.
`articles.js` is in the pattern for the same reason: it is a real asset that
needs busting and only `static/articles/index.html` references it.

The older pattern `grep -oP 'v=\K[a-f0-9]+'` is broken: it only matches hex characters, so version strings containing non-hex letters (e.g. `ds17`, `sec9`) produce a partial or empty match and sed silently no-ops. Do not use the old pattern.

## Testing
Any module a test imports that is not in requirements.txt goes in requirements-dev.txt, never in the workflow file.

python3 -m pytest tests/ -v
python3 -c "import ast; ast.parse(open('server.py').read()); print('OK')"
curl -s https://dns-audit.com/api/health | python3 -m json.tool
