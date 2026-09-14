# Doc 39: Footer line that says what I do

Copy only. Line numbers are from main at 55bf1c8;
re-locate by content if they have moved.

The footer on every page reads "Built by Neil
Anuskiewicz" followed by a LinkedIn icon linking to
https://www.linkedin.com/in/neilanuskiewicz/
(static/index.html:344, and the same
.footer-attribution block in about.html,
privacy.html, 404.html, and the four files under
static/articles/). It says who built the tool and
not what he does, and the icon is the only hint that
the link is a way to reach him.

Replace the contents of .footer-attribution in all
eight files with exactly:

Built by Neil Anuskiewicz. Need help with email
deliverability, email security, or DNS?
<a href="https://www.linkedin.com/in/neilanuskiewicz/"
target="_blank" rel="noopener">Contact me on
LinkedIn</a>.

Drop the SVG icon. Keep the existing font, size,
colour, and weight of the attribution line; no
button, no box, no new class. It stays on one line
at desktop width and may wrap on mobile.

Do not add an email address or a mailto link
anywhere. Do not change the results-contact-note in
index.html or _renderContactNote in app.js; the
results view already has its own closing line and
it stays as it is.

Add a test that reads every .footer-attribution
block across the eight static pages and asserts
they are byte-identical, so a later change to the
link or the wording cannot land on seven pages and
miss one.

No em dashes and no double hyphens in any
user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
No cache-bust needed unless a static asset other
than HTML changes.
Commit to a branch, push, merge to main, then
deploy per CLAUDE.md and confirm /api/health
reports the new SHA.
Save this doc as docs/prompts/doc-39.md in the
same commit.

Done when every page's footer carries the same one
line naming the three things I help with and one
LinkedIn link, the results view is unchanged, and
the identical-footer test passes.
