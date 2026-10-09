Doc 95: retitle the APRF article

Save this as docs/history/doc-NN.md with the next free number
in docs/history, then do the work on a branch and open a PR.

Goal

The APRF article at /articles/aprf is live with the title
APRF is now an IETF working group draft. That is a news line
about a process step and it goes stale when the draft advances.
Replace it with a title that carries the reader promise, and move
the news into the standfirst. Body text is unchanged.

New values

H1, articles index card title, og:title, twitter:title, and the
JSON-LD headline:
What APRF inbox placement reports tell you, and what they don't

Title tag, shorter so it fits the search result with the site
suffix:
What APRF reports tell you, and what they don't | dns-audit.com

Standfirst, replacing the current one (which now duplicates the
title):
Adopted as an IETF working group draft on October 8, 2026. One
provider sends reports today, and the figures are approximate.

Where to change it

Search the repo for the old title string and the old standfirst
string and replace every occurrence: the article template, the
articles index card, any home page or related article card, the
meta and JSON-LD blocks, and any test that asserts the old text.
Leave the route, slug, sitemap entry, and body untouched. Update
dateModified in the JSON-LD and any visible modified date to
today. Keep the apostrophe in don't as a plain ASCII apostrophe,
matching the rest of the site.

Checks

Grep for the old title and old standfirst after the change; both
return nothing. Confirm the title tag is under 65 characters
including the suffix. Run the test suite. Load /articles/aprf and
/articles and confirm the new title in the H1, the browser tab,
and the index card.

Report

Reply with the PR number, the merge SHA once CI passes and it is
deployed, and the list of files changed.
