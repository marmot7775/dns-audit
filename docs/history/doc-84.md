# Doc 84: links between the articles

## Context

The articles do not link to each other. Add four internal links,
each on an existing sentence, no new sentences. Link text is the
words shown; do not change the wording around it.

## Edits

1. /articles/dmarcbis, in the numbered edit about removing the
   retired tags: link the words Stay at p=none until your
   aggregate reports show every legitimate sender aligning to
   /articles/p-reject.

2. /articles/spf-lookups, in the section headed permerror isn't
   a warning: link the words Receivers honoring p=quarantine or
   p=reject then send it to spam or refuse it to
   /articles/p-reject.

3. /articles/p-reject, first paragraph: link the words RFC 9989,
   at the first mention only, to /articles/dmarcbis.

4. /articles/p-reject, in the section headed The requirement:
   link the words a platform that was added to the SPF record
   when it was set up to /articles/spf-lookups.

Links use the same styling as existing in body links on the
articles. Relative paths, no external hosts.

## Verification

Confirm each of the four links resolves with a 200 on the deployed
site. If the suite has a link check for static pages, it must
pass; if it does not, add one that fetches every internal link on
the eight pages and asserts 200. Deploy, then report main SHA and
/api/health.
