# Doc 85: two copy fixes on live articles

Main at b68bdfa. Re-fetch before starting. Copy only.

1. static/articles/dane.html: the phrase "is is in production"
   appears five times (standfirst, meta description, og and
   twitter descriptions, JSON-LD description). Change each to
   "is in production". The index card already reads correctly.

2. static/articles/dnssec.html: replace the dbis-lede paragraph
   with this text, word for word:

   Most opinions about DNSSEC were formed before 2017 and never
   revisited. The common one was that it carried too much
   operational risk for the threat it closed: KSK rollovers broke
   domains, registrars wanted a ticket for every DS update, and
   RSA signatures pushed responses into TCP fallback. That was a
   fair reading at the time. It is out of date now. This article
   covers what changed, what DNSSEC protects against, where it
   still falls short, and what a good deployment looks like.

   Set that page's JSON-LD dateModified to the deploy date.

Run the suite, open a PR, merge on green, deploy, and report the
version from /api/health.
