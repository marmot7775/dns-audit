# Doc 86: link audit findings to the articles

Main at 353affb. Re-fetch before starting.

Five findings get one sentence each, at the end of the finding's
existing explanation or detail text, linking to the article that
answers the question the finding raises. The link uses the same
anchor form the RFC links in result_transformer.py already use
(target _blank, rel noopener) with an internal path. No link on a
clean card, no reading list, no change to status, verdict, plan
rows or summary. Wording is given word for word; the link text is
the part in square brackets, with the brackets removed.

1. SPF card, result_transformer.py near line 4772. Both the over
   the limit branch (lookups > 10) and the near band branch get
   this sentence appended:
   How to get back under 10, and why flattening once by hand makes
   it worse, is in [the SPF lookup article].
   Link: /articles/spf-lookups

2. DMARC card, the DKIM required at p=reject note (the entry
   built with REJECT_DKIM_NOTE_TITLE near line 172). Append to its
   text:
   [What to check before you publish p=reject] covers this
   requirement and how to confirm it from aggregate reports.
   Link: /articles/p-reject

3. DMARC card, two places. The pct warning detail (the _pct_text
   variants near line 2515) and the inherited policy explanation
   when the method note cites the RFC 9989 tree walk (near line
   2313). Append to each:
   [What RFC 9989 changes for your DMARC record] explains this
   in full.
   Link: /articles/dmarcbis

4. DNSSEC card, transform_dnssec. Whenever the card's status is
   anything other than pass, append to the explanation:
   [DNSSEC in 2026] covers what changed, what it protects
   against, and what a good deployment looks like.
   Link: /articles/dnssec

5. DANE card, transform_dane. Whenever the card's status is
   anything other than pass, except the no MX case where there is
   no inbound mail to protect, append to the explanation:
   [DANE for email in 2026] covers who runs it and what to do
   about it.
   Link: /articles/dane

Tests: one test per finding that the link is present when the
finding fires and absent on the same domain when it does not; a
check that no card with status pass contains a link to
/articles/. Extend tests/test_internal_links_resolve.py so these
five paths are covered if it does not already fetch them. The
PDF already renders the anchor tags in explanations, so leave
pdf_report.py alone unless a test shows otherwise.

Save this doc as docs/history/doc-86.md with its index line in
docs/history/README.md. Run the suite, open a PR, merge on green,
deploy, and report the version from /api/health.
