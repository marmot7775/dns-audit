Doc 96: three additions to the APRF article

Save this as docs/history/doc-NN.md with the next free number
in docs/history, then do the work on a branch and open a PR.

Goal

The article at /articles/aprf checks out against draft-01 but
leaves three gaps a reader hits in practice: it says to check who
signs your mail without saying how, it describes a report without
showing one, and it skips two loose ends in the draft that affect
what a reader publishes. Add the text below. Everything else in
the article stays as it is. Add no links; the test that pins the
article to zero links stays green.

Wrap literal names in code tags the way the rest of the article
does: d=, s=, DKIM-Signature, google, selector1, selector2,
_aprf._domainkey, sdi, sdi_used, N/F, N/A, inbox, unwanted,
positive, negative, neutral, version. Escape angle brackets in
placeholders like <your domain> as the existing paragraphs do.

1. In What a report tells you

After the paragraph ending "that some mail arrived." insert this
paragraph, then the code block, then the paragraph after it.

A report looks like this. It is the flat sample from the draft,
with the header trimmed to the fields that carry meaning.

[
  {
    "header": {
      "version": 4,
      "source": "Receiver MBP, Inc.",
      "dkim_domain": "example.com",
      "dkim_selector": "sel1",
      "report_start": 1709164800,
      "report_end": 1709251199,
      "sdi_used": "N/F"
    },
    "body": [
      {
        "classification": { "inbox": 10000, "unwanted": 100 },
        "engagement": { "positive": 200, "negative": 100, "neutral": 20 }
      }
    ]
  }
]

The header says who reported, which signing domain and selector
the report covers, and the day as Unix timestamps. The version is
the provider's own format number. It changes when the provider
adds or drops something it counts, so numbers on either side of a
change don't compare. sdi_used reads N/F when your record has no
sdi tag and N/A when it has one the provider ignored. In the body,
inbox and unwanted count messages received that day, and the three
engagement figures count actions taken that day on mail from any
day. Each figure is the top of its bucket. With sdi in use, the
body holds one block like this per segment.

Put the JSON in a pre element with the same class and tabindex as
the other code blocks in the article. Keep the two-space indent.

2. In Should you publish a record?

Append to the paragraph ending "check who signs your mail.":

The sure way is to read a message you sent. In Gmail, open it and
choose Show original; other mail clients call this view source or
view message details. Find the DKIM-Signature line. The d= value
is the signing domain and the s= value is the selector. If d= is
the platform's domain, the next paragraph is about you. If it's
your domain, the one after is.

After the paragraph ending "so the APRF record is yours to
publish." add this paragraph:

Google Workspace and Microsoft 365 both sign with your domain.
Google Workspace uses the selector google unless you chose another
when you turned DKIM on. Microsoft 365 uses selector1 and selector2
and switches between them when it rotates keys, so publish the bare
record at _aprf._domainkey.<your domain> rather than one per
selector, and it covers whichever selector is active. The bare
record is also the right choice for any platform that gives you
CNAME records at your domain. The APRF record sits at a different
name from the DKIM CNAME, so the two don't collide.

3. In Where it stands

Add this paragraph after the one ending "Record details and report
fields could change.":

Two smaller things are unsettled too. The draft describes the
outside destination check two ways: one section measures the
report address against the signing domain, another against the
From address. And now that the working group owns the document,
its next revision will carry a working group name in place of the
author's, so the draft-brotman name will stop updating and links
to it will go stale.

4. In Technical details

Replace the sentence "A wildcard in the selector position accepts
reports for every selector on that signing domain." with:

A wildcard in the selector position accepts reports for every
selector on that signing domain, and a wildcard in the signing
domain position accepts them from every signing domain.

After the sentence "Without the record, a provider that follows the
draft won't send." add:

The draft states this check against the signing domain in one
place and the From domain in another. The lookup name is built
from the signing domain, so that is the reading dns-audit.com
follows. If your report address is on any domain other than the
one that signs, publish the destination record.

Dates

Set dateModified in the JSON-LD to the day this ships. Show the
modified date on the page and the articles index card the way
dane.html does for an updated article.

Checks

Pipe the JSON sample through python -m json.tool; it parses. Grep
the article for an em dash, a double hyphen, and "yourdomain";
all return nothing. Run the test suite. Load /articles/aprf at
1280 and 390 px in both themes: the JSON block scrolls inside
itself, nothing overflows the viewport, and the new paragraphs
sit where this doc places them. Confirm the article still has no
links apart from the byline's About link.

Report

Reply with the PR number, the merge SHA once CI passes and it is
deployed, and the list of files changed.
