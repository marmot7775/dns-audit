# Doc 55: About and Privacy, rewritten

Copy only. The About page reads like a launch post (one-line
paragraphs, "So I built it", "this tool was built for you")
and the Privacy page has a few sentences in the same register.
Replace the prose with the text below, word for word. Keep
every element, class, link, href, and section as it is; only
the text inside the p elements changes. No facts change. Line
numbers are from main at 05f3436.

## 1. About (static/about.html:58 to 73)

The main content becomes these paragraphs, in this order. The
first block is the six p elements before the first section;
replace them with four.

Heading stays: About

Paragraph 1: Most DNS tools show you your records and stop
there. Whether the records are right, whether a tag
combination is dangerous, whether the RFC you are reading is
still the current one: that part is left to you. I wanted a
tool that did the analysis, showed its work, cited the RFC it
checked against, and gave me the exact record to paste. I
could not find one, so I built it.

Paragraph 2: Enter a domain and it reads the public DNS
records behind your email and the policy files they point to,
then tells you what is missing or misconfigured and how to fix
it. DMARC is checked two ways: against RFC 9989, the standard
published in May 2026 alongside RFC 9990 for aggregate
reporting and RFC 9991 for failure reporting, and against the
RFC 7489 behavior most receivers still run while tree walk
support rolls out. You see both results and what changes
between them. SPF, DKIM, MX, DNSSEC, MTA-STS, TLS-RPT, DANE,
CAA, BIMI, Certificate Transparency, and nameserver
configuration are covered as well.

Paragraph 3: It's free. There are no accounts, no cookies, and
no tracking. The code is open source under the MIT License;
you can [read it, run it yourself, or fork it] (keep the
existing GitHub link on that phrase).

Section "Who built this", one paragraph: I'm Neil Anuskiewicz.
I work on email deliverability and authentication from Eugene,
Oregon, and have since DKIM was new. At Proofpoint
Professional Services I ran DMARC programs for more than 40
enterprise customers, taking them from p=none to enforcement
without losing legitimate mail. Most of the judgment in this
tool comes from that work: what a real rollout breaks, and
which failures are worth acting on. My clients now are mostly
small companies, MSPs, and startups on Google Workspace or
Microsoft 365, and the job is usually the same one at a
smaller scale.

Section "If your audit turned up something", two paragraphs:

Some findings are a five-minute DNS change. Others are not,
and the hard part is telling which is which before you touch
anything.

If you want a second opinion, [message me on LinkedIn] (keep
the link) with your domain. I'll read the audit and tell you
plainly whether it needs a consultant or a careful hour of
your own time. When it needs one, the work is scoped in
writing before anything starts. The scope says what is wrong
and what the change is, and it names anything that could
break. You approve it and we make the change together. Longer
work, such as taking a domain with a dozen sending services to
DMARC enforcement, is scoped the same way.

The meta, og, and twitter descriptions at lines 7 to 16 stay.

## 2. Privacy (static/privacy.html)

Three sentences change; everything else stays.

- Line 62: replace "The domain you type is the whole point of
  the tool, so it is recorded. Worth knowing before you audit
  a domain whose existence you would rather not put in
  someone's log file." with: "The domain you type is the whole
  point of the tool, so it is recorded. If a domain's
  existence is itself something you would rather keep private,
  audit it from a copy you run yourself."
- The Third parties section: "The web server in front of the
  application keeps its own connection logs, as web servers
  do." becomes "The web server in front of the application
  keeps its own connection logs."
- The Checking this yourself section: "None of this has to be
  taken on trust." becomes "You do not have to take any of
  this on trust."
- Line 106: set the Last updated date to the deploy date.

## 3. 404

No change.

## Tests

tests/static_pages.py and the header, footer, and alias tests
cover these pages; run them. In
tests/test_tone_and_repetition.py add the About and Privacy
pages to the tone test's banned-string scan (the list from Doc
47, plus "So I built it", "built for you", "Worth knowing",
"as web servers do") so the old register cannot come back.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
No cache-bust needed; only HTML changes.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/history/doc-55.md in the same commit.

## Done when

The About page reads as four short paragraphs and two sections
in the text above, the three Privacy sentences are replaced,
the date is current, every link and section still works, and
the suite passes.
