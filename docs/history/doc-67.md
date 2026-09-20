# Doc 67: Every check says what it is first

The reader who called the report overwhelming is an
experienced network engineer who does not work in email. She
knew what DNS was and not what MTA-STS was, and the report
never told her. Twelve cards name a protocol, a status, and a
finding. The only definition anywhere is a hover tooltip on
the card title (app.js:159 to 173), which does not exist on a
phone and does not exist in the PDF at all. This doc puts one
plain line at the top of every check, on the page and in the
PDF, and fixes the last duplicate detail line. Line numbers
are from main at ab03f4b.

## 1. One source for the text

The twelve lines below live in Python, not in app.js, so the
page and the PDF cannot drift. Put them in
result_transformer.py as a module-level dict keyed by check
name, and emit the matching string on every check as
"what_this_is". app.js reads that field and the
PROTOCOL_TOOLTIPS dict at 159 to 173 goes, along with the
tooltip markup at 1054 to 1063 and its aria-describedby
wiring; the text is visible now, so a hover version of it is
one more thing to keep in step.

Each line is two sentences: what the thing is, then what it
does for the reader. Use these words.

DMARC: Tells mail servers that receive your mail what to do
with a message that claims to be from your domain but fails
authentication. Without it, every receiver decides on its own,
and you get no report of who is sending as you.

SPF: A DNS record listing the servers allowed to send mail for
your domain. A receiver compares the server that delivered a
message against that list.

DKIM: A signature added to every message you send, checked
against a key you publish in DNS. It proves the message came
from your domain and was not altered on the way.

MX Records: The servers that accept mail addressed to your
domain. Mail to you is delivered to whatever these name, in
priority order.

Nameservers: The servers that answer every DNS question about
your domain, including the records on this page. If they
disagree with each other or stop answering, your mail and your
website stop resolving.

MTA-STS: A policy you publish telling sending servers to
require TLS when they deliver to you, and to give up rather
than fall back to plaintext. Without it, an attacker on the
network can strip the encryption and read the mail.

TLS-RPT: An address you publish so senders can report failed
TLS connections to your mail servers. It is how you find out
that delivery is being downgraded or blocked.

DANE: Publishes your mail server's certificate fingerprint in
DNSSEC-signed DNS, so a sending server can verify the
certificate without trusting a certificate authority. It
requires DNSSEC on your zone and it fails closed, so mail
stops if the record and the certificate drift apart.

DNSSEC: Signs your DNS records so a resolver can tell the
answer it got is the answer you published. It stops an
attacker from forging DNS answers for your domain, and it is
what DANE is built on.

CAA: A DNS record naming which certificate authorities may
issue certificates for your domain. It does not affect mail;
it limits who can get a certificate in your name.

BIMI: Shows your logo beside your mail in the clients that
support it. It is branding, not security, and it requires
DMARC at quarantine or reject first.

Certificate Transparency: Public logs that every certificate
authority writes to when it issues a certificate. Reading them
shows every certificate that exists for your domain, including
ones nobody at your company ordered.

## 2. Where it shows

On the page, inside an opened card, the line is the first
thing in the body, above the existing explanation paragraph
(renderCheckBody, app.js:1234 to 1240). Label the two: "What
this is" above the new line, "What we found" above the
explanation that is already there. Style the new line in the
muted body colour at the body font size, with the labels in
the small caps label style the plan rows use, so the card
reads as two short labelled parts and then the details.

In the PDF, the same line goes in section 3 Checks, under the
status line and above the detail rows, with the same "What
this is" label. The appendix keeps the long explanation
paragraph where Doc 65 put it.

A check with no entry in the dict shows no line and no label
rather than an empty one.

## 3. The last duplicate

The Certificate Transparency card prints the same CAA mismatch
twice, and after the Doc 66 reorder the two lines are
adjacent: result_transformer.py:7107 to 7111 writes "CAA
allows [digicert.com] but certs found from Acme R1", and the
engine's own issue at audit_engine.py:4263 to 4271, merged in
downstream, writes "CT logs show certificates issued by Acme
R1, but CAA only allows: digicert.com. These may be older
certs issued before CAA was configured." Keep the engine's,
which says more, and drop the transformer's loop. The fix text
at 7157 to 7166 stays as it is.

## Tests

- Every check the transformer emits carries a non-empty
  what_this_is, and the string matches the dict exactly.
- Browser: opening each of the twelve cards on the fixture
  shows "What this is" followed by its line, then "What we
  found"; no card title carries a tooltip attribute any more.
- PDF: the Checks section contains "What this is" once per
  check, and the appendix still carries the long explanations.
- A check name absent from the dict renders no label and no
  line, on the page and in the PDF.
- The CT details list contains exactly one CAA mismatch line
  for a fixture with a mismatch, and it is the engine's
  wording.
- The tone test scans the twelve new strings with the existing
  banned-string list.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
No calendar timelines on DMARC monitoring anywhere.
Run python3 -m pytest tests/ -q. All must pass.
app.js and style.css change, so cache-bust the asset URLs per
CLAUDE.md.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA. After
deploy, audit github.com through the live API and put the
twelve what_this_is strings in the PR.
Save this doc as docs/history/doc-67.md in the same commit and
add its line to docs/history/README.md.

## Done when

Every check on the page and in the PDF opens with a plain
two-sentence line saying what the protocol is and why it
matters, the text lives in one place, the hover tooltip is
gone, the CAA mismatch prints once, and the suite passes.
