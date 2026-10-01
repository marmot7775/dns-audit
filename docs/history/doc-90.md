# Doc 90: About page, contact note, PDF contact line, home subtitle

1. static/about.html, replace the whole "Who built this" body with:

I'm Neil Anuskiewicz, and I've worked in email from Eugene, Oregon
since 2004. That started with twelve years at StreamSend, an email
service provider, the last seven as a solutions engineer working on
authentication and deliverability for its customers. Before that I was
the hostmaster at an ISP, and I wrote about DNS for Linux Journal in
2001.

At Proofpoint Professional Services I deployed email security and
email fraud defense for more than 40 enterprise customers and led
DMARC programs from p=none to p=reject without disrupting legitimate
mail. Most of the judgment in this tool comes from that work: what a
real rollout breaks, and which failures are worth acting on.

Between and since those jobs I've worked independently, with more than
180 contracts on Upwork, most of them deliverability work. My clients
are mostly small businesses, nonprofits, MSPs, and startups on Google
Workspace or Microsoft 365, and the job is usually the same one at a
smaller scale.

Link "Linux Journal in 2001" to
https://www.linuxjournal.com/article/4597 and "Upwork" to his Upwork
profile URL if one is already linked anywhere in the repo; otherwise
leave Upwork unlinked.

2. static/about.html, in "If your audit turned up something", change
   "message me on LinkedIn with your domain" to "email
   dns@dns-audit.com or message me on LinkedIn with your domain". Use
   the same markup the footer uses for the address so Cloudflare
   obfuscates it.

3. Results contact note (app.js _renderContactNote). Keep the current
   text for audits with a warning or failure. Add a second variant for
   audits where everything passes, shown only when the domain sends
   mail (skip it when is_defensive or a null MX applies):

Everything here checks out. If mail from this domain still lands in
spam, the cause is somewhere DNS can't show, such as sender reputation
or sending practices. That's the other half of what I do. Email
dns@dns-audit.com or message me on LinkedIn.

4. PDF (pdf_report.py, end of _about_page). Add one short paragraph:

Questions about this report? Neil Anuskiewicz built dns-audit.com and
does this work as a consultant. Reach him on LinkedIn at
linkedin.com/in/neilanuskiewicz or through dns-audit.com/about.

Make both links clickable in the PDF. Do not put an email address in
the PDF.

5. static/index.html subtitle. Replace "Most DNS tools show you your
   records. This one tells you what is wrong with them. Includes RFC
   9989 readiness, DNSSEC validation, and more." with "Most DNS tools
   show you your records. This one tells you what is wrong with them
   and gives you the record to paste." Keep the RFC 9989 link out of
   the subtitle; it is covered on About.

6. Update the meta description on about.html if it no longer matches.
   Voice rules: no dashes as punctuation, no marketing words. Tone
   test, identical footer test, and the address guard test must pass.

Done when: tests pass, deploy is live, /api/health shows the new SHA,
and you report renders of About at 390 and 1280, a passing audit and a
failing audit showing the right note, and the last page of a
github.com PDF.
