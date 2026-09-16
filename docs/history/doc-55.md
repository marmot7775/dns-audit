# Doc 55: About page copy and heading spacing

Two changes on the About page. Replace the body copy, and fix the stacked
top margins that leave a large empty band above each section heading.

## Change 1: About page body copy

Find the About page template (the page served at /about, the one whose main
element carries class "about-page") and replace everything inside
<main class="about-page" id="main-content"> with the markup below. Keep the
main element, its classes and its id. Keep the section classes exactly as
they are: the first section is "dbis-section", the second is
"dbis-section about-closing". Keep both link targets and their rel and
target attributes.

        <h1>About</h1>
        <p>The tools I wanted didn't exist.</p>
        <p>Most DNS tools show you what records you have and leave you to
        work out the rest: whether the records are correct, whether a tag
        combination is dangerous, whether the RFC you're reading is still
        the current one. I wanted something that did the analysis, showed
        its work, cited the RFC it checked against, and gave me the exact
        record to paste. So I built it.</p>
        <p>It runs twelve checks: DMARC, SPF, DKIM, MX, DNSSEC, MTA-STS,
        TLS-RPT, DANE, CAA, BIMI, Certificate Transparency, and nameserver
        configuration. Every check cites the standard it is judged against,
        and where the fix is a DNS record, you get the record.</p>
        <p>DMARC gets checked twice. Once against the current standard,
        published May 2026 in three parts: RFC 9989 for the protocol, RFC
        9990 for aggregate reporting, RFC 9991 for failure reporting. Once
        against RFC 7489, which most receivers still implement while tree
        walk support rolls out. You see both, and what changes between
        them.</p>
        <p>It's free. No accounts, no cookies, no tracking. The code is open
        source under the MIT License, so you can 
        href="https://github.com/marmot7775/dns-audit" target="_blank"
        rel="noopener">read it, run it locally, or fork it</a>.</p>
        <section class="dbis-section">
            <h2>Who built this</h2>
            <p>I'm Neil Anuskiewicz. I work on email deliverability and
            authentication from Eugene, Oregon, and have since the days when
            DKIM was new. At Proofpoint Professional Services I ran DMARC
            programs for more than 40 enterprise customers, taking them from
            p=none to enforcement without dropping legitimate mail. That is
            where most of the judgment in this tool comes from: what a real
            rollout breaks, and which failures are worth acting on. My
            clients now are mostly small companies, MSPs, and startups on
            Google Workspace or Microsoft 365, where the job is the same one
            at smaller scale.</p>
        </section>
        <section class="dbis-section about-closing">
            <h2>If your audit turned up something</h2>
            <p>Some findings are a five-minute DNS change. Some are not, and
            the hard part is knowing which before you touch anything.</p>
            <p>If you want a second opinion, 
            href="https://www.linkedin.com/in/neilanuskiewicz/"
            target="_blank" rel="noopener">message me on LinkedIn</a> with
            your domain. I'll read the audit and tell you plainly whether it
            needs a consultant or a careful hour of your own. If it needs
            one, you get the scope in writing first: what is wrong, what the
            change is, what could break. You approve it, then we make the
            change together. That holds for a single record and for a domain
            with a dozen sending services on its way to enforcement.</p>
        </section>

Collapse the indented paragraph text onto single source lines to match the
file's existing style. The wrapping above is for reading only.

Two sentences were dropped on purpose. "If you manage DNS for a domain
someone depends on, this tool was built for you" announced an audience
instead of showing one. The old closing sentence about longer work repeated
"scoped" a third time. Do not reinstate either.

## Change 2: heading spacing

In static/style.css, the h2 inside each About section gets margin-top 3rem
from the .about-page h2 rule, and that stacks on the section's own
margin-top, and on .about-closing's padding-top as well. The result is about
120px of empty band before "Who built this" and about 136px split by the
border line before "If your audit turned up something".

Add one rule in the About page block, after .about-closing:

.about-page section > h2:first-child { margin-top: 0; }

Scope it to .about-page. Leave the article pages alone. Do not change the
.about-page h2 rule itself, the .dbis-section margin, or the .about-closing
padding, because the article pages share them.

## Verify

Render /about at 1280, 1024, 820, 768 and 390 in both themes. The gap above
"Who built this" should be 4.5rem, and the closing section's border rule
should sit with roughly even space above and below it. No page errors.

Run the full suite. If a test asserts the old About copy or a paragraph
count on that page, update the test to the new text rather than reverting
the copy.
