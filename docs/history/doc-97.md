Results page: replace the verdict box and fix the domain input check

This replaces any earlier version of this doc. Pull main first and
read CLAUDE.md.

Context. The box at the top of the results page shows, for a
p=reject domain:

  Receivers are asked to refuse mail that pretends to be from this
  domain or its subdomains.
  Nothing urgent. The plan has smaller improvements.
  [See the plan] [Technical summary]

The sentence is accurate. The problem is clarity. It describes a
policy instead of answering the visitor's question, which is whether
their domain is protected and whether anything needs doing. The box
looks the same in every state, and both buttons point at sections
already visible directly below.

The headline comes from result_transformer.py around line 712, which
already branches on how each spoofing route is covered. Keep that
detection logic. Change what each branch says, and map its existing
branches onto the table in Part 1. Report every other consumer of
these strings, including the PDF cover, before changing them.

Part 1. Headline, chosen by DMARC state

  p=reject, sp absent or sp=reject or sp=quarantine:
    Your domain is protected against spoofing.
  p=quarantine, same sp condition:
    Mail that fakes your domain goes to spam.
  p=reject or p=quarantine with sp=none:
    Your domain is protected, but its subdomains are not.
  p=none:
    Your domain does not yet ask receivers to block mail that
    fakes it.
  No DMARC record:
    Your domain publishes no protection against spoofing.
  DMARC record present but invalid, including the lowercase
  v=dmarc1 case the engine records in syntax_errors:
    Your spoofing protection record has an error, so receivers
    ignore it.
  DMARC lookup unavailable or timed out:
    We couldn't check your spoofing protection. Run the audit again.
  DMARC out of scope for this run:
    No DMARC headline. Use the subline alone.

The headline must not state a fact from a check that was
unavailable or not run, the same invariant as doc 20. If an existing
branch has no row here, or a row has no branch, report it rather
than guessing.

Part 2. Subline, from the What to do list

  Required items present:   N fixes needed below.
  Only optional items:      N optional improvements below.
  Nothing listed:           Nothing to fix.

Get the singular right: 1 fix, 1 optional improvement. Use the
same counts the What to do box shows so the two cannot disagree.

Part 3. Buttons

Remove See the plan and Technical summary. Before deleting
Technical summary, check whether it shows anything that appears
nowhere else on the page. If it does, stop and report what it holds.

Part 4. Domain input check mark

The input showed dns-audit.comds with a green check while the
results were for dns-audit.com. The check validates format only.

  a. Remove the green check mark. It implies a validation the page
     does not do.
  b. Reproduce whether editing the input after a run leaves the
     input and the results showing different domains. Report what
     you find. The results heading already shows the audited domain.
  c. Audit example.comds. If the page renders a full set of failed
     checks, return one message instead, based on NXDOMAIN for the
     domain itself:
       That domain doesn't exist in DNS. Check the spelling.

Part 5. Design

Each state gets a visual treatment so the result reads at a glance:

  Protected: pass color, shield with check icon.
  Subdomains unprotected, p=none, quarantine: warning color.
    Shield half icon for subdomains, warning triangle for p=none,
    shield with check for quarantine.
  No record or invalid record: fail color, shield with x icon.
  Unavailable: neutral gray, refresh icon.

Layout: the existing card, with a 3px left bar in the state color
and square corners on that side. A 40px circular icon on the left,
state color on a tint of the same color. Headline at the size the
current headline uses, subline in the muted text color at body
size. Use the site's existing pass, warning, fail and neutral color
tokens. Do not add new colors. Icons are inline SVG with
aria-hidden, since the headline carries the meaning.

Text must meet 4.5:1 and the icon 3:1 against the card in both
themes. At 375px the icon stays left of the text and nothing
overflows.

Copy rules for every string above: no dashes as punctuation, no
exclamation marks, contractions fine. Use the strings exactly as
written.

Tests. One test per headline row and per subline case, plus one for
the NXDOMAIN message. Run the full suite and give before and after
counts. Check the page at 375px and 1280px in both themes with
dns-audit.com, a p=none domain and a domain with no DMARC record.

Bust the cache per CLAUDE.md, since style.css and app.js will
change. Commit, open the PR, merge when CI is green, deploy, and
confirm on the live site.

Report back in one fenced markdown block: merge SHA, /api/health
SHA, test counts, the consumer list, any branch or row with no
match, what Technical summary held, the Part 4b finding, and the
contrast ratios measured for each state in both themes.
