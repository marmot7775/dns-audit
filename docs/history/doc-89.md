# Doc 89: article accuracy pass

Goal: fix every claim a primary source contradicts and every sentence
that leaves a reader with a false belief, across the five articles in
static/articles/. Each item gives the current sentence and the
replacement. Match the surrounding HTML. Keep the voice: plain,
direct, no dashes as punctuation, no marketing words. The tone test
must pass.

dnssec.html
1. Replace "At Cloudflare, deSEC, Route 53, NS1, and Google Cloud DNS,
   signing is a checkbox and the provider handles the keys and the
   rollovers." with "At Cloudflare, deSEC, Route 53, NS1, and Google
   Cloud DNS, signing is a checkbox. Some of them roll every key for
   you; Route 53 and Google Cloud DNS still leave the KSK rollover to
   you." (Google Cloud DNS docs: Cloud DNS does not support automatic
   rotation of KSKs.)
2. Replace "IANA's Root Zone Database shows whether a TLD is signed,
   but not whether it automates DS updates." with "DNSViz will show
   whether a TLD is signed. Whether its registry automates DS updates
   is in the registry's own documentation." The IANA pages have no
   DNSSEC field.
3. Replace the "low single digits" sentence about signed zones with
   "About 5% of .com and .net domains are signed; Verisign's DNSSEC
   Scoreboard publishes the counts." (Scoreboard 2026-09-29: 8,315,092
   .com and 695,908 .net signed.)
4. APNIC figures: change 38% to 39% and 47% to 48% (30 day average,
   Sept 2026: 38.94 and 47.91).
5. Make the RFC 8078 and 9615 sentences distinct: "RFC 8078 let a
   registry accept the first DS from CDS, but only through
   unauthenticated checks such as a waiting period. RFC 9615 made that
   first step authenticated."
6. Replace "they are the ones who made RFC 9615 work in production"
   with "deSEC, whose engineers wrote RFC 9615, runs it in
   production."
7. In the CDS scanning list, drop .nl unless you find a SIDN source
   saying it scans for CDS today.
8. Replace "Unless you run a registry, a TLD, or a national CERT."
   with "Unless you operate a TLD registry."
9. FAQPage JSON-LD: the algorithm answer says 13 only; the body says
   13 or 15. Make the FAQ say 13 or 15.

dane.html
10. Replace the Zivver figures with "In a September 2025 scan of the
    10,000 domains Zivver's customers email most, 14% of domains
    supported DANE, and those domains received about 28% of the mail
    by volume." The current 12.6% and 25% leave out the DANE plus
    MTA-STS group.
11. Replace "Chrome never shipped it." with "Chrome briefly supported
    a DNSSEC variant of it and then removed it, and Firefox never
    shipped it." (The linked Langley post says Chrome supported
    something like it for a while.)
12. The secure email gateway sentence claims enterprises get DANE at
    the gateway hop through Proofpoint or Mimecast. Their inbound
    hosts publish no TLSA records. Replace with "unless it sits behind
    a gateway whose inbound hosts publish TLSA records. Check the
    gateway's own MX hosts before assuming it does."
13. Rewrite the Microsoft 365 steps: "The admin signs the domain's own
    zone at its DNS host, runs Enable-DnssecForVerifiedDomain, points
    MX at the mx.microsoft host it returns, then runs
    Enable-SmtpDaneInbound. Microsoft publishes the TLSA records at
    its own hosts; the customer never publishes TLSA. Domains added to
    Microsoft 365 since July 2026 get an mx.microsoft MX from the
    start."
14. Add one sentence where Google Workspace comes up: the TLSA record
    lives at the MX host, which is why a Workspace customer cannot add
    one.
15. Replace "four to five percent of users could not get the answer
    back, because captive portals, ISPs, and middleboxes stripped the
    records" with "four to five percent of users could not retrieve a
    TXT record that Chrome knew existed, most likely because something
    on their network blocked unusual DNS record types."
16. Replace "Google's position is that the web PKI is more accountable
    than the DNS hierarchy for transport keys." with "MTA-STS relies
    on the web PKI, where Certificate Transparency logs give an audit
    trail."
17. "strips the STARTTLS offer from the greeting" becomes "strips
    STARTTLS from the server's EHLO response".
18. "rolled out through 2022" becomes "rolled out in the first half of
    2022".
19. This article says "before 2018" where dnssec.html says "before
    2017" for the same event. Make both say 2017.

dmarcbis.html
20. Replace the t tag sentence with "The new t tag has two values.
    With t=y, receivers apply one level below your policy, so reject
    is treated as quarantine and quarantine as none. With t=n, the
    default, they apply the policy as written." (RFC 9989 section
    4.7.)
21. Replace "Your existing record keeps working throughout." with "For
    most domains the record keeps working unchanged. If you publish
    records at more than one level, or send from a domain on the
    private part of the Public Suffix List, the old and new methods
    can disagree. Publishing a record at every From domain removes
    that risk." (RFC 9989 Appendix C.3.) Adjust the diagram caption
    "Same input, same result" to match.
22. Replace "The walk finds the organizational domain, not the
    policy." with "A receiver uses the From domain's own record when
    there is one. When there is not, the same walk supplies the policy
    from the organizational domain or, failing that, the public
    suffix."
23. Replace "Stay at p=none until your aggregate reports show every
    legitimate sender aligning" with "Stay at p=none until your
    aggregate reports show every legitimate sender passing with
    aligned DKIM, not SPF alone" (agrees with p-reject.html and RFC
    9989 section 7.4).
24. "On yours, it is five edits you can make in one sitting." becomes
    "On yours, it is five checks, three of them edits, and all fit in
    one sitting."
25. "The heavy lifting is on the receiver side." becomes "Most of the
    work falls on receivers."

p-reject.html
26. "RFC 7960 catalogs every variety." becomes "RFC 7960 describes the
    common ones."
27. Replace the "produces no bounce and no trace" sentence with
    "Reject refuses the message during delivery, so the receiver never
    sends a bounce of its own to a forged address. For forwarded mail,
    the forwarder's server usually returns the bounce, and the failure
    shows up in your aggregate reports as mail from the forwarder's IP
    address."
28. "It is losing mail every time someone forwards a message" becomes
    "It risks losing mail whenever a message is forwarded to a
    receiver that enforces the policy".
29. Replace the sentence saying 9989 recommends SPF and DKIM and at
    reject the recommendation becomes a requirement with "Section 4.5
    recommends SPF and DKIM for every domain, and Section 8 lists both
    as requirements for full participation. At reject the standard
    adds a separate rule that SPF alone is never enough."
30. In the table, "Domain that sends no mail" becomes "Domain that
    neither sends nor receives mail" (a null MX refuses inbound mail).
31. Alignment definition: "where aligned means the signing domain is
    the From domain or shares its organizational domain."
32. "Most domains skip quarantine entirely" becomes "In my experience
    most domains skip quarantine". Same hedge where the quarantine
    section repeats it.
33. The link on "a platform that was added to the SPF record when it
    was set up" points to the SPF lookups article, which is not about
    DKIM signing. Remove the link.
34. "the strongest word the standard has" becomes "the standard's
    firmest requirement".
35. Update the Google help link /a/answer/81126 to /mail/answer/81126.

spf-lookups.html
36. Replace the bulk sender sentence ("The exception is bulk...") with
    "Google, Yahoo and Microsoft require bulk mail to pass SPF as well
    as DKIM. That pass can come from the platform's own domain or from
    a subdomain, so the requirement does not by itself keep a bulk
    sender's include in your main record."
37. "mail from SendGrid on the sixth" becomes "most SendGrid mail
    passes on the fifth" (sendgrid.net lists its ip4 ranges before its
    nested include).
38. Replace "The subdomain's SPF record is usually the vendor's,
    reached through a CNAME, so you don't maintain it." with "Some
    vendors have you point the subdomain at their record with a CNAME,
    so they maintain it. Others, Mailgun among them, have you publish
    a TXT record there yourself, which spends its own 10."
39. Replace the CNAME "idle for the same reason" sentence with "If
    it's a subdomain of yours that the platform had you point at them
    with a CNAME, the receiver checks that subdomain's record, so the
    include in your main record is idle. Here the SPF pass still
    counts toward DMARC, because the subdomain aligns with your
    domain."
40. "It's more reliable than Return-Path, which forwarders rewrite."
    becomes "It's the better field to read because it sits beside the
    SPF result it produced, in the receiver's own header."
41. "and so will every other tool" becomes "and so does any checker
    that doesn't know the sending address".
42. Replace the "CDN edge or a shared web host... thousands of
    strangers" sentence with "On many domains that's a shared web
    host, where other customers on the same server can send mail that
    passes as yours, or a CDN edge that sends no mail at all."
43. Add after the void lookup sentence: "and so can an a term on a
    name with no IPv6 address when mail arrives over IPv6."

All five articles
44. Show a visible date line on every article: "Published <Month
    YYYY>, updated October 2026" from datePublished, or "Published
    September 2026" where they match. Set dateModified to the deploy
    date on every article you changed, and update the matching card
    dates in articles/index.html.

Done when: tests pass, deploy is live, /api/health shows the new SHA,
and you report any item you could not apply because the sentence
differs from what is quoted here.
