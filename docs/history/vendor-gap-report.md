# Vendor identification: gap report (8 October 2026)

Neil's doc asked for a report only, against main at 215387c: where the app's
vendor identification differs from his sender discovery script
(Toolkit/templates: sender_discovery.py, vendors.json, selectors.txt), with
seven questions (signals, naming rules, confidence, required records, vendor
tables, cost, the panel). The report was delivered inline. This file keeps
its findings and the plan. Neil then said to move forward and choose the
open decisions.

## Findings, in short

1. Signals the script reads and the app does not: return path, tracking and
   autodiscover CNAMEs (a 30 label wave); TXT at _amazonses; every DMARC rua
   and ruf and every TLS-RPT rua (the app reads only the first rua); nested
   SPF includes and redirect=; every hop of a DKIM CNAME chain (the app reads
   only the final name); revoked and dangling keys as account only evidence;
   6 selector patterns. The app alone reads an apex TXT TTL and an A record
   at bounce, autodiscover and email, and both always fall under its 0.5
   cutoff, so they cost queries and show nothing.
2. Naming: the vendor panel follows CNAME first. The DKIM card and key table
   do not: they prefer a tag set during discovery from the SPF vendor map.
   Mocked cases: SPF with Mailgun plus a k1 CNAME into mcsv.net, the card
   said Mailgun, the panel and the script said Mailchimp. A selector1 TXT key
   with Microsoft 365 in SPF and MX, the card said Microsoft 365, the script
   said that is evidence against Microsoft 365.
3. Confidence: the app score is the strongest signal plus 0.05 per signal,
   capped at 0.99, so almost every vendor shows 99. Script tiers map as in
   use = MX; configured = SPF include, DKIM CNAME, return path or tracking
   CNAME; likely = DKIM by name or pattern; account only = verification TXT,
   report address, autodiscover, revoked or dangling key. The app ranks a
   report address above a key named by its selector.
4. Required records: nothing per vendor. The SPF suggestion table suggested
   includes for vendors that need none (Mailchimp, Postmark, SparkPost,
   Brevo), had two names the panel never produces (ProtonMail, Brevo
   (Sendinblue)), and gave Barracuda, Zoho and Fastmail includes their docs
   do not.
5. Tables: app 58 vendor names in 174 entries, plus five more vendor tables
   in other modules; script 87 vendors. Every app vendor is in the script.
   No pattern maps to two different vendors; the differences are presence
   only. One table can serve both.
6. Cost: the CNAME wave is 30 queries plus one TXT in one parallel wave on
   _probe_executor (never _shared_executor, where fingerprinting runs, or
   _dkim_executor); everything else is free from records the audit already
   holds.
7. Panel: sources name only SPF, MX, DKIM and TXT. A DMARC report address
   showed as a vendor at 90 percent with "Detected via DNS records", reading
   as a sender; DKIM by CNAME and by name both print "DKIM".

## Plan, one small doc each

1. SPF suggestion table follows the footprints.
2. DKIM card and key table use the panel's naming rule.
3. Panel honesty: label DMARC, TLS-RPT and DKIM CNAME; reporting services
   are not senders; drop the TTL and A probe signals.
4. Free signals: all report addresses, nested SPF includes, every CNAME hop,
   dangling and revoked keys, selector patterns.
5. One vendor table, vendors.json as the source.
6. The CNAME label wave, with a canary and a cap.
7. Confidence tiers in words instead of a percentage.
8. Per vendor required records, last.

## Decisions, chosen for Neil

1. The repo holds the one table; the script can read the repo copy. Matters
   from step 5.
2. Tiers in words replace the percentage; reporting services show as
   reporting services, not senders.
3. Missing record findings on dns-audit.com only where the record is
   checkable, and not before step 8.
4. The 30 query wave is acceptable in parallel with a cap and a canary.
5. Adopt the script's generic name rule.
