# Doc 88: privacy page accuracy and logging

Goal: every sentence on static/privacy.html is true of the running
system. Read deploy/nginx.conf, server.py, and the live config on the
droplet (/etc/nginx and /etc/logrotate.d/nginx) before changing
anything, and report what you find there if it differs from the repo.

1. nginx writes visitor IPs. deploy/nginx.conf turns access_log off
   only for /static/, so location / and /api/audit/stream log with the
   default format, which starts with the client IP (real_ip comes from
   CF-Connecting-IP). The privacy page says the IP "is not written to
   the audit log or to any other file." That sentence is false today.
   Fix the system, not the sentence: add a log_format that omits
   $remote_addr and $http_user_agent (keep time, method, path, status,
   bytes, request time) and use it in both locations. Apply it on the
   droplet, reload nginx, and confirm a fresh access.log line has no
   IP. Old access logs on the droplet still hold IPs; report how many
   days are there and the logrotate retention.

2. nginx error_log lines include "client: <ip>" for errors. Say so on
   the page in one sentence, with the retention logrotate actually
   uses on the droplet.

3. Add a section "How long it is kept" covering, in this order: the
   audit log (RotatingFileHandler, 10 MB times 11 files, size based;
   measure the oldest line on the droplet and state the span in plain
   words, such as "about N months at current traffic"); nginx access
   and error logs (the droplet's logrotate setting); DNS snapshots (90
   days, already stated, move it here); recent audits in the browser
   (until you clear them). Do not invent a Sentry retention figure;
   leave Sentry out of this section.

4. Disclose the weekly copy. Add to "What running an audit records":
   "Once a week a copy of this log is downloaded to my own computer
   and summarized into a private usage report that only I see. It is
   not published or shared."

5. Add under Accounts: "If you email dns@dns-audit.com, your message
   and address are kept in my mailbox like any other email."

6. Update "Last updated" to the deploy date. Keep the page's voice:
   plain, first person where it already is, no dashes as punctuation,
   no marketing words. The tone test must still pass.

7. Cloudflare is injecting two scripts into every page (an inline
   JavaScript detections script and
   static.cloudflareinsights.com/beacon.min.js). The CSP blocks both,
   which puts two errors in the console. Neil is turning both off in
   the Cloudflare dashboard. After he does, load the home page in
   Playwright and confirm zero console errors and no request to
   cloudflareinsights.com. If either remains, report which and stop;
   do not loosen the CSP.

Done when: tests pass, deploy is live, /api/health shows the new SHA,
and you report the access.log sample line, the logrotate retention,
and the audit log span you measured.
