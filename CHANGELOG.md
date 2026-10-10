# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
dns-audit has no numbered releases: main deploys to dns-audit.com after each
merge. So entries are dated, and grouped by the review doc that drove them;
the docs themselves are in [docs/history](docs/history/README.md). Docs 16,
17 and 24 predate saving docs to the repo. Seeded from the git log since
1 September 2026, the start of the accuracy work.

## [Unreleased]

### Added
- ARCHITECTURE.md: the pipeline, the module map, and the rules the code keeps.
- docs/decisions: eight dated decision records.
- CONTRIBUTING.md.
- CI workflow `lint.yml`: `ruff check` as a gate, mypy in report-only mode.
- `tools/gen_requirements.py` and a test that the requirements files match
  pyproject.toml.

### Changed
- pyproject.toml is the one place the Python floor and dependencies are
  declared; requirements.txt and requirements-dev.txt are generated from it.
- ruff's rule set is named in pyproject.toml (E4, E7, E9, F) so a ruff upgrade
  cannot widen it.
- README leads with a real audit result and states the floor by reference.

### Removed
- Dead code found by vulture and ruff: `AdvancedFingerprinter._matches_suffix`,
  `config.API_BASE_URL`, four unused PDF colours, and unused locals in
  audit_engine, dmarc_tree_walk, mx_check, pdf_report and result_transformer.

### Type checking
- mypy 2.4.0 reports **423 errors in 15 files** (`mypy`, config in
  pyproject.toml). That is the number to drive to zero, after which the CI
  step stops being report only. Under `--strict` it is 1,328 in 19 files.

## 2026-10: changes outside a numbered doc

- 2026-10-09: APRF article: the working group draft is out ([#191](https://github.com/marmot7775/dns-audit/pull/191))
- 2026-10-09: Hosted SPF check reads only terms that authorize ([#190](https://github.com/marmot7775/dns-audit/pull/190))
- 2026-10-09: Klaviyo owns its kl/kl2 keys; no include advice for hosted or macro SPF ([#189](https://github.com/marmot7775/dns-audit/pull/189))
- 2026-10-09: Vendor plan step 8: missing records per sender; dead sticky bar removed; SPF suggestion fix ([#188](https://github.com/marmot7775/dns-audit/pull/188))
- 2026-10-09: Article lede at body size; APRF article structured for scanning ([#187](https://github.com/marmot7775/dns-audit/pull/187))
- 2026-10-09: PDF: split long record blocks across pages (github.com PDF was 500) ([#186](https://github.com/marmot7775/dns-audit/pull/186))
- 2026-10-09: Headline: fall back to the verdict for older results ([#183](https://github.com/marmot7775/dns-audit/pull/183))
- 2026-10-09: Remove the live validity mark on the domain input ([#179](https://github.com/marmot7775/dns-audit/pull/179))
- 2026-10-09: APRF article: you may see placement data now ([#178](https://github.com/marmot7775/dns-audit/pull/178))
- 2026-10-09: APRF article: accuracy fixes against draft-01, same-month byline ([#177](https://github.com/marmot7775/dns-audit/pull/177))
- 2026-10-09: APRF: pin discovery of the bare record beside live selectors ([#175](https://github.com/marmot7775/dns-audit/pull/175))
- 2026-10-09: APRF article gets its own link preview card ([#174](https://github.com/marmot7775/dns-audit/pull/174))
- 2026-10-09: Preview image URL carries a version (Cloudflare cached a 404) ([#173](https://github.com/marmot7775/dns-audit/pull/173))
- 2026-10-09: Link previews, structured data and crawler access agree ([#171](https://github.com/marmot7775/dns-audit/pull/171))
- 2026-10-09: APRF card: advice matches the article, links to it, field-test fixes ([#172](https://github.com/marmot7775/dns-audit/pull/172))
- 2026-10-08: Vendor panel reads return path, tracking and autodiscover CNAMEs ([#167](https://github.com/marmot7775/dns-audit/pull/167))
- 2026-10-08: APRF article descriptions drop the adoption news line ([#168](https://github.com/marmot7775/dns-audit/pull/168))
- 2026-10-08: Vendor tables catch up with the sender discovery vendors.json ([#163](https://github.com/marmot7775/dns-audit/pull/163))
- 2026-10-08: Vendor panel says the evidence in words: in use, configured, likely, account only ([#165](https://github.com/marmot7775/dns-audit/pull/165))
- 2026-10-08: CI: pin the runner to ubuntu-24.04 ([#164](https://github.com/marmot7775/dns-audit/pull/164))
- 2026-10-08: Plan card link is a 44px touch target on phones ([#162](https://github.com/marmot7775/dns-audit/pull/162))
- 2026-10-08: Vendor panel reads every report address, nested SPF and CNAME hops ([#159](https://github.com/marmot7775/dns-audit/pull/159))
- 2026-10-08: APRF note: a working group draft, not yet a standard ([#161](https://github.com/marmot7775/dns-audit/pull/161))
- 2026-10-08: Cache-bust assets to 5d0f3c2 (main fails the asset version test) ([#160](https://github.com/marmot7775/dns-audit/pull/160))
- 2026-10-08: New article: APRF is now an IETF working group draft ([#158](https://github.com/marmot7775/dns-audit/pull/158))
- 2026-10-08: Vendor panel names every source; reporting services are not senders ([#157](https://github.com/marmot7775/dns-audit/pull/157))
- 2026-10-08: One naming rule for DKIM keys in the card, table and panel ([#156](https://github.com/marmot7775/dns-audit/pull/156))
- 2026-10-08: SPF suggestion includes only vendors that need one ([#155](https://github.com/marmot7775/dns-audit/pull/155))
- 2026-10-08: APRF check, informational only ([#153](https://github.com/marmot7775/dns-audit/pull/153))
- 2026-10-08: Byline on every article, linked to About ([#152](https://github.com/marmot7775/dns-audit/pull/152))
- 2026-10-08: Postmaster Tools article: one verdict wording ([#151](https://github.com/marmot7775/dns-audit/pull/151))
- 2026-10-07: New article: Gmail Postmaster Tools without the reputation ratings ([#150](https://github.com/marmot7775/dns-audit/pull/150))
- 2026-10-07: Keep email addresses out of Cloudflare's email obfuscation ([#148](https://github.com/marmot7775/dns-audit/pull/148))
- 2026-10-07: DKIM and vendor batch: dangling CNAMEs, verification TXT, key settings ([#147](https://github.com/marmot7775/dns-audit/pull/147))
- 2026-10-07: Vendor panel: one shared table, and DKIM keys count as evidence ([#146](https://github.com/marmot7775/dns-audit/pull/146))
- 2026-10-07: Resilience SPF row: v=spf1 -all authorizes no server ([#145](https://github.com/marmot7775/dns-audit/pull/145))
- 2026-10-07: DKIM card names the email service behind each ESP key ([#144](https://github.com/marmot7775/dns-audit/pull/144))
- 2026-10-01: On a plan tie, DMARC leads SPF leads DKIM ([#142](https://github.com/marmot7775/dns-audit/pull/142))
- 2026-10-01: Pct=0 ranks with p=none and says none ([#141](https://github.com/marmot7775/dns-audit/pull/141))
- 2026-10-01: Regression hunt 2 fixes ([#140](https://github.com/marmot7775/dns-audit/pull/140))
- 2026-10-01: Say DKIM for your own domain in the SPF plan head ([#137](https://github.com/marmot7775/dns-audit/pull/137))
- 2026-10-01: Make the results page agree with itself on six real-domain shapes ([#130](https://github.com/marmot7775/dns-audit/pull/130))
- 2026-10-01: A BIMI logo host that does not resolve says so ([#129](https://github.com/marmot7775/dns-audit/pull/129))
- 2026-10-01: Fix MTA-STS unresolvable host, cross-provider SOA serials, CNAME null records, non-delegated NS, Outlook.com label ([#127](https://github.com/marmot7775/dns-audit/pull/127))
- 2026-10-01: Fix the DMARC plan for duplicate records, unauthorized rua and partial pct ([#128](https://github.com/marmot7775/dns-audit/pull/128))
- 2026-10-01: Keep SPF suggestions within 10 lookups; rank SPF PermError critical ([#126](https://github.com/marmot7775/dns-audit/pull/126))
- 2026-10-01: Say what uvicorn's proxy headers actually do, and pin them ([#124](https://github.com/marmot7775/dns-audit/pull/124))
- 2026-10-01: Privacy page: Cloudflare error reports from browsers ([#120](https://github.com/marmot7775/dns-audit/pull/120))

## 2026-10-09: Doc 99. Report copy part 1, address obfuscation, false statements, one name for What to do

Review doc: [docs/history/doc-99.md](docs/history/doc-99.md).

- Report copy part 1 ([#185](https://github.com/marmot7775/dns-audit/pull/185))

## 2026-10-09: Doc 98. Results page cleanup, contact note placement, centered buttons, no debug details

Review doc: [docs/history/doc-98.md](docs/history/doc-98.md).

- Results page cleanup ([#184](https://github.com/marmot7775/dns-audit/pull/184))

## 2026-10-09: Doc 97. Headline box at the top of the results, no validity mark on the input

Review doc: [docs/history/doc-97.md](docs/history/doc-97.md).

- Results headline says whether the domain is protected ([#181](https://github.com/marmot7775/dns-audit/pull/181))

## 2026-10-09: Doc 96. Three additions to the APRF article

Review doc: [docs/history/doc-96.md](docs/history/doc-96.md).

- Three additions to the APRF article ([#176](https://github.com/marmot7775/dns-audit/pull/176))

## 2026-10-08: Doc 95. Retitle the APRF article

Review doc: [docs/history/doc-95.md](docs/history/doc-95.md).

- Retitle the APRF article ([#166](https://github.com/marmot7775/dns-audit/pull/166))

## 2026-10-07: Doc 94. DKIM key records receivers cannot use

Review doc: [docs/history/doc-94.md](docs/history/doc-94.md).

- DKIM key records the card still passes when receivers cannot use them ([#149](https://github.com/marmot7775/dns-audit/pull/149))

## 2026-10-06: Doc 93. ESP selectors in the first DKIM wave

Review doc: [docs/history/doc-93.md](docs/history/doc-93.md).

- Restore ESP selector reach in DKIM discovery, in one parallel wave ([#143](https://github.com/marmot7775/dns-audit/pull/143))

## 2026-10-01: Doc 92. Results people can read

Review doc: [docs/history/doc-92.md](docs/history/doc-92.md).

- Results people can read ([#136](https://github.com/marmot7775/dns-audit/pull/136))

## 2026-10-01: Doc 91. Site copy accuracy

Review doc: [docs/history/doc-91.md](docs/history/doc-91.md).

- Follow-ups from the second review ([#131](https://github.com/marmot7775/dns-audit/pull/131))
- Site copy accuracy ([#125](https://github.com/marmot7775/dns-audit/pull/125))

## 2026-10-01: Doc 90. About page, contact note, PDF contact line, home subtitle

Review doc: [docs/history/doc-90.md](docs/history/doc-90.md).

- About page, contact note, PDF contact line, home subtitle ([#123](https://github.com/marmot7775/dns-audit/pull/123))

## 2026-10-01: Doc 89. Article accuracy pass

Review doc: [docs/history/doc-89.md](docs/history/doc-89.md).

- Smooth five seams left by Doc 89 ([#122](https://github.com/marmot7775/dns-audit/pull/122))
- Article accuracy pass ([#121](https://github.com/marmot7775/dns-audit/pull/121))

## 2026-10-01: Doc 88. Privacy page accuracy and logging

Review doc: [docs/history/doc-88.md](docs/history/doc-88.md).

- Privacy page accuracy and logging ([#119](https://github.com/marmot7775/dns-audit/pull/119))

## 2026-09: changes outside a numbered doc

- 2026-09-30: Upload test coverage to Codecov from CI ([#117](https://github.com/marmot7775/dns-audit/pull/117))
- 2026-09-30: Privacy page: error reports no longer carry the requested address ([b82ddcd](https://github.com/marmot7775/dns-audit/commit/b82ddcd))
- 2026-09-30: Keep the typed domain and framework locals out of Sentry ([8b239d9](https://github.com/marmot7775/dns-audit/commit/8b239d9))
- 2026-09-30: Report server errors to Sentry, without visitor data ([#118](https://github.com/marmot7775/dns-audit/pull/118))
- 2026-09-29: Link the JSON-LD entities by @id ([#116](https://github.com/marmot7775/dns-audit/pull/116))
- 2026-09-29: Keep the RFC toggle inside its bar at 320px ([#115](https://github.com/marmot7775/dns-audit/pull/115))
- 2026-09-29: Nginx: long cache only for /static/ requests that carry ?v= ([#114](https://github.com/marmot7775/dns-audit/pull/114))
- 2026-09-29: Fail CI when the asset ?v= is older than the last asset change ([#113](https://github.com/marmot7775/dns-audit/pull/113))
- 2026-09-29: DKIM note at p=reject: one row for the gap, no inherited firing ([#109](https://github.com/marmot7775/dns-audit/pull/109))
- 2026-09-29: DMARC card: note when p=reject and no DKIM key was found ([#108](https://github.com/marmot7775/dns-audit/pull/108))
- 2026-09-29: SPF article: Mailgun's US servers pass in the worked example ([#104](https://github.com/marmot7775/dns-audit/pull/104))
- 2026-09-23: SPF ~all passes, site copy review, live-audit bug fixes ([#92](https://github.com/marmot7775/dns-audit/pull/92))
- 2026-09-23: Explicit np row keeps the value np inherits from sp ([#90](https://github.com/marmot7775/dns-audit/pull/90))
- 2026-09-23: Fix results page controls that did not do what they named ([#89](https://github.com/marmot7775/dns-audit/pull/89))
- 2026-09-23: Fix plan rows and PDF sections that pointed at the wrong thing ([#88](https://github.com/marmot7775/dns-audit/pull/88))
- 2026-09-23: Fix verdicts that contradicted the record ([#87](https://github.com/marmot7775/dns-audit/pull/87))
- 2026-09-22: Tests: stub dns.query so the golden zone audit stays offline ([#83](https://github.com/marmot7775/dns-audit/pull/83))
- 2026-09-13: Add ruff and pytest-cov, configured but not forced ([#44](https://github.com/marmot7775/dns-audit/pull/44))
- 2026-09-11: Remove contact email address from the site ([b5233ec](https://github.com/marmot7775/dns-audit/commit/b5233ec))
- 2026-09-10: Stop breaking the repo's own dash rule in text visitors read ([3eac059](https://github.com/marmot7775/dns-audit/commit/3eac059))
- 2026-09-09: Give the site a contact path: results note, hero claim, footer email ([d7a50b4](https://github.com/marmot7775/dns-audit/commit/d7a50b4))
- 2026-09-09: Report a DMARC record that fails the version gate as malformed, not absent ([8d27692](https://github.com/marmot7775/dns-audit/commit/8d27692))
- 2026-09-08: Read each version tag the way its own spec defines it ([5e31c17](https://github.com/marmot7775/dns-audit/commit/5e31c17))
- 2026-09-09: Say what each audit scope checks, in text a phone can show ([8f18237](https://github.com/marmot7775/dns-audit/commit/8f18237))
- 2026-09-09: Keep a detail row's text beside its icon instead of under it ([029f252](https://github.com/marmot7775/dns-audit/commit/029f252))
- 2026-09-08: Correct the performance comment, fill five sub-44px gaps, and put DKIM through Copy All Records ([3aa7dc7](https://github.com/marmot7775/dns-audit/commit/3aa7dc7))
- 2026-09-08: Give record "caution" its own colour again instead of reusing warn ([ba33c08](https://github.com/marmot7775/dns-audit/commit/ba33c08))
- 2026-09-08: Build every result card up front, and fix the contrast the hidden ones hid ([0101e03](https://github.com/marmot7775/dns-audit/commit/0101e03))
- 2026-09-08: Clear WCAG AA contrast and 44px touch targets on every page in both themes ([8697493](https://github.com/marmot7775/dns-audit/commit/8697493))
- 2026-09-08: Add a light/dark theme toggle to every page header ([5a3d0b2](https://github.com/marmot7775/dns-audit/commit/5a3d0b2))
- 2026-09-08: Fix a low-priority item taking the biggest-risk slot ([dd2e067](https://github.com/marmot7775/dns-audit/commit/dd2e067))
- 2026-09-08: Dmarcbis article: tree walk finds the org domain, not the policy ([c69e9b9](https://github.com/marmot7775/dns-audit/commit/c69e9b9))
- 2026-09-08: Stop asserting what mail receivers do at p=none ([9cfa80d](https://github.com/marmot7775/dns-audit/commit/9cfa80d))
- 2026-09-08: Vendor list: drop fake vendors, label outbound vs inbound ([b50a70d](https://github.com/marmot7775/dns-audit/commit/b50a70d))
- 2026-09-08: Fix five small copy errors ([474f341](https://github.com/marmot7775/dns-audit/commit/474f341))
- 2026-09-08: DKIM key size wording: 2048 bits is a SHOULD, not a MUST ([9c6aee8](https://github.com/marmot7775/dns-audit/commit/9c6aee8))
- 2026-09-08: DMARCbis readiness: absent np and sp are not compliance gaps ([a03e0d8](https://github.com/marmot7775/dns-audit/commit/a03e0d8))
- 2026-09-08: Fix Certificate Transparency query and the 0-certs pass pill ([0ede888](https://github.com/marmot7775/dns-audit/commit/0ede888))
- 2026-09-08: Pass cards must carry no fix: CAA, Nameservers, MTA-STS ([bc4565a](https://github.com/marmot7775/dns-audit/commit/bc4565a))
- 2026-09-08: Use requests in live_check.py to clear bandit B310 ([0f1e7eb](https://github.com/marmot7775/dns-audit/commit/0f1e7eb))
- 2026-09-08: Name the unprotected spoofing vector instead of counting the protected ones ([5d315fd](https://github.com/marmot7775/dns-audit/commit/5d315fd))
- 2026-09-08: Grade an enforcing policy with no rua amber, not green ([fdf1e8c](https://github.com/marmot7775/dns-audit/commit/fdf1e8c))
- 2026-09-08: Remove the Blocklist check ([aacccd5](https://github.com/marmot7775/dns-audit/commit/aacccd5))
- 2026-09-08: Grade absent BIMI as information rather than three separate nags ([0e805a2](https://github.com/marmot7775/dns-audit/commit/0e805a2))
- 2026-09-08: Make the Proton selectors reachable, not merely present ([ebfef3a](https://github.com/marmot7775/dns-audit/commit/ebfef3a))
- 2026-09-08: Stop the DMARC card asserting a DKIM absence the DKIM card refuses to ([076d7f3](https://github.com/marmot7775/dns-audit/commit/076d7f3))
- 2026-09-08: Stop failing an enforcing DMARC record for an optional tag ([b9d62ab](https://github.com/marmot7775/dns-audit/commit/b9d62ab))
- 2026-09-08: Stop warning about a single MX the provider is fanning out behind ([ec36330](https://github.com/marmot7775/dns-audit/commit/ec36330))
- 2026-09-08: Stop telling hosted domains to publish TLSA they cannot publish ([989b17e](https://github.com/marmot7775/dns-audit/commit/989b17e))
- 2026-09-08: Add a live-site check script ([94a801d](https://github.com/marmot7775/dns-audit/commit/94a801d))
- 2026-09-08: Stop the DMARC tree walk stating a policy across a level it could not read ([e63ff8a](https://github.com/marmot7775/dns-audit/commit/e63ff8a))
- 2026-09-08: Stop the void-lookup message describing the wrong mechanism ([1df9bac](https://github.com/marmot7775/dns-audit/commit/1df9bac))
- 2026-09-08: Drop the SPF merge step added with H3 ([6fa8183](https://github.com/marmot7775/dns-audit/commit/6fa8183))
- 2026-09-07: Fix three defects in the DKIM three-outcome change ([452b9fb](https://github.com/marmot7775/dns-audit/commit/452b9fb))
- 2026-09-07: Stop the DKIM check claiming an absence it cannot establish ([e733705](https://github.com/marmot7775/dns-audit/commit/e733705))
- 2026-09-07: Fix seven smaller defects in the report, the pool and the request path ([aa049cc](https://github.com/marmot7775/dns-audit/commit/aa049cc))
- 2026-09-07: Stop eight checks misattributing, misreading or overstating ([0113eed](https://github.com/marmot7775/dns-audit/commit/0113eed))
- 2026-09-07: Stop five checks stating facts the audit did not establish ([50283c2](https://github.com/marmot7775/dns-audit/commit/50283c2))
- 2026-09-07: Fix stale references in README and .gitignore ([8253d85](https://github.com/marmot7775/dns-audit/commit/8253d85))
- 2026-09-07: Settle the sample audit target on sample.dns-audit.com ([1c3e47b](https://github.com/marmot7775/dns-audit/commit/1c3e47b))
- 2026-09-07: Record the homepage positioning addendum to the redesign spec ([56ce1d1](https://github.com/marmot7775/dns-audit/commit/56ce1d1))
- 2026-09-05: Fix contrast on the inconclusive resilience badge ([7383150](https://github.com/marmot7775/dns-audit/commit/7383150))
- 2026-09-05: Bound the DNS cache before it outlives the answers ([1ae7fd7](https://github.com/marmot7775/dns-audit/commit/1ae7fd7))
- 2026-09-05: Teach the summary layer to hear "I could not check this" ([c799839](https://github.com/marmot7775/dns-audit/commit/c799839))
- 2026-09-04: Fix article headers that CSP was silently discarding ([b858bc7](https://github.com/marmot7775/dns-audit/commit/b858bc7))
- 2026-09-04: Repo cleanup: drop the stale markdown copies and the unused fonts ([dc00ed4](https://github.com/marmot7775/dns-audit/commit/dc00ed4))
- 2026-09-04: Reconcile the two protocol counts in the PDF ([fac68a9](https://github.com/marmot7775/dns-audit/commit/fac68a9))
- 2026-09-04: Make the PDF describe the report it actually is ([4057ae8](https://github.com/marmot7775/dns-audit/commit/4057ae8))
- 2026-09-04: README: stop telling self-hosters to bind 0.0.0.0 ([d4fa0f5](https://github.com/marmot7775/dns-audit/commit/d4fa0f5))
- 2026-09-04: Document and enforce the single-worker assumption ([6713f25](https://github.com/marmot7775/dns-audit/commit/6713f25))
- 2026-09-04: Stop reporting broken DKIM keys as healthy ([bfe2c48](https://github.com/marmot7775/dns-audit/commit/bfe2c48))
- 2026-09-03: Make the front end work under the Content Security Policy it ships with ([ae590e0](https://github.com/marmot7775/dns-audit/commit/ae590e0))
- 2026-09-02: Stop reporting a failed lookup as a finding about the domain ([c34d98d](https://github.com/marmot7775/dns-audit/commit/c34d98d))
- 2026-09-02: Fix six reporting-layer verdicts that told clients the wrong thing ([7a9bb31](https://github.com/marmot7775/dns-audit/commit/7a9bb31))
- 2026-09-02: Fix six SPF verdicts that were wrong on valid records ([7912a39](https://github.com/marmot7775/dns-audit/commit/7912a39))

## 2026-09-29: Doc 87. Root type size inherits the reader's setting

Review doc: [docs/history/doc-87.md](docs/history/doc-87.md).

- Root type size inherits the reader's setting ([#112](https://github.com/marmot7775/dns-audit/pull/112))

## 2026-09-29: Doc 86. Link audit findings to the articles

Review doc: [docs/history/doc-86.md](docs/history/doc-86.md).

- Link audit findings to the articles ([#111](https://github.com/marmot7775/dns-audit/pull/111))

## 2026-09-29: Doc 85. Two copy fixes on live articles

Review doc: [docs/history/doc-85.md](docs/history/doc-85.md).

- Two copy fixes on live articles ([#110](https://github.com/marmot7775/dns-audit/pull/110))

## 2026-09-29: Doc 84. Links between the articles

Review doc: [docs/history/doc-84.md](docs/history/doc-84.md).

- Links between the articles ([#107](https://github.com/marmot7775/dns-audit/pull/107))

## 2026-09-29: Doc 82. SPF lookups article, three edits

Review doc: [docs/history/doc-82.md](docs/history/doc-82.md).

- SPF lookups article, three edits ([#106](https://github.com/marmot7775/dns-audit/pull/106))

## 2026-09-29: Doc 81. New article, what to check before you publish p=reject

Review doc: [docs/history/doc-81.md](docs/history/doc-81.md).

- New article, what to check before you publish p=reject ([#105](https://github.com/marmot7775/dns-audit/pull/105))

## 2026-09-29: Doc 80. New article, SPF lookup limit

Review doc: [docs/history/doc-80.md](docs/history/doc-80.md).

- New article, SPF lookup limit ([#103](https://github.com/marmot7775/dns-audit/pull/103))

## 2026-09-28: Doc 79. Details content fits its panel at every width

Review doc: [docs/history/doc-79.md](docs/history/doc-79.md).

- Details content fits its panel at every width ([#102](https://github.com/marmot7775/dns-audit/pull/102))

## 2026-09-28: Doc 78. No-mail domains, dispositions and small wording

Review doc: [docs/history/doc-78.md](docs/history/doc-78.md).

- No-mail domains, dispositions and small wording ([#101](https://github.com/marmot7775/dns-audit/pull/101))

## 2026-09-28: Doc 77. Plan records drop retired tags, and readiness agrees with the plan

Review doc: [docs/history/doc-77.md](docs/history/doc-77.md).

- Plan records drop retired tags, and readiness agrees with the plan ([#100](https://github.com/marmot7775/dns-audit/pull/100))

## 2026-09-28: Doc 76. Inherited subdomains are judged by the policy that applies to them

Review doc: [docs/history/doc-76.md](docs/history/doc-76.md).

- Inherited subdomains are judged by the policy that applies to them ([#99](https://github.com/marmot7775/dns-audit/pull/99))

## 2026-09-28: Doc 74. Internal validation codes stay out of the page

Review doc: [docs/history/doc-74.md](docs/history/doc-74.md).

- Internal validation codes stay out of the page ([#98](https://github.com/marmot7775/dns-audit/pull/98))

## 2026-09-28: Doc 73. Collapsed cards take their content out of reach

Review doc: [docs/history/doc-73.md](docs/history/doc-73.md).

- Collapsed cards take their content out of reach ([#97](https://github.com/marmot7775/dns-audit/pull/97))

## 2026-09-28: Doc 72. Audit speed, measure then fix the dominant cost

Review doc: [docs/history/doc-72.md](docs/history/doc-72.md).

- Stop the DKIM sweep when a zone drops queries ([#96](https://github.com/marmot7775/dns-audit/pull/96))

## 2026-09-28: Doc 71. SPF lookup count, one rule everywhere

Review doc: [docs/history/doc-71.md](docs/history/doc-71.md).

- Add Doc 71 to the history index ([#95](https://github.com/marmot7775/dns-audit/pull/95))
- Judge the SPF lookup count by one rule everywhere (Doc 71) ([#94](https://github.com/marmot7775/dns-audit/pull/94))

## 2026-09-23: Doc 70. The DMARC output overstates the RFC 9989 change

Review doc: [docs/history/doc-70.md](docs/history/doc-70.md).

- Drop the readiness count beside the label ([#86](https://github.com/marmot7775/dns-audit/pull/86))
- The DMARC output overstates the RFC 9989 change ([#85](https://github.com/marmot7775/dns-audit/pull/85))

## 2026-09-22: Doc 69. The PDF endpoint reports on domains that do not exist

Review doc: [docs/history/doc-69.md](docs/history/doc-69.md).

- The PDF endpoint reported on domains that do not exist ([#81](https://github.com/marmot7775/dns-audit/pull/81))

## 2026-09-20: Doc 68. Three defects on the edges of the report

Review doc: [docs/history/doc-68.md](docs/history/doc-68.md).

- Three defects on the edges of the report ([#79](https://github.com/marmot7775/dns-audit/pull/79))

## 2026-09-20: Doc 67. Every check says what it is first

Review doc: [docs/history/doc-67.md](docs/history/doc-67.md).

- Every check says what it is first ([#78](https://github.com/marmot7775/dns-audit/pull/78))

## 2026-09-20: Doc 66. The report still contradicts itself in five places

Review doc: [docs/history/doc-66.md](docs/history/doc-66.md).

- Five places the report contradicted itself ([#77](https://github.com/marmot7775/dns-audit/pull/77))

## 2026-09-20: Doc 65. The PDF gets the same shape as the page

Review doc: [docs/history/doc-65.md](docs/history/doc-65.md).

- The PDF gets the same shape as the page ([#76](https://github.com/marmot7775/dns-audit/pull/76))

## 2026-09-20: Doc 64. Priorities becomes a plan the reader can follow

Review doc: [docs/history/doc-64.md](docs/history/doc-64.md).

- Priorities becomes a plan the reader can follow ([#75](https://github.com/marmot7775/dns-audit/pull/75))

## 2026-09-20: Doc 63. The results page shows everything at once

Review doc: [docs/history/doc-63.md](docs/history/doc-63.md).

- The results page shows everything at once ([#74](https://github.com/marmot7775/dns-audit/pull/74))

## 2026-09-19: Doc 62. Explicit SPF qualifiers get a valid record failed

Review doc: [docs/history/doc-62.md](docs/history/doc-62.md).

- Explicit SPF qualifiers get a valid record failed ([#73](https://github.com/marmot7775/dns-audit/pull/73))

## 2026-09-17: Doc 61. The Certificate Transparency check sets the audit's wall time

Review doc: [docs/history/doc-61.md](docs/history/doc-61.md).

- The Certificate Transparency check sets the audit's wall time ([#72](https://github.com/marmot7775/dns-audit/pull/72))

## 2026-09-17: Doc 60. The DANE article, rewritten

Review doc: [docs/history/doc-60.md](docs/history/doc-60.md).

- The DANE article, rewritten ([#71](https://github.com/marmot7775/dns-audit/pull/71))

## 2026-09-17: Doc 59. The DNSSEC article, rewritten

Review doc: [docs/history/doc-59.md](docs/history/doc-59.md).

- The DNSSEC article, rewritten ([#70](https://github.com/marmot7775/dns-audit/pull/70))

## 2026-09-17: Doc 58. The DMARC article scrolls sideways on phones

Review doc: [docs/history/doc-58.md](docs/history/doc-58.md).

- The DMARC article scrolls sideways on phones ([#69](https://github.com/marmot7775/dns-audit/pull/69))

## 2026-09-16: Doc 57. The DMARC article, rewritten

Review doc: [docs/history/doc-57.md](docs/history/doc-57.md).

- The DMARC article, rewritten ([#68](https://github.com/marmot7775/dns-audit/pull/68))

## 2026-09-16: Doc 56. About and Privacy, rewritten (sent as a second Doc 55; saved verbatim)

Review doc: [docs/history/doc-56.md](docs/history/doc-56.md).

- About and Privacy, rewritten ([#67](https://github.com/marmot7775/dns-audit/pull/67))

## 2026-09-16: Doc 55. About page copy and heading spacing

Review doc: [docs/history/doc-55.md](docs/history/doc-55.md).

- About page copy and heading spacing ([#66](https://github.com/marmot7775/dns-audit/pull/66))

## 2026-09-14: Doc 54. Rename the repo to dns-audit

Review doc: [docs/history/doc-54.md](docs/history/doc-54.md).

- Rename the repo to dns-audit ([#64](https://github.com/marmot7775/dns-audit/pull/64))

## 2026-09-14: Doc 53. A visible cue that the domain field is ready (sent as a second Doc 52; saved verbatim)

Review doc: [docs/history/doc-53.md](docs/history/doc-53.md).

- A visible cue that the domain field is ready ([#63](https://github.com/marmot7775/dns-audit/pull/63))

## 2026-09-14: Doc 52. The PDF in the site's typefaces

Review doc: [docs/history/doc-52.md](docs/history/doc-52.md).

- The PDF in the site's typefaces ([#62](https://github.com/marmot7775/dns-audit/pull/62))

## 2026-09-14: Doc 51. Repo hygiene and README

Review doc: [docs/history/doc-51.md](docs/history/doc-51.md).

- Repo hygiene and README ([#61](https://github.com/marmot7775/dns-audit/pull/61))

## 2026-09-14: Doc 50. Put the Sept 9 home page back, and the iPad summary row

Review doc: [docs/history/doc-50.md](docs/history/doc-50.md).

- Put the Sept 9 home page back, and the iPad summary row ([#59](https://github.com/marmot7775/dns-audit/pull/59))
- One wordmark in the header, and a headline that fits ([#58](https://github.com/marmot7775/dns-audit/pull/58))

## 2026-09-14: Doc 49. Dead code, dead output, and audit speed

Review doc: [docs/history/doc-49.md](docs/history/doc-49.md).

- Dead code, dead output, and audit speed ([#60](https://github.com/marmot7775/dns-audit/pull/60))

## 2026-09-13: Doc 48. UI defects, consistency, and accessibility

Review doc: [docs/history/doc-48.md](docs/history/doc-48.md).

- UI defects, consistency, and accessibility ([#57](https://github.com/marmot7775/dns-audit/pull/57))

## 2026-09-13: Doc 47. Tone, repetition, plurals, placeholders, and plain wording

Review doc: [docs/history/doc-47.md](docs/history/doc-47.md).

- Tone, repetition, plurals, placeholders, and plain wording ([#56](https://github.com/marmot7775/dns-audit/pull/56))

## 2026-09-13: Doc 46. False and unverified claims in generated text, the articles, and the README

Review doc: [docs/history/doc-46.md](docs/history/doc-46.md).

- False and unverified claims in generated text, the articles, and the README ([#55](https://github.com/marmot7775/dns-audit/pull/55))

## 2026-09-13: Doc 45. The other checks: SPF, DANE, CAA, BIMI, TLS-RPT, MTA-STS, DKIM, MX, and a PDF crash

Review doc: [docs/history/doc-45.md](docs/history/doc-45.md).

- The other checks: SPF, DANE, CAA, BIMI, TLS-RPT, MTA-STS, DKIM, MX, and a PDF crash ([#54](https://github.com/marmot7775/dns-audit/pull/54))

## 2026-09-13: Doc 44. DMARC evaluation grades and verdicts that the RFC does not support

Review doc: [docs/history/doc-44.md](docs/history/doc-44.md).

- DMARC evaluation grades and verdicts that the RFC does not support ([#53](https://github.com/marmot7775/dns-audit/pull/53))

## 2026-09-13: Doc 43. Origin exposure and four hardening gaps

Review doc: [docs/history/doc-43.md](docs/history/doc-43.md).

- Origin exposure and four hardening gaps ([#52](https://github.com/marmot7775/dns-audit/pull/52))

## 2026-09-13: Doc 41. Contact lines with the dns@ alias

Review doc: [docs/history/doc-41.md](docs/history/doc-41.md).

- Contact lines with the dns@ alias ([#51](https://github.com/marmot7775/dns-audit/pull/51))

## 2026-09-13: Doc 40. Homepage copy, one false RFC claim, and the last attacker sentences

Review doc: [docs/history/doc-40.md](docs/history/doc-40.md).

- Homepage copy, one false RFC claim, and the last attacker sentences ([#50](https://github.com/marmot7775/dns-audit/pull/50))

## 2026-09-13: Doc 39. Footer line that says what I do

Review doc: [docs/history/doc-39.md](docs/history/doc-39.md).

- Footer line that says what Neil does ([#46](https://github.com/marmot7775/dns-audit/pull/46))

## 2026-09-13: Doc 38. One visual system for the site, the results page, and the PDF

Review doc: [docs/history/doc-38.md](docs/history/doc-38.md).

- One visual system for the site, the results page, and the PDF ([#49](https://github.com/marmot7775/dns-audit/pull/49))

## 2026-09-13: Doc 37. Remove my email address from the repo

Review doc: [docs/history/doc-37.md](docs/history/doc-37.md).

- Remove the personal email address from the repo ([#48](https://github.com/marmot7775/dns-audit/pull/48))

## 2026-09-10: Doc 36. One header on every page

Review doc: [docs/history/doc-36.md](docs/history/doc-36.md).

- One header on every page ([#43](https://github.com/marmot7775/dns-audit/pull/43))

## 2026-09-10: Doc 35. Palette and type, Phases 1 and 2

Review doc: [docs/history/doc-35.md](docs/history/doc-35.md).

- Palette and type, Phases 1 and 2 ([#42](https://github.com/marmot7775/dns-audit/pull/42))

## 2026-09-10: Doc 34. PDF fixes, then the palette

Review doc: [docs/history/doc-34.md](docs/history/doc-34.md).

- Part A: PDF rendering defects and a false sentence on scoped reports ([#41](https://github.com/marmot7775/dns-audit/pull/41))

## 2026-09-10: Doc 33. Use the audited domain in examples, and delete merged branches

Review doc: [docs/history/doc-33.md](docs/history/doc-33.md).

- Use the audited domain in examples, and delete merged branches ([#40](https://github.com/marmot7775/dns-audit/pull/40))

## 2026-09-10: Doc 32. About page rewrite, pluralization, and tone in app output

Review doc: [docs/history/doc-32.md](docs/history/doc-32.md).

- About page rewrite, pluralization, and tone in app output ([#39](https://github.com/marmot7775/dns-audit/pull/39))

## 2026-09-09: Doc 31. Factual errors in the three articles

Review doc: [docs/history/doc-31.md](docs/history/doc-31.md).

- Factual errors in the three articles ([#38](https://github.com/marmot7775/dns-audit/pull/38))

## 2026-09-09: Doc 30. README, SECURITY.md, and stale references on the site

Review doc: [docs/history/doc-30.md](docs/history/doc-30.md).

- README, SECURITY.md, and stale references on the site ([#37](https://github.com/marmot7775/dns-audit/pull/37))

## 2026-09-09: Doc 29. Homepage wording, layout, and type

Review doc: [docs/history/doc-29.md](docs/history/doc-29.md).

- Homepage wording, layout, and type ([#33](https://github.com/marmot7775/dns-audit/pull/33))

## 2026-09-09: Doc 28. False or unsupported statements in app output

Review doc: [docs/history/doc-28.md](docs/history/doc-28.md).

- False or unsupported statements in app output ([#36](https://github.com/marmot7775/dns-audit/pull/36))

## 2026-09-09: Doc 27. PDF report says things the audit did not find

Review doc: [docs/history/doc-27.md](docs/history/doc-27.md).

- PDF report says things the audit did not find ([#35](https://github.com/marmot7775/dns-audit/pull/35))

## 2026-09-09: Doc 24

- Hold the homepage descriptions and FAQ count to SCOPE_CHECKS ([#34](https://github.com/marmot7775/dns-audit/pull/34))
- Make the deploy checkable from outside, correct the Python floor, and fix the pct verdict ([#32](https://github.com/marmot7775/dns-audit/pull/32))

## 2026-09-08: Doc 17

- Refresh the live baseline to the post-doc-17 state ([b94c2a9](https://github.com/marmot7775/dns-audit/commit/b94c2a9))
- Record the pre-doc-17 live baseline ([f957c6f](https://github.com/marmot7775/dns-audit/commit/f957c6f))

## 2026-09-08: Doc 16

- Fix the doc 16 follow-up review: MX, BIMI, and 759 lines of dead code ([08e6ac3](https://github.com/marmot7775/dns-audit/commit/08e6ac3))
- Fix the remaining doc 16 findings: M4, M5, M6 and L8 ([0d39e5f](https://github.com/marmot7775/dns-audit/commit/0d39e5f))
- Fix the three high-severity findings from the doc 16 cold review ([25eed55](https://github.com/marmot7775/dns-audit/commit/25eed55))
