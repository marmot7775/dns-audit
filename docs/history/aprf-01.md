# APRF follow-up for draft-ietf-mailmaint-aprf-01, 2026-11-01

## Brief
dns-audit.com deleted its bare TXT record at _aprf._domainkey.dns-audit.com
and published a wildcard at *._aprf._domainkey.dns-audit.com instead. The
brief asked for three changes in one PR:

1. Tests: the expected state for our own domain is wildcard only, bare absent.
2. Card: present a bare record as a legacy location that -01 generators will
   not query, with advice to publish at the wildcard or the live selectors.
3. Article: say the wildcard goes in the selector position and cite -01.

## What was done
1. tests/test_aprf.py pins the wildcard-only shape: the bare name is queried
   and absent, live selector names answer with the wildcard's record, and the
   card reports one record at the wildcard. The bare-only test stays as a
   generic case.
2. Not done. The brief's premise does not hold: -01 section 4 still says "the
   publishing entity may opt to omit the selector from the declaration, and
   cover all selectors" at _aprf._domainkey.<d>, and section 4.2 still lists
   that name first in the order of discovery. A bare record is a valid -01
   location, so the card keeps reporting it as published. The only -01 change
   to section 4.2 is that the selector line gained its missing _aprf label;
   the engine comment that called it a typo now says -01 fixed it.
3. The article names the selector-position wildcard and the bare name as the
   two names that cover every selector, says -01 defines a wildcard only in
   the selector position, and adds a paragraph on -01 (destination check
   against the signing domain only, version a string, segment a list of
   strings, a later report for the same day replaces an earlier one). The
   sample's version is now a string, as in -01. dateModified 2026-11-01.
