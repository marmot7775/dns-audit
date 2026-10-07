Doc 94: DKIM key records the card still passes when receivers
cannot use them

Re-fetch main before starting. Written against 20a31f3.

Problem

0c48283 taught the DKIM card two key record tags, t=y and h=. Four
more conditions still pass as a healthy key, though each leaves a
key that receivers cannot use or that violates RFC 6376. Fetch RFC
6376 from rfc-editor.org and quote the governing text for each in
the test file docstring and the commit message. Do not cite from
memory.

1. v= with any value other than DKIM1. Section 3.6.1 says such a
   record is discarded. Grade fail, critical plan row.

2. v= present but not the first tag. Section 3.6.1 requires it
   first. Verifier handling varies, so grade warn, medium row, and
   say plainly that some receivers will reject the key.

3. k= naming a key type other than rsa or ed25519. Find what RFC
   6376 says a verifier does with an unrecognized key type and
   grade to match. Today only k=ed25519 is read, in
   dkim_formatter.py.

4. s= present and listing neither email nor *. Values are colon
   separated. Find what RFC 6376 says a verifier does with a key
   whose service type excludes email and grade to match.

5. A tag name appearing twice in the key record. Section 3.2 says
   the entire tag list is then invalid. Grade fail, critical row.

How

Parse the key record once into an ordered tag list in
dkim_formatter.py, split on semicolons and then on the first
equals sign as _tag_value already does, and keep tag order and
duplicates. Derive all checks from that, including the existing
t=y, h= and k=ed25519 reads, so there is one parser. Follow the
0c48283 pattern for card details, fix text, plan rows and the PDF.
Both discovery paths, the selector sweep and the manually entered
selector, must produce the same result for the same record.

Leave alone

t=s. It only matters with an i= in a signature, which DNS cannot
show. sender_discovery.py lives outside this repo; do not touch
it.

Tests

Add tests/test_dkim_key_record_tags.py with one case per condition
above, plus: a clean v=DKIM1; k=rsa; p= record still passes; a
record with no v= tag still passes (v= is optional); s=email and
s=* pass; k=ed25519 with a valid 32 byte key still passes; and a
record combining t=y and a duplicate tag reports both.

Report back

Commit SHA, test count before and after, the RFC 6376 text quoted
for conditions 3 and 4 with the grade you chose for each, and the
card text a user sees for each of the five conditions.
