# Doc 71: SPF lookup count, one rule everywhere

Main at 4ec81f1. Re-fetch before starting.

## Problem

The SPF lookup count is judged in four places with four thresholds,
so the page contradicts itself:

- result_transformer.py ~4626 to 4634, card detail: 0 to 8 is good,
  "well within the 10-lookup limit"; 9 to 10 is a warning line;
  over 10 is an error. Card status stays pass up to 10 (~4684).
- result_transformer.py ~926 to 931, plan row: HIGH at 8 or more,
  impact "Past 10 lookups, receivers return PermError. None of the
  mail passes SPF..." which describes a failure the domain is not in.
- anomaly_detector.py ~92 to 112: MEDIUM only at exactly 9, with the
  same PermError sentence. Nothing at 10.
- result_transformer.py ~644 to 648: deliverability summary finds
  near-limit by sniffing detail text for the substrings "near" or
  "at". Substring "at" is fragile. Read the number instead.
- result_transformer.py ~4995: optimization suggestion at 8 or more.

Result: at 8 lookups the card says well within, the plan says HIGH.

## Rule to apply everywhere

One helper, e.g. spf_lookup_band(lookups) in result_transformer.py,
returning "ok" (0 to 8), "near" (9 to 10), "over" (above 10).
Every site above reads the band, not its own number.

- ok: card detail good line as today. No plan row, no anomaly,
  no deliverability note, no optimization line.
- near: card stays Pass with the existing warning detail line.
  One plan row, priority medium, action
  "Free up SPF lookups (N/10)", impact stated as a risk, not a
  current failure, e.g. "One more include, a, or mx mechanism
  would take this past 10. Past 10, receivers return PermError,
  none of the mail passes SPF, and DMARC relies on DKIM alone."
  Deliverability summary may keep its near-limit sentence.
  Optimization line as today.
- over: card fail as today. Plan row priority high with the
  existing PermError impact sentence.

Remove the anomaly_detector near-limit entry. The plan row covers
it, and near the limit is not unusual. If a test depends on it,
update the test, do not keep the duplicate.

Keep spf_indeterminate as is: a count that is only a floor stays
warn and must not be banded as ok.

## Tests

Regression tests that assert on the transformed output the user
sees (card, plan items, anomalies, deliverability summary), for
lookup counts 8, 9, 10 and 11:

- 8: no plan row mentions SPF lookups; no anomaly; card detail good.
- 9 and 10: exactly one SPF lookup plan row, priority medium, impact
  does not assert a current PermError; no anomaly.
- 11: card fail; one plan row, priority high.
- No two surfaces disagree on the band for the same count.

Verify the way CI does:
python3 -m venv /tmp/civerify && /tmp/civerify/bin/pip install -r
requirements.txt -r requirements-dev.txt && /tmp/civerify/bin/python
-m pytest tests/ -q

## Rules

- No em dashes or double hyphens in any string.
- One commit, one PR. Save this doc as docs/history/doc-71.md.
- After deploy, report the /api/health version and the SPF card,
  plan rows and anomalies for one live domain in the 9 to 10 band
  if you can find one, else the fixture results for 8 to 11.
