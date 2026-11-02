"""The staged DMARC path: the next stage only, and when to move on.

A domain gets to p=reject in stages: publish p=none with a report address,
read the reports until every service that sends as the domain passes, move
to p=quarantine, read the reports again, then p=reject. This module reads
the DMARC card and the sender map and says which stage is next. It is rules
only. Nothing here calls a language model or any service outside the audit,
and the same inputs give the same words on every run, so the page and the
PDF print one text.

What it cannot know is whether the move is safe. The site never receives
the domain's DMARC reports; they go to the address in rua=. The path says
so in REPORTS_NOTICE, beside every stage that asks for enforcement.

``build`` returns None when there is no stage to show: the DMARC lookup did
not complete, the record is broken (the plan rows cover that), the policy
is inherited from a parent, the domain is already at p=reject, or the scope
does not ask for enforcement.
"""
from typing import Callable, Dict, List, Optional

import plan_records
from plan_records import parse_tags

STAGE_COUNT = 3

REPORTS_NOTICE = (
    "This site never sees your DMARC reports. They go to the address in your record's rua= "
    "tag, not to dns-audit.com, so this audit cannot tell whether moving to enforcement is "
    "safe for your mail. Only your reports can."
)

NO_SENDERS_NOTE = (
    "No sending services were found from DNS. That does not mean there are none: a service "
    "that signs with its own domain, or sends from a server not named in your SPF record, "
    "shows up only in your reports."
)

# Two weeks is the shortest window that still catches a weekly sender; a
# monthly one needs longer, and the text says so.
_WAIT = "at least two weeks (longer if something mails you monthly, such as invoices)"


def _usable_rua(rec: str) -> bool:
    for k, v in parse_tags(rec):
        if k == "rua" and v and not plan_records.has_placeholder(v):
            return any(u.strip().lower().startswith(("mailto:", "https:")) for u in v.split(","))
    return False


def vendor_rows(vendors: Optional[List[Dict]], spf_include: Callable[[str], Optional[str]]) -> List[Dict]:
    """One row per sending service the sender map found: what it is, how it
    was detected, the SPF include its documented setup asks for (from
    Sendermap's catalog), and whether the map saw its setup complete.
    Account-only and reporting services are not senders and are left out."""
    rows = []
    for v in vendors or []:
        if v.get("role") != "sender":
            continue
        missing = list(v.get("missing") or [])
        rows.append({
            "name": v.get("name", ""),
            "category": v.get("category") or "",
            "detected_via": v.get("detected_via") or "",
            "spf_include": spf_include(v.get("name", "")),
            "state": "incomplete" if missing else "covered",
            "missing": missing,
        })
    return rows


def build(domain: str, dmarc: Dict, scope: Optional[str], inbox_scopes,
          vendors: Optional[List[Dict]], spf_include: Callable[[str], Optional[str]],
          edit_record: Callable[..., Optional[str]]) -> Optional[Dict]:
    """The staged path for this audit, or None when there is no stage to show.

    ``edit_record`` is result_transformer._edit_dmarc_record, which edits the
    published record and nothing else; the stage's record is built from it so
    it keeps the owner's own report address and tags."""
    if not domain or not dmarc or dmarc.get("status") == "unavailable":
        return None
    if dmarc.get("inherited_from") or dmarc.get("registry_policy"):
        return None
    rec = dmarc.get("record")
    host = f"_dmarc.{domain}"
    senders = vendor_rows(vendors, spf_include)
    base = {"host": host, "reports_notice": REPORTS_NOTICE, "stage_count": STAGE_COUNT,
            "senders": senders,
            "senders_note": "" if senders else NO_SENDERS_NOTE,
            "set_p": None}

    if not rec:
        if dmarc.get("pill_label") != "Missing":
            return None
        return {**base, "stage": "report", "stage_number": 1,
                "title": "Stage 1 of 3: publish DMARC at p=none, with a report address",
                "do": ("Publish the DMARC record in the records below. p=none changes nothing "
                       "about how your mail is handled. It asks receivers to send you reports "
                       "about who is sending as your domain."),
                "condition": ("Nothing to wait for. Replace the placeholder address with a mailbox "
                              "you read, or a report service, before you publish.")}

    tags: Dict[str, str] = {}
    for k, v in parse_tags(rec):
        tags.setdefault(k, v)
    p = tags.get("p", "").lower()
    pct = tags.get("pct")
    if p == "none":
        if not _usable_rua(rec):
            return {**base, "stage": "report", "stage_number": 1,
                    "title": "Stage 1 of 3: add a report address to your p=none record",
                    "do": ("Add a rua= tag to your DMARC record so receivers send you reports. "
                           "Without it you are publishing a policy that asks for nothing and "
                           "tells you nothing."),
                    "condition": ("Nothing to wait for. Use a mailbox you read or a report "
                                  "service, and replace the placeholder address first.")}
        if scope in inbox_scopes:
            return None
        return {**base, "stage": "quarantine", "stage_number": 2, "set_p": "quarantine",
                "title": "Stage 2 of 3: move from p=none to p=quarantine",
                "do": ("Change p=none to p=quarantine and leave the rest of the record as it is. "
                       "Receivers then send mail that fails DMARC to spam instead of the inbox."),
                "condition": (f"Move on only when your reports have run for {_WAIT} and show every "
                              "service that sends as you passing DMARC. Add any sender that is "
                              "failing to your SPF record or set up its DKIM key first.")}
    if p == "quarantine":
        if (pct and pct.strip() != "100") or scope in inbox_scopes:
            return None
        return {**base, "stage": "reject", "stage_number": 3, "set_p": "reject",
                "title": "Stage 3 of 3: move from p=quarantine to p=reject",
                "do": ("Change p=quarantine to p=reject and leave the rest of the record as it "
                       "is. Receivers then refuse mail that fails DMARC."),
                "condition": (f"Move on only when quarantine has run for {_WAIT} and your reports "
                              "show no legitimate mail failing or landing in spam.")}
    return None


def record_for(stage: Dict, current: str, edit_record: Callable[..., Optional[str]]) -> Optional[str]:
    """The record that publishes this stage, or None when the stage is not a
    change to the published policy."""
    if not stage.get("set_p"):
        return None
    return edit_record(current, {"p": stage["set_p"]})
