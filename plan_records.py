"""The records each plan row asks for, and the change set built from them.

A plan row used to carry a record only when it was about DMARC. Every
other row said what to do in words, and the reader had to work out the
record. This module gives SPF, DKIM, MTA-STS, TLS-RPT and BIMI rows the
same thing: a list of records, each with its type, its name and its exact
value. When DNS does not tell us the value (a new DKIM key, the include a
sending service hands out, a certificate URL), the value is None and
``value_from`` says in plain words who has it.

``build_change_set`` turns the rows into one ordered list: every record in
plan order, with the edits several rows make to the same record folded
into one value, so following the list top to bottom never undoes a step.

Each record is a dict:

    op          "add", "replace", "delete" or "file" (a file served over
                HTTPS, which MTA-STS needs beside its TXT record)
    type        "TXT", "CNAME", "MX", "A or CNAME", or "Policy file"
    host        the full name, or the URL for a policy file
    value       the exact value, or None when it has to come from someone else
    value_from  who supplies the value, when value is None
    note        what to check before or after publishing it
    by          who publishes it, when that is not the domain's owner
    current     the value published now, for a replace or a delete
    placeholder True when the value holds RUA_PLACEHOLDER, an address the
                owner must replace before publishing

and, while the plan is being built, an ``edit`` that says how the value
was derived from the published record, so that two rows editing one
record can be merged. ``build_change_set`` removes it.
"""
import re
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional


# SPF includes the mailbox providers publish for their own outbound mail.
# Only providers the MX card names, and only the include each one
# documents for every tenant.
SPF_PROVIDER_INCLUDES = {
    "Google Workspace": "include:_spf.google.com",
    "Microsoft 365": "include:spf.protection.outlook.com",
}

SPF_LOOKUP_LIMIT = 10

# SPF terms that cost a DNS lookup (RFC 7208 section 4.6.4).
_SPF_LOOKUP_TERMS = ("include", "a", "mx", "ptr", "exists", "redirect")


# A report address this audit cannot know. It is never a working mailbox:
# the owner swaps it for their own before publishing, and the page and the
# PDF flag every record that still holds it.
RUA_PLACEHOLDER = "REPLACE-WITH-YOUR-ADDRESS"


def rua_placeholder(domain: str) -> str:
    return f"mailto:{RUA_PLACEHOLDER}@{domain}"


def has_placeholder(value: Optional[str]) -> bool:
    return bool(value) and RUA_PLACEHOLDER in value


def record(op: str, rtype: str, host: str, value: Optional[str] = None,
           value_from: Optional[str] = None, note: Optional[str] = None,
           by: Optional[str] = None, edit: Optional[Dict] = None,
           current: Optional[str] = None) -> Dict:
    out = {"op": op, "type": rtype, "host": host, "value": value,
           "value_from": value_from if value is None else None, "note": note}
    if by:
        out["by"] = by
    if current:
        out["current"] = current
    if has_placeholder(value):
        out["placeholder"] = True
    if edit:
        out["edit"] = edit
    return out


# ------------------------------------------------------------------
# Tag lists (DKIM, TLS-RPT, MTA-STS, BIMI records)
# ------------------------------------------------------------------

def parse_tags(rec: Optional[str]) -> List[tuple]:
    """A tag=value; record as (tag, value) pairs, in order, tag lowercased."""
    pairs = []
    for part in (rec or "").split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        pairs.append((k.strip().lower(), v.strip()))
    return pairs


def edit_tag_list(rec: Optional[str], set_tags: Optional[Dict[str, str]] = None,
                  remove=(), first: Optional[str] = None) -> Optional[str]:
    """The record with only the named tags changed, in its own order.

    A tag being set that the record lacks goes at the end. ``first`` moves
    that tag to the front (v= in DKIM, RFC 6376 section 3.6.1).
    """
    if not rec:
        return None
    set_tags = {k.lower(): v for k, v in (set_tags or {}).items()}
    drop = {t.lower() for t in remove}
    pairs = []
    for k, v in parse_tags(rec):
        if k in drop:
            continue
        if k in set_tags:
            v = set_tags.pop(k)
        pairs.append((k, v))
    pairs.extend(set_tags.items())
    if first:
        pairs.sort(key=lambda kv: kv[0] != first)
    return "; ".join(f"{k}={v}" for k, v in pairs)


# ------------------------------------------------------------------
# SPF
# ------------------------------------------------------------------

def spf_lookup_terms(rec: str) -> int:
    """Terms in the record itself that cost a lookup. Includes nest, so the
    real count can only be higher."""
    n = 0
    for term in rec.split()[1:]:
        name = re.split(r"[:/=]", term.lstrip("+-~?").lower(), maxsplit=1)[0]
        if name in _SPF_LOOKUP_TERMS:
            n += 1
    return n


def spf_replace_all(rec: str, qualifier: str = "~") -> Optional[str]:
    """The record with its all mechanism set to ``qualifier``all."""
    terms = rec.split()
    out, changed = [], False
    for t in terms:
        if t.lower() in ("all", "+all", "?all"):
            out.append(f"{qualifier}all")
            changed = True
        else:
            out.append(t)
    return " ".join(out) if changed else None


def spf_merge(records: List[str]) -> Optional[str]:
    """One record carrying every mechanism of ``records``, or None when a
    modifier (redirect=, exp=) makes the merge a judgment call."""
    terms, all_term = [], None
    for rec in records:
        parts = rec.split()
        if not parts or parts[0].lower() != "v=spf1":
            return None
        for t in parts[1:]:
            low = t.lower()
            if low.startswith(("redirect=", "exp=")):
                return None
            if low.lstrip("+-~?") == "all":
                all_term = all_term or t
                continue
            if low not in (x.lower() for x in terms):
                terms.append(t)
    merged = " ".join(["v=spf1", *terms, all_term or "~all"])
    # RFC 7208 section 4.6.4: past 10 lookups the record is a PermError, and
    # the services it includes add their own on top of the terms counted
    # here, so a merge already at the limit is not offered.
    if spf_lookup_terms(merged) > SPF_LOOKUP_LIMIT - 1:
        return None
    return merged


def spf_missing_record(domain: str, providers: List[str]) -> Dict:
    includes = [SPF_PROVIDER_INCLUDES[p] for p in providers if p in SPF_PROVIDER_INCLUDES]
    if includes:
        return record(
            "add", "TXT", domain, " ".join(["v=spf1", *includes, "~all"]),
            note=(f"Your MX records point at {', '.join(p for p in providers if p in SPF_PROVIDER_INCLUDES)}, "
                  "so this record covers mail sent from there. Add an include: for every other "
                  f"service that sends mail as {domain} before you publish it; each service's "
                  "setup page gives its include."))
    return record(
        "add", "TXT", domain,
        value_from=("Your email provider and each service that sends mail as you. Each one's "
                    "setup page gives an include:, and the record lists them all: "
                    "v=spf1 include:<first service> include:<second service> ~all"))


# ------------------------------------------------------------------
# MTA-STS
# ------------------------------------------------------------------

def mta_sts_id(now: Optional[datetime] = None, current: Optional[str] = None) -> str:
    """An id= for the _mta-sts record: the UTC date and a counter, different
    from the published id, since a changed id is what tells senders to fetch
    the policy again (RFC 8461 section 3.1). The date, not the time, so two
    audits on one day propose the same record."""
    day = (now or datetime.now(timezone.utc)).strftime("%Y%m%d")
    n = 1
    while f"{day}{n:02d}" == (current or ""):
        n += 1
    return f"{day}{n:02d}"


def mta_sts_policy(mode: str, mx_hosts: List[str], max_age: int) -> str:
    lines = ["version: STSv1", f"mode: {mode}"]
    lines += [f"mx: {h}" for h in mx_hosts]
    lines.append(f"max_age: {max_age}")
    return "\n".join(lines)


def mta_sts_new(domain: str, mx_hosts: List[str], now: Optional[datetime] = None) -> List[Dict]:
    """The three pieces of a new MTA-STS setup, in the order to publish them:
    the policy file, the name that serves it, then the TXT record that tells
    senders to fetch it."""
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    if mx_hosts:
        policy = record("file", "Policy file", url, mta_sts_policy("testing", mx_hosts, 604800),
                        note=("Testing mode: senders report failures but still deliver. Move to "
                              "mode: enforce once TLS-RPT reports show clean delivery. Serve it "
                              "as text/plain."))
    else:
        policy = record("file", "Policy file", url,
                        value_from=("Your MX hosts, one mx: line each, under version: STSv1, "
                                    "mode: testing and max_age: 604800. This audit did not read "
                                    "the MX records, so it cannot list them."))
    host = record("add", "A or CNAME", f"mta-sts.{domain}",
                  value_from=("Whoever hosts the policy file. The name must serve HTTPS with a "
                              f"valid certificate for mta-sts.{domain}."))
    txt = record("add", "TXT", f"_mta-sts.{domain}", f"v=STSv1; id={mta_sts_id(now)}",
                 note="Publish this last, once the policy file loads over HTTPS.")
    return [policy, host, txt]


def mta_sts_enforce(domain: str, card: Dict, mx_hosts: List[str],
                    now: Optional[datetime] = None) -> List[Dict]:
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    hosts = card.get("policy_mx") or mx_hosts
    max_age = card.get("policy_max_age") or 604800
    if hosts:
        policy = record("file", "Policy file", url, mta_sts_policy("enforce", hosts, max_age),
                        note=("Only the mode: line changes. Check every mx: line still matches "
                              "your MX records first: in enforce mode, senders refuse to deliver "
                              "to a host the policy does not list."))
    else:
        policy = record("file", "Policy file", url,
                        value_from="Your current policy file, with mode: testing changed to mode: enforce.")
    out = [policy]
    cur = card.get("record")
    new_id = mta_sts_id(now, dict(parse_tags(cur)).get("id"))
    new_txt = edit_tag_list(cur, {"id": new_id}) if cur else f"v=STSv1; id={new_id}"
    out.append(record("replace", "TXT", f"_mta-sts.{domain}", new_txt,
                      note="A new id= tells senders to fetch the changed policy.",
                      edit={"kind": "tags", "base": cur, "set": {"id": new_id}}
                      if cur else None))
    return out


# ------------------------------------------------------------------
# The change set
# ------------------------------------------------------------------

def build_change_set(items: List[Dict], editors: Dict[str, Callable]) -> Dict:
    """Every record the plan asks for, in plan order, one entry per record.

    Rows that edit the same published record (DMARC rua, sp and np rows; a
    DKIM key in test mode with v= out of place) become one entry whose
    value carries every edit, so publishing the list in order never undoes
    an earlier step. Optional rows come after the rest, as in the plan.
    """
    ordered = ([i for i in items if not i.get("optional")]
               + [i for i in items if i.get("optional")])
    entries: List[Dict] = []
    by_key: Dict[tuple, Dict] = {}
    rows_without = 0
    for item in ordered:
        recs = item.get("records") or []
        if not recs:
            rows_without += 1
            continue
        for rec in recs:
            edit = rec.get("edit")
            key = None
            if edit and edit.get("base"):
                key = (rec["type"], rec["host"].lower(), edit["kind"], edit["base"])
            if key and key in by_key:
                entry = by_key[key]
                merged = entry["_edit"]
                merged["set"].update(edit.get("set") or {})
                for t in edit.get("remove") or ():
                    merged["remove"].append(t)
                    merged["set"].pop(t, None)
                merged["first"] = merged.get("first") or edit.get("first")
                entry["value"] = _apply_edit(merged, editors)
                entry["placeholder"] = has_placeholder(entry["value"])
                _add_reason(entry, item, rec)
                continue
            entry = {
                "protocol": item.get("protocol", ""),
                "priority": item.get("priority", ""),
                "optional": bool(item.get("optional")),
                "actions": [],
                "why": [],
                "op": rec["op"],
                "type": rec["type"],
                "host": rec["host"],
                "value": rec.get("value"),
                "value_from": rec.get("value_from"),
                "current": rec.get("current"),
                "placeholder": bool(rec.get("placeholder")),
                "notes": [],
            }
            if rec.get("by"):
                entry["by"] = rec["by"]
            _add_reason(entry, item, rec)
            if key:
                entry["_edit"] = {"kind": edit["kind"], "base": edit["base"],
                                  "set": dict(edit.get("set") or {}),
                                  "remove": list(edit.get("remove") or ()),
                                  "first": edit.get("first")}
                by_key[key] = entry
            entries.append(entry)
    # A step whose value is the owner's call (move to enforcement) comes after
    # the exact edits to the same record, so it starts from the edited one.
    for e in [e for e in entries if e["value"] is None and e["op"] == "replace"]:
        same = [n for n, o in enumerate(entries)
                if o is not e and o["value"] is not None
                and (o["type"], o["host"].lower()) == (e["type"], e["host"].lower())]
        if same and same[-1] > entries.index(e):
            entries.remove(e)
            entries.insert(same[-1], e)
    # MTA-STS testing mode is judged by TLS-RPT reports, so a new TLS-RPT
    # record goes ahead of the MTA-STS steps when the plan has both.
    _first_sts = next((n for n, e in enumerate(entries) if e["protocol"] == "MTA-STS"), None)
    if _first_sts is not None:
        _rpt = [e for e in entries[_first_sts:] if e["protocol"] == "TLS-RPT"]
        if _rpt:
            rest = [e for e in entries[_first_sts:] if e["protocol"] != "TLS-RPT"]
            entries = entries[:_first_sts] + _rpt + rest
    for n, e in enumerate(entries, 1):
        e["step"] = n
        e.pop("_edit", None)
    for item in items:
        for rec in item.get("records") or []:
            rec.pop("edit", None)
    exact = sum(1 for e in entries if e["value"] is not None)
    return {"entries": entries, "exact": exact,
            "from_provider": len(entries) - exact,
            "placeholders": sum(1 for e in entries if e["placeholder"]),
            "rows_without_records": rows_without}


def _apply_edit(edit: Dict, editors: Dict[str, Callable]) -> Optional[str]:
    fn = editors[edit["kind"]]
    if edit["kind"] == "tags":
        return fn(edit["base"], edit["set"], edit["remove"], first=edit.get("first"))
    return fn(edit["base"], edit["set"], edit["remove"])


def _add_reason(entry: Dict, item: Dict, rec: Dict) -> None:
    if item.get("action") and item["action"] not in entry["actions"]:
        entry["actions"].append(item["action"])
    why = item.get("plain_head") or item.get("impact")
    if why and why not in entry["why"]:
        entry["why"].append(why)
    if rec.get("note") and rec["note"] not in entry["notes"]:
        entry["notes"].append(rec["note"])


def mx_hosts_from_card(card: Optional[Dict]) -> List[str]:
    """MX hostnames in preference order, from the MX card."""
    if not card or card.get("status") == "unavailable":
        return []
    hosts = card.get("mx_hosts")
    if hosts is not None:
        return list(hosts)
    out = []
    for line in (card.get("record") or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] not in (".", ""):
            out.append(parts[1].rstrip("."))
    return out


def dkim_selector_records(card: Dict) -> Dict[str, Dict]:
    """selector -> {"record", "cname_target"} from the DKIM card."""
    out = {}
    for s in card.get("dkim_selectors") or []:
        out[s["selector"]] = s
    if out:
        return out
    for line in (card.get("record") or "").splitlines():
        m = re.match(r"^([^\s:]+)\._domainkey:\s*(.*)$", line)
        if m:
            out[m.group(1)] = {"selector": m.group(1), "record": m.group(2), "cname_target": None}
    return out
