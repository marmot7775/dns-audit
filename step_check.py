"""The step check: is the one record you just published live?

The results page walks the change set one record at a time. After the owner
publishes a record, the page asks for that record only, and this module
answers live or not yet. It does its own lookup on a resolver with no
cache, so an answer is never the five minute audit result or an earlier
lookup of the same name. It reads one name, writes nothing and stores
nothing, and the name has to be the audited domain or a name under it.

States:
    live         the record is published and matches
    not_yet      nothing is published there, or what is published differs
    unavailable  the lookup did not complete, which says nothing either way
"""
from typing import Dict, List, Optional

import dns.exception
import dns.resolver

import dns_tools
import plan_records

TIMEOUT = 5.0

# What the page may ask for. A policy file is a web page, not a DNS record.
TYPES = {"TXT": "TXT", "CNAME": "CNAME", "A or CNAME": "A"}

# Values longer than any record this audit proposes are not a record.
MAX_EXPECT = 4096

LAG_NOTE = ("DNS can lag: a resolver may keep serving the old answer until its TTL runs out, "
            "so if you just published, wait a few minutes and check again.")

_TAG_RECORDS = ("v=dmarc1", "v=dkim1", "v=stsv1", "v=tlsrptv1", "v=bimi1")


def _norm_name(name: str) -> str:
    return (name or "").strip().lower().rstrip(".")


def _kind(value: str) -> Optional[str]:
    """The record family a value belongs to, by its version tag."""
    low = (value or "").strip().lower()
    for prefix in _TAG_RECORDS:
        if low.startswith(prefix):
            return prefix
    return "v=spf1" if low.startswith("v=spf1") else None


def _tags(value: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in plan_records.parse_tags(value):
        out.setdefault(k, v)
    return out


def values_match(expect: str, found: str) -> bool:
    """True when ``found`` says what ``expect`` says.

    Tag records (DMARC, DKIM, MTA-STS, TLS-RPT, BIMI) match on their tags, in
    any order, with the policy words and tag names case-insensitive. An
    expected report address that is still the placeholder matches any real
    address, but never the placeholder itself. SPF matches on its terms,
    case-insensitive, whitespace ignored. Anything else must be equal."""
    kind = _kind(expect)
    if kind in _TAG_RECORDS:
        if _kind(found) != kind:
            return False
        want, have = _tags(expect), _tags(found)
        if plan_records.has_placeholder(want.get("rua")) or plan_records.has_placeholder(want.get("ruf")):
            for tag in ("rua", "ruf"):
                if plan_records.has_placeholder(want.get(tag)):
                    if not have.get(tag) or plan_records.has_placeholder(have[tag]):
                        return False
                    want.pop(tag)
                    have.pop(tag)
        if set(want) != set(have):
            return False
        loose = {"p", "sp", "np", "v", "adkim", "aspf", "fo", "t", "h", "k", "s"}
        return all((want[t].lower() == have[t].lower()) if t in loose else (want[t] == have[t])
                   for t in want)
    if kind == "v=spf1":
        return expect.lower().split() == found.lower().split()
    return expect.strip() == found.strip()


def _txt_strings(answer) -> List[str]:
    return ["".join(s.decode("utf-8", "replace") for s in r.strings) for r in answer]


def lookup(host: str, rtype: str, resolver=None) -> Optional[List[str]]:
    """The values published at ``host``, freshly asked. An empty list means
    nothing is published there; None means the lookup did not complete."""
    resolver = resolver or dns_tools.get_uncached_resolver(TIMEOUT)
    resolver.lifetime = TIMEOUT
    try:
        if rtype == "TXT":
            return _txt_strings(resolver.resolve(host, "TXT"))
        if rtype == "CNAME":
            return [_norm_name(str(r.target)) for r in resolver.resolve(host, "CNAME")]
        # "A or CNAME": a name that resolves, whichever way.
        out: List[str] = []
        for t in ("CNAME", "A", "AAAA"):
            try:
                out += [(_norm_name(str(r.target)) if t == "CNAME" else str(r.address))
                        for r in resolver.resolve(host, t)]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            if out:
                break
        return out
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
            dns.exception.DNSException):
        return None


def check(domain: str, host: str, rtype: str, expect: Optional[str] = None,
          op: str = "add", resolver=None) -> Dict:
    """Ask for ``host`` fresh and compare it with what the step published.

    ``expect`` is the step's value. For a delete it is the value that must be
    gone; for a name that only has to resolve ("A or CNAME") it is None."""
    host = _norm_name(host)
    if rtype not in TYPES:
        raise ValueError("unsupported record type")
    if not plan_records.is_under(host, domain):
        raise ValueError("host is not under the audited domain")
    found = lookup(host, rtype, resolver)
    base = {"host": host, "type": rtype, "found": found or []}
    if found is None:
        return {**base, "state": "unavailable",
                "note": "The lookup did not complete, so this says nothing about the record. "
                        "Try again in a moment."}
    if op == "delete":
        target = (expect or "").strip()
        gone = not any(values_match(target, f) or f.strip() == target for f in found)
        return {**base, "state": "live" if gone else "not_yet",
                "note": ("The old record is gone." if gone else
                         "The old record is still published. " + LAG_NOTE)}
    if rtype == "A or CNAME":
        return {**base, "state": "live" if found else "not_yet",
                "note": ("The name resolves." if found else
                         "The name does not resolve yet. " + LAG_NOTE)}
    expect = expect or ""
    kind = _kind(expect)
    same_kind = [f for f in found if kind and _kind(f) == kind]
    if kind in ("v=dmarc1", "v=spf1") and len(same_kind) > 1:
        return {**base, "state": "not_yet",
                "note": f"{len(same_kind)} {kind[2:].upper().rstrip('1')} records are published at this "
                        "name, and a receiver ignores all of them when there is more than one. "
                        "Delete the extra ones."}
    if any(values_match(expect, f) for f in found):
        return {**base, "state": "live", "note": "The record is published and matches."}
    if not found:
        return {**base, "state": "not_yet",
                "note": "Nothing is published at this name yet. " + LAG_NOTE}
    if plan_records.has_placeholder(expect) and any(plan_records.has_placeholder(f) for f in found):
        return {**base, "state": "not_yet",
                "note": "The record is published, but it still holds the placeholder address. "
                        "Replace it with your own and publish again."}
    return {**base, "state": "not_yet",
            "note": "A different value is published at this name. " + LAG_NOTE}
