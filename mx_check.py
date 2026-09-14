"""
MX Analysis Module - DNS Security Auditor
MX record checking with provider detection, priority analysis, and RFC
compliance.

Usage:
    from mx_check import check_mx
    result = check_mx("example.com")
"""

import re
import ipaddress
from typing import Any, Dict, List, Optional

try:
    import dns.resolver
    import dns.exception

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from dns_tools import get_resolver as _get_resolver, make_issue as _make_issue


# ============================================================
# MX Provider Fingerprints
# ============================================================

MX_PROVIDERS = [
    (r"\.mail\.protection\.outlook\.com$", "Microsoft 365"),
    (r"\.olc\.protection\.outlook\.com$", "Microsoft 365 (GCC)"),
    (r"\.google\.com$", "Google Workspace"),
    (r"\.googlemail\.com$", "Google Workspace"),
    (r"aspmx\.l\.google\.com$", "Google Workspace"),
    (r"\.pphosted\.com$", "Proofpoint"),
    (r"\.ppe-hosted\.com$", "Proofpoint Essentials"),
    (r"\.mimecast\.com$", "Mimecast"),
    (r"\.mimecast-offshore\.com$", "Mimecast"),
    (r"\.barracudanetworks\.com$", "Barracuda"),
    (r"\.iphmx\.com$", "Cisco Email Security"),
    (r"\.sophos\.com$", "Sophos"),
    (r"\.reflexion\.net$", "Sophos (Reflexion)"),
    (r"\.mailcontrol\.com$", "Forcepoint"),
    (r"\.messagelabs\.com$", "Symantec/Broadcom"),
    (r"\.tmes\.trendmicro\.com$", "Trend Micro"),
    (r"\.zoho\.com$", "Zoho Mail"),
    (r"\.zohomail\.com$", "Zoho Mail"),
    (r"\.fastmail\.com$", "Fastmail"),
    (r"\.messagingengine\.com$", "Fastmail"),
    (r"\.yahoodns\.net$", "Yahoo Mail"),
    (r"\.protonmail\.ch$", "ProtonMail"),
    (r"\.proton\.me$", "Proton Mail"),
    (r"\.emailsrvr\.com$", "Rackspace"),
    (r"\.amazonaws\.com$", "Amazon SES"),
    (r"\.awsapps\.com$", "Amazon WorkMail"),
    (r"\.secureserver\.net$", "GoDaddy"),
    (r"\.privateemail\.com$", "Namecheap"),
    (r"\.hostinger\.", "Hostinger"),
    (r"\.icloud\.com$", "Apple iCloud"),
    (r"\.migadu\.com$", "Migadu"),
    (r"\.mtasv\.net$", "Postmark"),
    (r"\.mailgun\.org$", "Mailgun"),
    (r"\.sendgrid\.net$", "SendGrid"),
    (r"\.spamexperts\.com$", "SpamExperts"),
    (r"\.antispamcloud\.com$", "SpamExperts"),
    (r"\.mx\.cloudflare\.net$", "Cloudflare Email Routing"),
    (r"\.cloudflare\.net$", "Cloudflare"),
]

COMPILED_PROVIDERS = [(re.compile(pat, re.IGNORECASE), name) for pat, name in MX_PROVIDERS]


# ============================================================
# Helpers
# ============================================================

def _detect_provider(hostname: str) -> Optional[str]:
    h = hostname.lower().rstrip(".")
    for pattern, provider in COMPILED_PROVIDERS:
        if pattern.search(h):
            return provider
    return None


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def _resolve_addresses(hostname: str, rdtype: str) -> List[str]:
    """A or AAAA addresses for one host; empty when the lookup yields none."""
    try:
        return [str(r) for r in _get_resolver().resolve(hostname, rdtype)]
    except dns.exception.DNSException:
        return []


# ============================================================
# Main MX Check
# ============================================================

def check_mx(domain: str, executor=None) -> Dict[str, Any]:
    """MX records and per-host analysis.

    executor, when given, runs the hosts' A and AAAA lookups side by side;
    run_full_audit passes its probe pool. Without one they run in order.
    """
    result = {
        "check": "MX Records", "domain": domain,
        "records": [], "record_count": 0, "providers": [],
        "status": "ok", "issues": [], "warnings": [],
        "recommendations": [], "mx_details": [], "has_null_mx": False,
    }

    if not DNS_AVAILABLE:
        result["status"] = "error"
        result["issues"].append(_make_issue("error", "DNS library not available",
            "Cannot perform DNS lookups.", "", "pip install dnspython"))
        return result

    resolver = _get_resolver()
    raw_mx = []

    try:
        answers = resolver.resolve(domain, "MX")
        result["ttl"] = answers.rrset.ttl if answers.rrset else None
        for rdata in answers:
            priority = rdata.preference
            host = str(rdata.exchange).rstrip(".")
            raw_mx.append((priority, host))
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        result["status"] = "error"
        result["issues"].append(_make_issue(
            "error", f"Domain '{domain}' does not exist (NXDOMAIN)",
            "This domain is not registered or has no DNS records.",
            "No email can be received.",
            "Verify the domain name is correct."))
        return result
    except dns.exception.DNSException as e:
        # SERVFAIL, REFUSED, timeout, NoNameservers. NXDOMAIN and NoAnswer are
        # answers and are handled above; this is the case where nothing was
        # learned. Reported as "unavailable" rather than "error", because the
        # card built from an error status said "No MX records exist for this
        # domain", which is a claim about the domain that this query did not
        # establish. MX is also what has_mx is derived from, so an invented
        # absence here propagates into the checks that depend on it.
        result["status"] = "unavailable"
        result["unavailable_reason"] = "dns_lookup_failed"
        result["lookup_target"] = domain
        result["issues"].append(_make_issue(
            "info", "MX lookup did not complete",
            "The nameserver returned a failure or stopped responding, so this "
            "audit did not learn whether MX records exist.", "",
            "Re-run the audit once the nameservers are answering."))
        return result

    if not raw_mx:
        result["status"] = "warning"
        result["issues"].append(_make_issue(
            "warning", "No MX records found",
            f"No MX records for {domain}. Senders fall back to the domain's A or AAAA "
            "record (RFC 5321 section 5.1), so mail is still attempted if that host runs SMTP.",
            "Mail arrives at the A record host, or bounces if nothing listens there.",
            "Add at least one MX record."))
        return result

    raw_mx.sort(key=lambda x: x[0])
    result["records"] = [f"{p} {h}" for p, h in raw_mx]
    result["record_count"] = len(raw_mx)

    # Null MX check (RFC 7505)
    if len(raw_mx) == 1 and raw_mx[0][0] == 0 and raw_mx[0][1] in (".", ""):
        result["has_null_mx"] = True
        result["status"] = "info"
        result["issues"].append(_make_issue(
            "info", "Null MX record (RFC 7505)",
            "This domain explicitly declares it does not accept email.",
            "Senders get a clean rejection.", ""))
        return result

    # A and AAAA for every MX host at once. The lookups are independent, and
    # one after another they were most of this check's time.
    lookups = [(h, t) for _, h in raw_mx if not _is_ip_address(h) for t in ("A", "AAAA")]
    mapper = executor.map if executor is not None else map
    addresses = dict(zip(lookups, mapper(lambda ht: _resolve_addresses(*ht), lookups)))

    # Analyze each MX host
    seen_providers = set()
    priorities = [p for p, _ in raw_mx]

    for priority, hostname in raw_mx:
        mx_detail = {
            "priority": priority, "hostname": hostname,
            "provider": None, "resolved": False,
            "ips": [],
        }

        if _is_ip_address(hostname):
            result["issues"].append(_make_issue(
                "error", f"MX points to IP address: {hostname}",
                "RFC 5321 requires MX to point to hostnames, not IPs.",
                "Some servers will refuse delivery.",
                "Create a hostname and point the MX there."))
            result["mx_details"].append(mx_detail)
            continue

        provider = _detect_provider(hostname)
        if provider:
            mx_detail["provider"] = provider
            if provider not in seen_providers:
                seen_providers.add(provider)
                result["providers"].append(provider)

        mx_detail["ips"] = addresses[(hostname, "A")] + addresses[(hostname, "AAAA")]
        mx_detail["resolved"] = bool(mx_detail["ips"])

        if not mx_detail["resolved"]:
            result["issues"].append(_make_issue(
                "error", f"MX host '{hostname}' does not resolve",
                f"'{hostname}' has no A or AAAA records.",
                "Mail delivery will fail for this MX.",
                f"Add A/AAAA records for '{hostname}'."))

        result["mx_details"].append(mx_detail)

    # Redundancy check.
    #
    # A single MX at a recognised provider is not a single point of failure:
    # the provider fans out behind the one hostname it gives you, and
    # Microsoft's own setup documentation requires exactly one MX record. The
    # card's explanation already said this ("handle redundancy internally...
    # does not indicate a single point of failure") while the status stayed
    # amber and the fix said to add a secondary, so the card argued with
    # itself and the advice broke the provider's supported configuration.
    #
    # Detected with _detect_provider, the same matcher the MX card's own
    # provider column uses, rather than a second list kept in step by hand.
    if len(raw_mx) == 1 and not _detect_provider(raw_mx[0][1]):
        result["issues"].append(_make_issue(
            "warning", "Only one MX record (no redundancy)",
            "If this host becomes unavailable, inbound mail queues at the "
            "sending server and may eventually bounce.",
            "Single point of failure.",
            "Add a secondary MX record for failover."))

    # Duplicate priorities
    from collections import Counter
    dupes = {p: c for p, c in Counter(priorities).items() if c > 1}
    for p, count in dupes.items():
        hosts = [h for pri, h in raw_mx if pri == p]
        result["warnings"].append(
            f"Priority {p} shared by {count} hosts ({', '.join(hosts)}).")

    severities = [i["severity"] for i in result["issues"]]
    if "error" in severities:
        result["status"] = "error"
    elif "warning" in severities:
        result["status"] = "warning"

    for issue in result["issues"]:
        fix = issue.get("fix")
        if fix and fix not in result["recommendations"]:
            result["recommendations"].append(fix)

    return result
