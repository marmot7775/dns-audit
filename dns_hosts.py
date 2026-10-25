"""Where to paste a record: the DNS host a domain's nameservers belong to, and the steps
for adding a record there.

Every step, field rule and warning below comes from the host's own help pages, read
2026-10-25; `source` is the page a reader can check. A fact the docs did not state is
left out rather than guessed. Hosts whose docs disagree with each other on the path
(Network Solutions, Vultr) and nameserver names that two hosts share (googledomains.com:
Google Cloud DNS and Squarespace; nsone.net: Squarespace, Wix and other NS1 customers)
get no steps, so the page never names the wrong screen.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import dns.resolver


@dataclass(frozen=True)
class DnsHost:
    name: str
    # Nameserver host name suffixes, matched on a label boundary.
    ns: Tuple[str, ...]
    steps: Tuple[str, ...]
    # How the Name field is filled: what stands for the domain itself.
    apex: str
    source: str
    # Anything about the value field, and a trap that breaks email records.
    value_tip: str = ""
    warning: str = ""


_RELATIVE = "Enter the name without your domain (`_dmarc`, not `_dmarc.{domain}`)."

HOSTS: Tuple[DnsHost, ...] = (
    DnsHost(
        "Cloudflare", ("ns.cloudflare.com",),
        ("Sign in to the Cloudflare dashboard and select the domain.",
         "Open DNS, then Records, and select Add record.",
         "Choose the type, fill in Name and the value, and select Save."),
        "use @",
        "https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/",
        "Long DKIM keys can be pasted whole; Cloudflare splits them.",
        "Set any CNAME for email (DKIM, bounce, tracking) to DNS only, the grey cloud. "
        "A proxied CNAME stops answering as a CNAME and the record breaks.",
    ),
    DnsHost(
        "GoDaddy", ("domaincontrol.com",),
        ("Sign in and open your Domain Portfolio.",
         "Select the domain, then DNS, then Add New Record.",
         "Choose the type, fill in Name and Value, and select Save."),
        "use @",
        "https://www.godaddy.com/help/add-a-txt-record-19232",
        "A value can be up to 1,024 characters.",
    ),
    DnsHost(
        "Namecheap", ("registrar-servers.com",),
        ("Sign in and open Domain List from the left menu.",
         "Select Manage next to the domain, then the Advanced DNS tab.",
         "Select Add new record, choose the type, fill in Host and Value, "
         "and select Save all changes."),
        "use @",
        "https://www.namecheap.com/support/knowledgebase/article.aspx/317/2237/"
        "how-do-i-add-txtspfdkimdmarc-records-for-my-domain/",
    ),
    DnsHost(
        "Amazon Route 53", ("awsdns-",),
        ("Open the Route 53 console and select Hosted zones.",
         "Select the zone for your domain, then Create record.",
         "Fill in Record name, type and value, and select Create records."),
        "leave Record name blank",
        "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-creating.html",
        "Put a TXT value in double quotes. Route 53 does not split long values: break a DKIM "
        "key into quoted pieces of 255 characters or fewer on one line, \"part1\" \"part2\".",
    ),
    DnsHost(
        "Azure DNS", ("azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info"),
        ("In the Azure portal, open DNS zones and select the zone.",
         "Open Record sets and select Add.",
         "Fill in Name, Type and the value, and select Add."),
        "use @",
        "https://learn.microsoft.com/azure/dns/dns-operations-recordsets-portal",
        "Paste a TXT value as one string without quotes; the portal splits long values.",
    ),
    DnsHost(
        "DigitalOcean", ("digitalocean.com",),
        ("In the control panel, open Networking, then Domains, and select the domain.",
         "Choose the record type and fill in Hostname and the value.",
         "Select Create Record."),
        "use @",
        "https://docs.digitalocean.com/products/networking/dns/how-to/manage-records/",
    ),
    DnsHost(
        "Squarespace Domains", ("squarespacedns.com",),
        ("Open account.squarespace.com/domains and select the domain.",
         "Open DNS, then DNS Settings, and scroll to Custom records.",
         "Select Add record, confirm your password, then fill in Type, Name and the value, "
         "and select Save."),
        "use @",
        "https://support.squarespace.com/hc/en-us/articles/31120980444429",
        "Leave quotes out of the value: they can stop an SPF record working. Squarespace adds "
        "your domain to the name for you.",
    ),
    DnsHost(
        "IONOS", ("ui-dns.com", "ui-dns.de", "ui-dns.org", "ui-dns.biz"),
        ("Sign in and open your domains list.",
         "Select the gear icon under Actions for the domain, then DNS.",
         "Select Add Record, choose the type, fill in Host name and the value, and select Save."),
        "use @",
        "https://www.ionos.com/help/domains/configuring-txt-and-srv-records/managing-txt-records/",
    ),
    DnsHost(
        "Hostinger", ("dns-parking.com",),
        ("In hPanel, open Domains from the left sidebar and select the domain.",
         "Open DNS to reach the DNS records page.",
         "Choose the type, fill in Name and the value, and select Add Record."),
        "use @",
        "https://www.hostinger.com/support/1583249-how-to-manage-dns-records-at-hostinger",
    ),
    DnsHost(
        "Wix", ("wixdns.net",),
        ("Go to Domains in your Wix account.",
         "Select the Domain Actions icon next to the domain, then Manage DNS Records.",
         "In the section for the record type, select Add Record, fill in Host Name and "
         "Value, and select Save."),
        "leave Host Name blank",
        "https://support.wix.com/en/article/adding-or-updating-txt-records-in-your-wix-account",
    ),
    DnsHost(
        "Bluehost", ("bluehost.com",),
        ("Sign in to the portal and open Domains from the left menu.",
         "Open the DNS tab and select Add Record, then Single Record.",
         "Choose the type; for any name other than the domain itself, set Refers to "
         "Other Host and enter the host name. Fill in the value and select Add."),
        "set Refers to @",
        "https://www.bluehost.com/help/article/how-to-add-a-dkim-record",
    ),
    DnsHost(
        "Porkbun", ("ns.porkbun.com",),
        ("Sign in and open Domain Management from the Account menu.",
         "Select DNS under the domain.",
         "Choose the type, fill in Host and Answer, and select Add."),
        "leave Host blank",
        "https://kb.porkbun.com/article/231-how-to-add-dns-records-on-porkbun",
    ),
    DnsHost(
        "Hetzner", ("ns.hetzner.com", "ns.hetzner.de"),
        ("In Hetzner Console, open the project, then DNS from the left menu.",
         "Select the zone.",
         "Choose the type, fill in Name and the value, and select Add."),
        "use @",
        "https://docs.hetzner.com/networking/dns/getting-started/adding-records/",
        "Put a TXT value in double quotes, at most 255 characters per quoted piece: split a "
        "DKIM key into \"part1\" \"part2\".",
    ),
    DnsHost(
        "OVHcloud", ("ovh.net",),
        ("In the Control Panel, open Web Cloud, then Domain names, and select the domain.",
         "Open the DNS zone tab and select Add an entry.",
         "Choose the type, fill in Subdomain and the value, and select Add."),
        "leave Subdomain empty",
        "https://docs.ovhcloud.com/en/guides/web-cloud/domains/dns-zone-edit",
        "The form takes TXT values up to 255 characters; for a longer DKIM key, edit the zone "
        "in text mode from the zone's Actions menu.",
        "End a CNAME target with a dot (`target.example.net.`), or OVHcloud adds your domain "
        "to the end of it.",
    ),
    DnsHost(
        "DNSimple", ("dnsimple-edge.com", "dnsimple-edge.net", "dnsimple-edge.io",
                     "dnsimple-edge.org", "dnsimple.com"),
        ("Open the Domains tab and select the domain.",
         "Open the DNS tab, then Add Record in the DNS records section.",
         "Choose the type, fill in Name and Content, and select Add Record."),
        "leave Name blank",
        "https://support.dnsimple.com/articles/how-to-add-dns-records/",
        "Paste the value without quotes; DNSimple adds them and splits long values.",
    ),
    DnsHost(
        "Linode (Akamai Cloud)", ("linode.com",),
        ("In Cloud Manager, open Domains and select the domain.",
         "Select Add a Record in the section for the record type.",
         "Fill in the form and select Save."),
        "leave Hostname blank",
        "https://techdocs.akamai.com/cloud-computing/docs/manage-dns-records",
        "Paste the value without quotes; the DNS Manager adds them and splits long values.",
    ),
)


def _matches(ns_host: str, suffix: str) -> bool:
    """A suffix matches on a label boundary, or inside a label when it ends in a dash
    (awsdns- in ns-123.awsdns-45.com)."""
    host = ns_host.lower().rstrip(".")
    if suffix.endswith("-"):
        return any(label.startswith(suffix) for label in host.split("."))
    return host == suffix or host.endswith("." + suffix)


def host_for(ns_hosts: Iterable[str]) -> Optional[DnsHost]:
    """The one host every nameserver belongs to, or None when they are mixed, unknown
    or empty: steps for the wrong host are worse than none."""
    found = set()
    for ns in ns_hosts:
        match = next((h for h in HOSTS if any(_matches(ns, s) for s in h.ns)), None)
        if match is None:
            return None
        found.add(match.name)
    if len(found) != 1:
        return None
    name = found.pop()
    return next(h for h in HOSTS if h.name == name)


def lookup_ns(domain: str, resolver: Optional[dns.resolver.Resolver] = None) -> List[str]:
    """The domain's nameserver names, from its own NS record or its parent's (a
    subdomain usually sits in its parent's zone). Empty when neither answers."""
    resolver = resolver or dns.resolver.Resolver()
    labels = domain.lower().rstrip(".").split(".")
    for name in (".".join(labels), ".".join(labels[1:])):
        if name.count(".") < 1:
            break
        try:
            answer = resolver.resolve(name, "NS", lifetime=4)
        except Exception:
            continue
        return sorted(str(r.target).rstrip(".").lower() for r in answer)
    return []


def dns_host_block(domain: str, ns_hosts: Iterable[str]) -> Optional[Dict]:
    """The result's dns_host field: the host's name and steps, with the name rule worded
    for this domain, or None when no one host is known."""
    host = host_for(ns_hosts)
    if host is None:
        return None
    block = asdict(host)
    block.pop("ns")
    block["steps"] = list(host.steps)
    block["name_tip"] = (_RELATIVE.format(domain=domain)
                         + f" For the domain itself, {host.apex}.")
    return block
