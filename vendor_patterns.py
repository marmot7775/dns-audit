"""Email vendors recognisable from a domain's own DNS.

One table for the vendor panel (advanced_fingerprinting.py) and the DKIM
card (result_transformer.py), so the two cannot name different senders for
the same record. Before this the panel knew 13 vendors from SPF and 4 from
MX, and three of its SPF patterns (_spf.marketo.com, _spf.mimecast.com,
_spf.pphosted.com) are names that do not exist in DNS.

Sources: Neil's sender discovery vendors.json (Toolkit/templates, 6 Oct
2026), whose verified entries were checked against live DNS, plus the
selector names Doc 93 verified. Every SPF include below was confirmed on
2026-10-07 to publish a v=spf1 record, except the zones that only hold
per-customer includes (mimecast.com, mim.ec, pphosted.com, ppe-hosted.com,
smart.ondmarc.com), which match as suffixes.

All hostname patterns match on label boundaries (the host equals the
pattern or ends in "." plus it), and the longest matching pattern wins, so
spf.em.secureserver.net is GoDaddy Websites + Marketing, not GoDaddy mail.
"""
from typing import Dict, Optional

# SPF include host (or zone) -> vendor.
SPF_INCLUDE_VENDORS: Dict[str, str] = {
    "_spf.google.com": "Google Workspace",
    "aspmx.googlemail.com": "Google Workspace",
    "_netblocks.google.com": "Google Workspace",
    "spf.protection.outlook.com": "Microsoft 365",
    "pphosted.com": "Proofpoint",
    "ppe-hosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "mim.ec": "Mimecast",
    "spf.messagelabs.com": "Symantec MessageLabs",
    "servers.mcsv.net": "Mailchimp",
    "mandrillapp.com": "Mandrill",
    "sendgrid.net": "SendGrid",
    "amazonses.com": "Amazon SES",
    "mailgun.org": "Mailgun",
    "sparkpostmail.com": "SparkPost",
    "spf.mtasv.net": "Postmark",
    "spf.mailjet.com": "Mailjet",
    "spf.brevo.com": "Brevo",
    "sendinblue.com": "Brevo",
    "send.klaviyo.com": "Klaviyo",
    "emsd1.com": "ActiveCampaign",
    "_spf.createsend.com": "Campaign Monitor",
    "constantcontact.com": "Constant Contact",
    "send.aweber.com": "AWeber",
    "zcsend.net": "Zoho Campaigns",
    "zohomail.com": "Zoho Mail",
    "one.zoho.com": "Zoho Mail",
    "_spf.hubspot.com": "HubSpot",
    "hubspotemail.net": "HubSpot",
    "mktomail.com": "Marketo",
    "_spf.salesforce.com": "Salesforce",
    "aspmx.pardot.com": "Salesforce Account Engagement",
    "infusionmail.com": "Keap",
    "mail.zendesk.com": "Zendesk",
    "email.freshdesk.com": "Freshdesk",
    "helpscoutemail.com": "Help Scout",
    "intercom-mail.com": "Intercom",
    "intercom.io": "Intercom",
    "shops.shopify.com": "Shopify",
    "_spf.firebasemail.com": "Firebase",
    "_spf.protonmail.ch": "Proton Mail",
    "spf.messagingengine.com": "Fastmail",
    "secureserver.net": "GoDaddy Professional Email",
    "spf.em.secureserver.net": "GoDaddy Websites + Marketing",
    "emailsrvr.com": "Rackspace Email",
    "_spf-us.ionos.com": "IONOS",
    "_spf.mx.cloudflare.net": "Cloudflare Email Routing",
    "outbound.mailhop.org": "DuoCircle",
    "mailkit.eu": "Omnivery/Mailkit",
    "omnivery.com": "Omnivery",
    "vali.email": "Valimail",
    "smart.ondmarc.com": "Red Sift OnDMARC",
    # From vendors.json on 2026-10-08, each confirmed that day to publish a
    # v=spf1 record (spf.barracudanetworks.com, freshemail.io,
    # _spf.marketo.com and _spf.intuit.com do not, so they are left out).
    "_spf.atlassian.net": "Atlassian",
    "spf.ess.barracudanetworks.com": "Barracuda",
    "ccsend.com": "Constant Contact",
    "_spf.elasticemail.com": "Elastic Email",
    "eversrv.com": "Everlytic",
    "spf.fastmail.com": "Fastmail",
    "_netblocks2.google.com": "Google Workspace",
    "_netblocks3.google.com": "Google Workspace",
    "hubspot.com": "HubSpot",
    "zoho.com": "Zoho Mail",
}

# MX host suffix -> vendor.
MX_VENDORS: Dict[str, str] = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    # Consumer Outlook.com, the same split mx_check.py draws.
    "olc.protection.outlook.com": "Outlook.com (consumer)",
    "pphosted.com": "Proofpoint",
    "ppe-hosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "barracudanetworks.com": "Barracuda",
    "messagelabs.com": "Symantec MessageLabs",
    "protonmail.ch": "Proton Mail",
    "messagingengine.com": "Fastmail",
    "zoho.com": "Zoho Mail",
    "zoho.eu": "Zoho Mail",
    "zoho.in": "Zoho Mail",
    "zoho.com.au": "Zoho Mail",
    "secureserver.net": "GoDaddy Professional Email",
    "emailsrvr.com": "Rackspace Email",
    "ionos.com": "IONOS",
    "kundenserver.de": "IONOS",
    "mx.cloudflare.net": "Cloudflare Email Routing",
    # From vendors.json, 2026-10-08.
    "mx.microsoft": "Microsoft 365",
    "mimecast.co.za": "Mimecast",
    "mimecast-offshore.com": "Mimecast",
}

# Zone a DKIM selector's CNAME points into -> vendor. The strongest DKIM
# evidence: the vendor hosts the key, whatever the selector is called.
DKIM_CNAME_VENDORS: Dict[str, str] = {
    "dkim.amazonses.com": "Amazon SES",
    "dkim.brevo.com": "Brevo",
    "ccsend.com": "Constant Contact",
    "messagingengine.com": "Fastmail",
    "dkim.fmhosted.com": "Fastmail",
    "em.secureserver.net": "GoDaddy Websites + Marketing",
    "helpscout.net": "Help Scout",
    "hubspotemail.net": "HubSpot",
    "dkim.intercom.io": "Intercom",
    "dkim.ionos.com": "IONOS",
    "klaviyo.com": "Klaviyo",
    "mcsv.net": "Mailchimp",
    "mandrillapp.com": "Mandrill",
    "dkim.mail.microsoft": "Microsoft 365",
    "onmicrosoft.com": "Microsoft 365",
    "domains.proton.ch": "Proton Mail",
    "sailthrudkim.com": "Sailthru",
    "sendgrid.net": "SendGrid",
    "squarespace-mail.com": "Squarespace",
    "zendesk.com": "Zendesk",
    "send.aweber.com": "AWeber",
    # From vendors.json, 2026-10-08.
    "mailgun.com": "Mailgun",
    "klaviyodns.com": "Klaviyo",
    "custdkim.salesforce.com": "Salesforce",
    "eversrv.com": "Everlytic",
    # Not freshemail.io: every Freshworks product signs from it, so it does
    # not say which one (Freshdesk, Freshsales, Freshservice).
}

# Selector name -> vendor, for a key published as TXT at the domain itself,
# where the name is the only evidence. selector1 and selector2 are not here.
# Microsoft 365 publishes them only as CNAMEs (a TXT key at the selector is
# not supported), so a TXT key under that name is evidence against Microsoft;
# they are attributed from the CNAME. "api" (Elastic Email, in
# ESP_SELECTORS) is left out too: the name is too common to credit to one
# vendor on the name alone.
DKIM_SELECTOR_VENDORS: Dict[str, str] = {
    "google": "Google Workspace", "gapps": "Google Workspace",
    "k1": "Mailchimp", "k2": "Mailchimp", "k3": "Mailchimp",
    "mandrill": "Mandrill", "mte1": "Mandrill", "mte2": "Mandrill",
    "s1": "SendGrid", "s2": "SendGrid",
    "ses": "Amazon SES",
    "cm": "Campaign Monitor",
    "zendesk1": "Zendesk", "zendesk2": "Zendesk",
    "hubspot": "HubSpot", "hs1": "HubSpot", "hs2": "HubSpot",
    "sf": "Salesforce", "sf1": "Salesforce", "sf2": "Salesforce",
    "protonmail": "Proton Mail", "protonmail2": "Proton Mail", "protonmail3": "Proton Mail",
    "mg": "Mailgun",
    "dkim": "Generic",
    "default": "Generic",
    "sendgrid": "SendGrid", "smtpapi": "SendGrid",
    "fm1": "Fastmail", "fm2": "Fastmail", "fm3": "Fastmail",
    "mimecast": "Mimecast",
    "pphosted": "Proofpoint",
    "everlytickey1": "Everlytic", "everlytickey2": "Everlytic",
    "kl": "Klaviyo", "kl2": "Klaviyo", "km1": "Klaviyo", "km2": "Klaviyo",
    "kt1": "Klaviyo", "kt2": "Klaviyo", "ks1": "Klaviyo", "ks2": "Klaviyo",
    "ctct1": "Constant Contact", "ctct2": "Constant Contact",
    "mailjet": "Mailjet",
    "brevo1": "Brevo", "brevo2": "Brevo",
    "acdkim1": "ActiveCampaign", "acdkim2": "ActiveCampaign",
    "aweber_key_a": "AWeber", "aweber_key_b": "AWeber", "aweber_key_c": "AWeber",
    "litesrv": "MailerLite",
    "cka": "Kit",
    "e2ma-k1": "Emma", "e2ma-k2": "Emma", "e2ma-k3": "Emma",
    "sailthru": "Sailthru",
    "resend": "Resend",
    "pepipost": "Pepipost",
    "strong1": "Help Scout", "strong2": "Help Scout",
    "intercom": "Intercom",
    "gor": "Gorgias", "gor2": "Gorgias",
}

# The distinctive selector names in vendors.json (2026-10-08) the table above
# lacked. Generic names are left out (is_generic_selector), and so are
# "wordpress" and "shops", ordinary words a site could use for its own key,
# and GoDaddy's dotted sable.cloud names (keys here are single labels).
# A name shared by several vendors goes to the vendor vendors.json marks
# primary_for it, or is left out when none is.
DKIM_SELECTOR_VENDORS.update({
    "activecampaign": "ActiveCampaign", "ac1": "ActiveCampaign",
    "amazonses": "Amazon SES", "ses1": "Amazon SES", "ses2": "Amazon SES",
    "aweber": "AWeber", "barracuda": "Barracuda", "bcuda": "Barracuda",
    "braze": "Braze", "appboy": "Braze", "brevo": "Brevo", "sendinblue": "Brevo",
    "sib": "Brevo", "calendly": "Calendly", "campaignmonitor": "Campaign Monitor",
    "cf2024-1": "Cloudflare Email Routing", "constantcontact": "Constant Contact",
    "krs": "Customer.io", "customerio": "Customer.io",
    "elasticemail": "Elastic Email", "emma": "Emma", "myemma": "Emma",
    "mesmtp": "Fastmail", "fastmail": "Fastmail", "freshdesk": "Freshdesk",
    "getresponse": "GetResponse",
    "secureserver1": "GoDaddy Professional Email",
    "secureserver2": "GoDaddy Professional Email",
    "googlemail": "Google Workspace", "ga1": "Google Workspace",
    "gorgias": "Gorgias", "helpscout": "Help Scout", "ic1": "Intercom",
    "s1-ionos": "IONOS", "s2-ionos": "IONOS", "s42582890": "IONOS",
    "iterable": "Iterable", "convertkit": "Kit", "klaviyo": "Klaviyo",
    "kl1": "Klaviyo", "mailchimp": "Mailchimp", "mailerlite": "MailerLite",
    "pdk1": "Mailgun", "pdk2": "Mailgun", "mailgun": "Mailgun", "mg1": "Mailgun",
    "mj1": "Mailjet", "mailpoet1": "MailPoet", "mailpoet2": "MailPoet",
    "marketo": "Marketo", "mkto": "Marketo", "mkto1": "Marketo",
    "mkto2": "Marketo", "mc1": "Mimecast", "mc2": "Mimecast", "mc3": "Mimecast",
    "mimecast20190719": "Mimecast", "mimecast20200619": "Mimecast",
    "omnisend": "Omnisend", "mailkit": "Omnivery", "mkt": "Omnivery",
    "omnivery": "Omnivery", "pipedrive": "Pipedrive", "postmark": "Postmark",
    "pm1": "Postmark", "proofpoint": "Proofpoint", "proofpoint1": "Proofpoint",
    "proofpoint2": "Proofpoint", "proofpoint3": "Proofpoint", "pp1": "Proofpoint",
    "pp02": "Proofpoint", "rackspace": "Rackspace Email",
    "mailtrust": "Rackspace Email", "salesforce": "Salesforce",
    "salesforce1": "Salesforce", "salesforce2": "Salesforce", "sfdc": "Salesforce",
    "200608": "Salesforce Account Engagement",
    "pardot": "Salesforce Account Engagement",
    "pardot1": "Salesforce Account Engagement",
    "exacttarget": "Salesforce Marketing Cloud Engagement",
    "sfmc": "Salesforce Marketing Cloud Engagement",
    "sfmc1": "Salesforce Marketing Cloud Engagement", "shopify": "Shopify",
    "myshopify": "Shopify", "sparkpost": "SparkPost", "scph": "SparkPost",
    "scph0819": "SparkPost", "messagebird": "SparkPost", "square": "Square",
    "squarespace": "Squarespace", "sqsp": "Squarespace", "stripe": "Stripe",
    "messagelabs": "Symantec MessageLabs", "symantec": "Symantec MessageLabs",
    "wix": "Wix", "zendesk": "Zendesk", "zoho": "Zoho Mail",
    "zohomail": "Zoho Mail",
})


# Apex TXT verification tokens that only a mail service asks for, as a
# regex on the start of the record -> vendor. Tokens for services that do
# not send or receive mail as the domain (Stripe, DocuSign, Atlassian
# sign-in) are left out, and so is google-site-verification: it is mostly
# Search Console, not Google Workspace. Prefixes seen on live domains on
# 2026-10-07 (github.com MS=, proton.me protonmail-verification, klaviyo.com
# mgverify and klaviyo-site-verification, rei.com amazonses:, target.com
# brevo-code: and pardot<id>=, uber.com atlassian-sending-domain-verification).
VERIFICATION_TXT_VENDORS = (
    (r"ms=(?=(ms)?[0-9a-f]{6,}$)", "Microsoft 365"),
    (r"protonmail-verification=", "Proton Mail"),
    (r"zoho-verification=", "Zoho Mail"),
    (r"mgverify=", "Mailgun"),
    (r"amazonses:", "Amazon SES"),
    (r"(brevo|sendinblue)-code:", "Brevo"),
    (r"klaviyo-site-verification=", "Klaviyo"),
    (r"pardot\d+=", "Salesforce Account Engagement"),
    (r"atlassian-sending-domain-verification=", "Atlassian"),
)


def match_verification_txt(record: Optional[str]) -> Optional[str]:
    """Vendor whose verification token this apex TXT record is, if any."""
    import re
    r = (record or "").strip().lower()
    for pattern, vendor in VERIFICATION_TXT_VENDORS:
        m = re.match(pattern, r)
        # A prefix with no token after it ("mgverify=") verifies nothing.
        if m and len(r[m.end():].strip()) >= 4:
            return vendor
    return None


def match_host(host: Optional[str], table: Dict[str, str]) -> Optional[str]:
    """Vendor for host by the longest pattern it equals or ends in on a
    label boundary. "sendgrid.net.attacker.example" is not SendGrid."""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return None
    best = None
    for pattern, vendor in table.items():
        if (h == pattern or h.endswith("." + pattern)) and (
            best is None or len(pattern) > len(best[0])
        ):
            best = (pattern, vendor)
    return best[1] if best else None


# Selector names too common to point at one vendor, from the sender
# discovery script's vendors.json: listed here, or two characters or fewer
# unless SHORT_SELECTORS_ALLOWED keeps them. Such a name names a vendor only
# when other records already show that vendor (the backed tag below).
GENERIC_SELECTORS = frozenset({
    "mx", "pm", "dk", "sp", "mail", "email", "default", "dkim", "selector",
    "key", "key1", "key2", "s", "k", "api", "smtp", "mta", "dkim1", "dkim2",
})
SHORT_SELECTORS_ALLOWED = frozenset({"k1", "k2", "k3", "s1", "s2", "cm", "kl"})

# Microsoft 365 publishes these only as CNAMEs into its own zones, so the
# name alone, or a vendor list that includes it, is never evidence.
_CNAME_ONLY_SELECTORS = frozenset({"selector1", "selector2"})


def is_generic_selector(selector: Optional[str]) -> bool:
    s = (selector or "").lower()
    return s in GENERIC_SELECTORS or (len(s) <= 2 and s not in SHORT_SELECTORS_ALLOWED)


def dkim_cname_vendor(cname_target: Optional[str], chain=None) -> Optional[str]:
    """Vendor whose zone a DKIM CNAME points into: the first hop that names
    one, else the final target."""
    for hop in list(chain or []) + [cname_target]:
        vendor = match_host(hop, DKIM_CNAME_VENDORS)
        if vendor:
            return vendor
    return None


def dkim_key_vendor(selector: Optional[str], cname_target: Optional[str],
                    backed: Optional[str] = None, chain=None) -> Optional[str]:
    """Vendor for a found DKIM key, the one rule the DKIM card, its key table
    and the vendor panel share. Never "Generic".

    1. The CNAME, always: the vendor hosts the key. Any hop counts.
    2. selector1 and selector2 name nobody without that CNAME.
    3. backed: the vendor discovery tagged the key with, one whose SPF
       include or MX this domain publishes and whose selector list has this
       name. It beats the name table, so k1 at a domain on Mailgun is not
       credited to Mailchimp on the name.
    4. The name table, unless the name is generic.
    """
    vendor = dkim_cname_vendor(cname_target, chain)
    if vendor:
        return vendor
    s = (selector or "").lower()
    if s in _CNAME_ONLY_SELECTORS:
        return None
    if backed:
        return backed
    if is_generic_selector(s):
        return None
    vendor = DKIM_SELECTOR_VENDORS.get(s)
    return None if vendor == "Generic" else vendor


# Report address domain -> the reporting service that receives DMARC or
# TLS-RPT reports there. From the app's original five and the rua_suffixes
# in Neil's sender discovery vendors.json. A vendor named only here is a
# reporting service, not a sender.
REPORTING_VENDORS: Dict[str, str] = {
    "dmarcian.com": "DMARCian",
    "agari.com": "Agari",
    "valimail.com": "Valimail",
    "vali.email": "Valimail",
    "proofpoint.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "dmarcanalyzer.com": "Mimecast DMARC Analyzer",
    "dmarc-reports.cloudflare.net": "Cloudflare DMARC Management",
    "easydmarc.com": "EasyDMARC",
    "easydmarc.eu": "EasyDMARC",
    "easydmarc.us": "EasyDMARC",
    "glockapps.com": "GlockApps",
    "dmarc.postmarkapp.com": "Postmark",
    "powerdmarc.com": "PowerDMARC",
    "ondmarc.com": "Red Sift OnDMARC",
    "uriports.com": "URIports",
}


def report_address_domains(record: Optional[str], tags=("rua",)):
    """Domains of every mailto: address in the given tags of a DMARC or
    TLS-RPT record, in order, without repeats."""
    out = []
    for part in (record or "").split(";"):
        key, sep, value = part.partition("=")
        if not sep or key.strip().lower() not in tags:
            continue
        for uri in value.split(","):
            uri = uri.strip()
            if uri.lower().startswith("mailto:") and "@" in uri:
                # RFC 6068: header fields after "?" are not the recipient,
                # and "!" starts a DMARC size limit.
                recipient = uri[7:].split("?")[0].split("!")[0].strip()
                local, at, domain = recipient.partition("@")
                # Exactly one "@", with something on both sides.
                if not at or not local or not domain or "@" in domain:
                    continue
                domain = domain.rstrip(".").lower()
                if domain and domain not in out:
                    out.append(domain)
    return out


# CNAMEs at fixed labels under the domain that name a sending vendor, from
# Neil's sender discovery vendors.json (2026-10-08). A return path (bounce)
# CNAME lets the vendor's bounces align with the domain for SPF; a tracking
# CNAME serves its click and open links. Vendors whose label is set per
# account (SendGrid's em1234, Amazon SES, ActiveCampaign) cannot be probed by
# name, so only the fixed labels are here, plus the script's general ones.
VENDOR_CNAME_LABELS = (
    "bounce", "bounces", "em", "email", "mail", "send", "mta", "rp",
    "pm-bounces", "links", "link", "click", "track", "tracking", "url", "go",
    "autodiscover", "cf-bounce", "eversrv", "fwdkim1", "bnc3",
    "bounces.cloud.em", "bounces.cloud2.em",
)
TRACKING_LABELS = frozenset({"links", "link", "click", "track", "tracking", "url", "go"})

RETURN_PATH_VENDORS: Dict[str, str] = {
    "amazonses.com": "Amazon SES",
    "mx.cloudflare.net": "Cloudflare Email Routing",
    "eversrv.com": "Everlytic",
    "freshdesk.com": "Freshdesk",
    "em.secureserver.net": "GoDaddy Websites + Marketing",
    "klaviyodns.com": "Klaviyo",
    "mailjet.com": "Mailjet",
    "mandrillapp.com": "Mandrill",
    "mktomail.com": "Marketo",
    "mtasv.net": "Postmark",
    "sailthrudkim.com": "Sailthru",
    "sendgrid.net": "SendGrid",
    "sparkpostmail.com": "SparkPost",
    "mail.e.sparkpost.com": "SparkPost",
}

TRACKING_VENDORS: Dict[str, str] = {
    "customeriomail.com": "Customer.io",
    "elasticemail.com": "Elastic Email",
    "iterable.com": "Iterable",
    "mailgun.org": "Mailgun",
    "mailjet.com": "Mailjet",
    "mandrillapp.com": "Mandrill",
    "resend-dns.com": "Resend",
    "sailthru.com": "Sailthru",
    "pardot.com": "Salesforce Account Engagement",
    "sendgrid.net": "SendGrid",
    "spgo.io": "SparkPost",
    "et.e.sparkpost.com": "SparkPost",
}

# A CNAME at a label one vendor names for itself: an account trace, not a
# sending setup (autodiscover finds Outlook mailbox settings).
OTHER_CNAME_VENDORS: Dict[str, Dict[str, str]] = {
    "autodiscover": {"autodiscover.outlook.com": "Microsoft 365"},
}


def label_cname_vendor(label: str, target: Optional[str]):
    """(vendor, kind) for a CNAME at label.<domain> pointing at target, kind
    being "return path", "tracking" or "autodiscover"; (None, None) when no
    vendor's zone matches."""
    label = (label or "").lower()
    if label in OTHER_CNAME_VENDORS:
        vendor = match_host(target, OTHER_CNAME_VENDORS[label])
        return (vendor, label) if vendor else (None, None)
    order = (("tracking", TRACKING_VENDORS), ("return path", RETURN_PATH_VENDORS))
    if label not in TRACKING_LABELS:
        order = order[::-1]
    for kind, table in order:
        vendor = match_host(target, table)
        if vendor:
            return vendor, kind
    return None, None
