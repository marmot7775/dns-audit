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


def dkim_key_vendor(selector: Optional[str], cname_target: Optional[str]) -> Optional[str]:
    """Vendor for a found DKIM key: the CNAME target when there is one, else
    the selector name. Never "Generic"."""
    vendor = match_host(cname_target, DKIM_CNAME_VENDORS)
    if not vendor:
        vendor = DKIM_SELECTOR_VENDORS.get((selector or "").lower())
    return None if vendor == "Generic" else vendor
