"""
The generic fallback DKIM sweep: names no vendor claims, probed by
spf_intelligence.smart_dkim_check only when the priority wave finds
nothing (chiefly "default", self-hosted mail's own convention).

The vendor dictionary is Sendermap's catalog (sendermap.catalog), which
carries each name's vendor, how it is known and a live domain that
publishes it. Nothing vendor named belongs here except LOCAL_SELECTORS.
"""

# Names this audit's probe found in production (dns_snapshots.db,
# record_type dkim:<selector>) that Sendermap's sweep does not carry yet.
# They stay in the priority wave until each has a Sendermap catalog entry
# with a proof, and are removed here as each one lands. Count is distinct
# domains, read 2026-10-27.
LOCAL_SELECTORS = (
    'gor2',         # 3 domains
    'proofpoint1',  # 2
    'autotask',     # 2
    'proofpoint',   # 1
    'proofpoint2',  # 1
    'mc1',          # 1
    'mc2',          # 1
    'mc3',          # 1
    'em',           # 1
    'em1',          # 1
    'sp1',          # 1
)

GENERIC_SELECTORS = [
    # Proton Mail. Also in Sendermap's sweep, so normally probed there first;
    # kept here so the fallback still covers a Proton domain on its own.
    # Verified live on proton.me, 2026-09-08: all three are CNAMEs into
    # domains.proton.ch resolving to live 2048-bit RSA keys.
    'protonmail', 'protonmail2', 'protonmail3',

    # Standard naming
    'default', 'mail', 'email', 'dkim',
    'key', 'dk', 'sig', 'signature',
    's', 'mx', 'server',
    'primary', 'secondary',
    'smtp', 'smtpout',
    'main', 'maindomain',
    'prod', 'production',
    'send', 'sender',
    'outbound', 'out',
    'relay', 'bounce',
    'notify', 'notification',
    'newsletter', 'marketing',
    'transactional', 'noreply', 'no-reply',
    'bulk', 'promo',
    'big-email',
    # From ryancdotorg/dkimscan
    'allselector', 'alpha', 'beta', 'gamma', 'delta',
    'auth', 'authsmtp',
    'bfi', 'ca', 'care', 'centralsmtp', 'class', 'corp',
    'dk20050327', 'dk2024', 'dkimmail', 'dkimrnt', 'dkrnt', 'dksel',
    'domain', 'domainkey', 'domk', 'duh',
    'ebmailerd', 'ei',
    'gears', 'global', 'gmmailerd',
    'hubris', 'id', 'iport', 'iweb',
    'lists', 'mail-dkim', 'mail-in', 'mailo', 'mailrelay',
    'mesmtp', 'mikd', 'mimi', 'mkt', 'monkey', 'msa',
    'neomailout', 'one', 'originating',
    'postfix.private', 'primus', 'private', 'proddkim', 'publickey', 'pvt',
    'qcdkim',
    'safe', 'sasl', 'scarlet', 'scooby',
    'selector', 'sharedpool', 'sitemail',
    'snowcrash', 'spop', 'spop1024', 'squaremail', 'stigmate',
    'test', 'testdk', 'testdkim', 'tilprivate',
    'wesmail', 'www', 'x', 'yibm',
    # From pythia2/dkim-api
    's1024', 's2048', '1k', '2k',
    'abr', 'admin', 'bm', 'contact', 'dc',
    'gd', 'hello', 'ic', 'info', 'is',
    'mailtcex', 'mo', 'ms', 'ms1',
    'm1', 'mx1', 'mx2', 'nc',
    'pic', 'postmaster',
    'rs', 'rc', 'secure', 'security',
    'service', 'services', 'server1', 'server2',
    'sign', 'sign1', 'sign2',
    'smtpd', 'strong', 'strong1', 'strong2', 'ss',
    'sl', 'vr', 'webmaster',
    # From Hellfire4959
    'Corporate', 'ED-DKIM',
]
