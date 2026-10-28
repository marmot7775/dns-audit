"""
DKIM selector discovery. The vendor dictionary and its order come from
Sendermap's catalog, ranked by the domain's SPF includes and MX hosts;
generic_selectors.py is the fallback sweep when that finds nothing.
"""

import re
import time
import dns.rdatatype
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FuturesTimeoutError, as_completed
from typing import List, Dict, Optional, Callable

from dkim_formatter import analyze_dkim_key_strength

from dns_tools import get_resolver, get_uncached_resolver

# Hard limits for DKIM selector discovery
# Kept below the Phase 2 batch budget (CHECK_TIMEOUT + 5 = 20s). A child
# deadline larger than its parent's can only ever be enforced by the parent,
# which means the child's own timeout handling never runs.
DKIM_DISCOVERY_TIMEOUT = 15   # seconds for entire discovery
DKIM_MAX_FOUND = 15           # stop after finding this many selectors

# Some nameservers rate limit NXDOMAIN answers and silently drop the rest.
# suckless.org, measured from the droplet on 2026-09-28: 60 probes in one
# burst got 19 answers and 41 timeouts, and the zone kept dropping for a few
# seconds after, so the full 197 probe sweep stretched every later check in
# the audit (fingerprinting and subdomain probing) to its own timeout: 28 s
# with the sweep, 6 s without it. Once a wave shows this many unanswered
# probes, the generic fallback stops. What it did not reach is reported as
# not confirmed, never as no DKIM.
DKIM_DROP_THRESHOLD = 5
# The generic fallback goes out in chunks this size, so a zone that starts
# dropping is noticed after one chunk instead of after the whole list.
DKIM_FALLBACK_CHUNK = 52
# The priority wave goes out in chunks this size too (Doc 102). One audit
# then never holds more than DKIM_WAVE_CHUNK DKIM threads at once, which is
# what audit_engine sizes _dkim_executor by. It must not be smaller than
# DKIM_FALLBACK_CHUNK, or a fallback chunk would queue on the pool.
DKIM_WAVE_CHUNK = DKIM_FALLBACK_CHUNK

# _test_selector's return for a probe that got no answer at all.
_UNANSWERED = object()
# A probe that ended in SERVFAIL or another resolver failure: counted as
# tested, as before, but not as answered, since nothing was learned.
_FAILED = object()

# Map SPF includes to the vendor and category the SPF card names
SPF_VENDOR_MAP = {
    # Google
    '_spf.google.com': {
        'vendor': 'Google Workspace',
        'category': 'email_provider'
    },
    
    # Proton Mail.
    #
    # Verified live on proton.me, 2026-09-08: protonmail, protonmail2 and
    # protonmail3 under _domainkey are CNAMEs into domains.proton.ch, and each
    # resolves through to a live 2048-bit RSA key. Proton's own setup adds
    # exactly these three CNAMEs. Without this entry the include mapped to no
    # vendor at all, so nothing pulled the selectors ahead of the 40-name cap
    # and a domain publishing three live keys was reported as unconfirmed.
    '_spf.protonmail.ch': {
        'vendor': 'Proton Mail',
        'category': 'email_provider'
    },

    # Microsoft 365
    'spf.protection.outlook.com': {
        'vendor': 'Microsoft 365',
        'category': 'email_provider'
    },
    
    # Proofpoint
    '_spf.pphosted.com': {
        'vendor': 'Proofpoint',
        'category': 'email_security'
    },
    
    # Mailchimp
    'servers.mcsv.net': {
        'vendor': 'Mailchimp',
        'category': 'marketing_esp'
    },
    
    # SendGrid
    'sendgrid.net': {
        'vendor': 'SendGrid',
        'category': 'transactional_esp'
    },
    
    # Amazon SES
    'amazonses.com': {
        'vendor': 'Amazon SES',
        'category': 'transactional_esp'
    },
    
    # Mailgun
    'mailgun.org': {
        'vendor': 'Mailgun',
        'category': 'transactional_esp'
    },
    
    # Mandrill
    'mandrillapp.com': {
        'vendor': 'Mandrill',
        'category': 'transactional_esp'
    },
    
    # SparkPost
    'sparkpostmail.com': {
        'vendor': 'SparkPost',
        'category': 'transactional_esp'
    },
    
    # Constant Contact
    'constantcontact.com': {
        'vendor': 'Constant Contact',
        'category': 'marketing_esp'
    },
    
    # HubSpot
    '_spf.hubspot.com': {
        'vendor': 'HubSpot',
        'category': 'marketing_esp'
    },
    
    # Zendesk
    'mail.zendesk.com': {
        'vendor': 'Zendesk',
        'category': 'support_platform'
    },

    # Omnivery / Mailkit
    'spf.mailkit.eu': {
        'vendor': 'Omnivery/Mailkit',
        'category': 'transactional_esp'
    },
    'mailkit.eu': {
        'vendor': 'Omnivery/Mailkit',
        'category': 'transactional_esp'
    },
}

def parse_spf_record(spf_record: str) -> List[str]:
    """Extract all include: mechanisms from SPF record.

    RFC 7208 section 4.6.1 makes terms case insensitive, so INCLUDE: and
    Include: are the same mechanism as include:.
    """
    include_pattern = r'include:([^\s]+)'
    return re.findall(include_pattern, spf_record, flags=re.IGNORECASE)

# One budget for every registrable-domain check together, run in parallel
# after the probe waves, so dangling targets cannot hold an audit open.
_DANGLING_NS_BUDGET = 3.0


def _classify_dangling(dangling: List[Dict], found: List[Dict]) -> List[Dict]:
    """Sort dangling DKIM CNAMEs by how much they matter.

    unregistered: the target's registrable domain does not exist, so anyone
    can register it and publish a key that signs as this domain.
    stale: the target sits in a zone that exists, usually a sender that was
    dropped; only that zone's owner can publish there.
    unknown: the registrable-domain lookup did not answer in time.
    microsoft_unfilled: Microsoft 365 publishes both selector CNAMEs and fills
    the second only when it rotates keys, so one empty slot is normal and is
    not reported. Both empty, with no live Microsoft key, usually means DKIM
    signing was never turned on in Microsoft 365. onmicrosoft.com is not
    anyone else's to claim, so it is never "unregistered".
    """
    from concurrent.futures import ThreadPoolExecutor, wait
    from dmarc_tree_walk import _tld_extract
    from sendermap_adapter import dkim_cname_service

    out = []
    microsoft = []
    others = []
    for d in dangling:
        vendor = dkim_cname_service(d['cname_target'])
        if vendor == 'Microsoft 365':
            microsoft.append(d)
        else:
            others.append({**d, 'vendor': vendor,
                           'registrable': _tld_extract(d['cname_target']).top_domain_under_public_suffix or ''})

    live_microsoft = any(
        dkim_cname_service(f.get('cname_target')) == 'Microsoft 365' for f in found)
    if len(microsoft) >= 2 and not live_microsoft:
        out.append({**microsoft[0], 'selector': ', '.join(m['selector'] for m in microsoft),
                    'vendor': 'Microsoft 365', 'registrable': '', 'status': 'microsoft_unfilled'})

    def _ns(name):
        try:
            get_uncached_resolver(2).resolve(name, 'NS')
            return 'stale'
        except dns.resolver.NXDOMAIN:
            return 'unregistered'
        except dns.exception.DNSException:
            return 'unknown'

    names = sorted({d['registrable'] for d in others if d['registrable']})
    verdict = {}
    if names:
        pool = ThreadPoolExecutor(max_workers=min(4, len(names)))
        futures = {pool.submit(_ns, n): n for n in names}
        done, _late = wait(futures, timeout=_DANGLING_NS_BUDGET)
        for f in done:
            verdict[futures[f]] = f.result()
        pool.shutdown(wait=False, cancel_futures=True)
    for d in others:
        d['status'] = verdict.get(d['registrable'], 'unknown')
        out.append(d)
    return out


def _cname_chain(answers, qname: str) -> List[str]:
    """The CNAME hops in an answer, in order from qname."""
    cnames = {}
    for rrset in getattr(getattr(answers, "response", None), "answer", None) or []:
        if getattr(rrset, "rdtype", None) == dns.rdatatype.CNAME and len(rrset):
            cnames[rrset.name.to_text().rstrip(".").lower()] = (
                rrset[0].target.to_text().rstrip(".").lower())
    chain, cur, seen = [], qname.rstrip(".").lower(), set()
    while cur in cnames and cur not in seen:
        seen.add(cur)
        cur = cnames[cur]
        chain.append(cur)
    return chain


def smart_dkim_check(domain: str, spf_record: Optional[str] = None,
                     mx_hosts: Optional[List[str]] = None,
                     progress_callback: Optional[Callable[[int], None]] = None,
                     executor: Optional[ThreadPoolExecutor] = None) -> Dict:
    """
    Probe Sendermap's selector sweep, vendors the domain's SPF or MX points
    at first, then the generic fallback if nothing was found.

    Args:
        domain: Domain to check
        spf_record: SPF record (optional, will query if not provided)
        mx_hosts: MX hostnames. With the SPF includes, they move the
            catalog rules whose hints match to the front of the sweep.
        executor: Pool to run the selector probes on. Defaults to a private
            pool. Callers that already run inside a pool must pass one that is
            not the pool they are running on.

    Returns:
        Complete DKIM discovery results with vendor intelligence
    """
    from sendermap.selectors import probe_order, rank_rules

    import sendermap_adapter
    from generic_selectors import GENERIC_SELECTORS, LOCAL_SELECTORS

    result = {
        'domain': domain,
        'found_selectors': [],
        'tested_count': 0,
        'discovery_method': 'blind_loop',
    }

    # Get SPF record if not provided
    if spf_record is None:
        try:
            answers = get_resolver().resolve(domain, 'TXT')
            for rdata in answers:
                txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
                # RFC 7208 section 4.6.1: the version term is case
                # insensitive, and spf_recursive already lowercases here.
                if txt.strip().lower().startswith('v=spf1'):
                    from spf_recursive import repair_spf_missing_spaces
                    spf_record, _ = repair_spf_missing_spaces(txt)
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
            spf_record = None

    # Sendermap's catalog is the vendor dictionary: its sweep, plus the names
    # production found that it does not carry yet, with the rules whose hints
    # match this domain's MX or SPF moved to the front. The whole sweep is the
    # priority wave; it goes out in chunks of DKIM_WAVE_CHUNK below.
    cat = sendermap_adapter.catalog()
    includes = parse_spf_record(spf_record) if spf_record else []
    ranked = rank_rules(cat.rules, mx_hosts or [], includes)

    # The names a matched rule's vendor backs (Catalog.backs, as Sendermap's
    # own engine does): a key found at one of them belongs to the vendor this
    # domain's own MX or SPF points at. Backed only names such as Google's
    # dated keys are outside the sweep and asked only here.
    mx_set = frozenset(h.lower().rstrip(".") for h in mx_hosts or [])
    spf_set = frozenset(i.lower().rstrip(".") for i in includes)
    backed = {}
    for rule in ranked:
        if rule.hints.matches(mx_set, spf_set):
            for name in sorted(cat.backs(rule.vendor)):
                backed.setdefault(name.lower(), rule.vendor)
    priority_selectors = list(
        probe_order(ranked, (*cat.probe_selectors, *backed, *LOCAL_SELECTORS)))
    _seen_priority = set(priority_selectors)
    if any(rule.hints.matches(frozenset(), spf_set) for rule in ranked):
        result['discovery_method'] = 'spf_intelligent'
    elif backed:
        result['discovery_method'] = 'mx_intelligent'

    # GENERIC_SELECTORS is a fallback sweep, not a standing addition. Before,
    # it was unioned into every probe regardless of outcome, so every audit
    # ran 40 (capped priority) + 156 (generic) = 196 probes even when the
    # very first vendor-implied selector was going to match. It only runs
    # now when the priority list, Sendermap's whole sweep, finds nothing, which is
    # the common case for self-hosted mail publishing "default" and the rare
    # case for everyone else.
    fallback_selectors = [
        s for s in GENERIC_SELECTORS if not (s in _seen_priority or _seen_priority.add(s))
    ]

    # Wildcard detection: query a random nonsense selector. If it returns
    # a TXT record, the domain has wildcard DNS and DKIM discovery is unreliable.
    import uuid
    _canary = f"_dkimwildcardtest{uuid.uuid4().hex[:8]}._domainkey.{domain}"
    try:
        # Uncached: the canary name is random per call, so caching it can
        # only evict a real answer to store one that will never be read.
        _canary_answers = get_uncached_resolver(3).resolve(_canary, 'TXT')
        # Got a response for a random selector -- wildcard DNS detected
        result['wildcard_detected'] = True
        result['found_selectors'] = []
        result['status'] = 'warning'
        result['issues'] = result.get('issues', [])
        result['issues'].append({
            'severity': 'warning',
            'issue': 'Wildcard DNS detected',
            'plain_english': (
                'This domain has wildcard DNS records that respond to any subdomain query. '
                'DKIM selector discovery is not possible because every selector appears to exist.'
            ),
        })
        return result
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
        pass  # No wildcard -- proceed normally

    # Test selectors in parallel
    def _test_selector(selector: str) -> dict | None:
        fqdn = f"{selector}._domainkey.{domain}"
        try:
            # Built per probe, but no longer re-reading /etc/resolv.conf from
            # disk each time: get_uncached_resolver copies a configuration
            # read once at import instead of reconfiguring from the file.
            # Uncached on purpose: with the fallback sweep now conditional,
            # a typical audit's unique probe names are fewer still, and a
            # name that resolves once here is not one any other domain's
            # audit will ever ask again.
            resolver = get_uncached_resolver(3)
            resolver.lifetime = 3
            answers = resolver.resolve(fqdn, 'TXT')
            # Where the name led, when it is an alias. Microsoft 365 DKIM is a
            # CNAME into its own namespace, so this is the evidence that
            # attributes selector1/selector2 to it; the name alone is not.
            _canon = str(getattr(answers, "canonical_name", "") or "").rstrip(".").lower()
            cname_target = _canon if _canon and _canon != fqdn.lower() else None
            # Every hop, not only the last: a vendor's CNAME can point on out
            # of its own zone (to a CDN or a key host), and the first hop is
            # the one that names the vendor.
            cname_chain = _cname_chain(answers, fqdn) or ([cname_target] if cname_target else [])

            # Every record at the name, one joined string each. Looking only
            # at answers[0] dropped the key whenever a domain verification
            # token happened to sort first, and the domain was then reported
            # as having no DKIM at all.
            dkim_record = None
            for rdata in answers:
                txt = "".join(
                    s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
                    for s in rdata.strings
                )
                if "p=" in txt and not txt.strip().startswith("v=spf1"):
                    dkim_record = txt
                    break

            if dkim_record is None:
                return None

            # Key type and size come from the same analyzer the manual
            # selector path uses, so both discovery paths hand downstream
            # consumers an identical selector shape. Guessing the size from
            # base64 length cannot tell 2048 from 3072 or 4096 apart.
            key_analysis = analyze_dkim_key_strength(dkim_record)

            matched_vendor = backed.get(selector.lower())

            return {
                'selector': selector,
                'fqdn': fqdn,
                'record': dkim_record,
                'record_display': dkim_record[:100] + '...' if len(dkim_record) > 100 else dkim_record,
                'key_type': key_analysis['key_type'],
                'key_bits': key_analysis['key_bits'],
                'vendor': matched_vendor,
                'cname_target': cname_target,
                'cname_chain': cname_chain,
                'discovery_priority': 'HIGH' if matched_vendor else 'LOW',
            }
        except dns.exception.Timeout:
            # No answer at all. Not the same as NXDOMAIN: the name may hold a
            # key the server never got round to telling us about.
            return _UNANSWERED
        except dns.resolver.NXDOMAIN as e:
            # A selector that is a CNAME to a name that does not exist. The
            # exception already records where the alias led, so this costs
            # no extra query.
            try:
                _canon = str(e.canonical_name).rstrip(".").lower()
            except Exception:
                _canon = ""
            if _canon and _canon != fqdn.lower():
                return {'selector': selector, 'fqdn': fqdn,
                        'cname_target': _canon, 'dangling': True}
            return None
        except dns.resolver.NoAnswer:
            return None
        except (dns.resolver.NoNameservers, dns.exception.DNSException):
            return _FAILED

    found = []
    dangling = []
    # Selectors whose query finished with an answer (a key, NXDOMAIN or no
    # TXT), so "no key at this name" is known rather than assumed. The vendor
    # panel reads it before saying a sender's key is missing.
    answered = set()
    timed_out = False
    unanswered = 0
    tested = 0
    deadline = time.monotonic() + DKIM_DISCOVERY_TIMEOUT

    # A private pool here meant 15 fresh threads per audit, so eight
    # concurrent audits spawned up to 120 of them on top of the audit pools.
    # Callers pass a long-lived pool instead.
    own_pool = executor is None
    pool = executor or ThreadPoolExecutor(max_workers=15)

    def _run_wave(selectors: List[str]) -> None:
        nonlocal timed_out, tested, unanswered
        if not selectors or timed_out:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            return
        futures = {pool.submit(_test_selector, sel): sel for sel in selectors}
        try:
            # A timeout passed to as_completed is enforced by the stdlib; the
            # previous form checked time.monotonic() only after each future
            # completed, so a slow queue meant the 15s budget was advisory,
            # observed overshooting to 15.2s.
            for future in as_completed(futures, timeout=remaining):
                r = future.result()
                if r is _UNANSWERED:
                    unanswered += 1
                    continue
                tested += 1
                if r is _FAILED:
                    continue
                answered.add(futures[future])
                if r and r.get('dangling'):
                    dangling.append(r)
                elif r:
                    found.append(r)
                    if progress_callback:
                        progress_callback(len(found))
                    if len(found) >= DKIM_MAX_FOUND:
                        break
        except _FuturesTimeoutError:
            timed_out = True
        finally:
            # Cancel the stragglers rather than shutting the pool down. The
            # pool may belong to the caller, and shutting a shared pool down
            # from inside one check would take every other check in the
            # process with it. A future still queued (never started) is
            # actually stopped by cancel(); one already running is not, a
            # limit of the underlying thread, not of this call.
            for f in futures:
                f.cancel()

    def _dropping() -> bool:
        return unanswered >= DKIM_DROP_THRESHOLD

    try:
        # The priority wave always runs in full: Sendermap's sweep, with the
        # names the domain's own SPF or MX points at first. Doc 102 sends them in chunks of DKIM_WAVE_CHUNK, so one
        # audit holds at most that many probe threads; between chunks it stops
        # where a single wave would, at DKIM_MAX_FOUND (_run_wave also stops
        # on the deadline). No drop check here: the full priority wave ran
        # before, and it still does.
        for i in range(0, len(priority_selectors), DKIM_WAVE_CHUNK):
            if len(found) >= DKIM_MAX_FOUND:
                break
            _run_wave(priority_selectors[i:i + DKIM_WAVE_CHUNK])
        if not found:
            for i in range(0, len(fallback_selectors), DKIM_FALLBACK_CHUNK):
                if _dropping():
                    break
                _run_wave(fallback_selectors[i:i + DKIM_FALLBACK_CHUNK])
    finally:
        if own_pool:
            pool.shutdown(wait=False, cancel_futures=True)

    # Preserve priority order: the sweep in rule order, then generics.
    selector_order = {sel: i for i, sel in enumerate(priority_selectors + fallback_selectors)}
    found.sort(key=lambda r: selector_order.get(r['selector'], 999))

    result['found_selectors'] = found
    # The real number of probes that finished, not the number queued. The
    # deadline and the DKIM_MAX_FOUND break both stop the loop early, and
    # reporting the queued count told users we had checked selectors we never
    # got to.
    result['tested_count'] = tested
    result['answered_selectors'] = sorted(answered)

    result['unanswered_count'] = unanswered
    dangling.sort(key=lambda r: selector_order.get(r['selector'], 999))
    result['dangling_selectors'] = _classify_dangling(dangling, found)
    for d in result['dangling_selectors']:
        if d['status'] == 'stale':
            result.setdefault('issues', []).append({
                'severity': 'info',
                'issue': 'DKIM selector points at a missing key',
                'plain_english': (
                    f"{d['selector']}._domainkey is a CNAME to {d['cname_target']}, "
                    "which does not exist. It is usually a sender you no longer use. "
                    "If so, remove the CNAME."
                ),
            })
        elif d['status'] == 'unknown':
            result.setdefault('issues', []).append({
                'severity': 'info',
                'issue': 'DKIM selector points at a missing key',
                'plain_english': (
                    f"{d['selector']}._domainkey is a CNAME to {d['cname_target']}, "
                    "which does not exist. This audit could not check whether "
                    f"{d['registrable'] or 'its domain'} is registered. Remove the "
                    "CNAME if you no longer use this sender."
                ),
            })
        elif d['status'] == 'microsoft_unfilled':
            result.setdefault('issues', []).append({
                'severity': 'info',
                'issue': 'DKIM selector points at a missing key',
                'plain_english': (
                    f"Microsoft 365 selectors ({d['selector']}) are published, but "
                    "neither points at a key yet. That usually means DKIM signing is "
                    "not turned on for this domain in Microsoft 365."
                ),
            })
        elif d['status'] == 'unregistered':
            result.setdefault('issues', []).append({
                'severity': 'error',
                'issue': 'DKIM selector points at an unregistered domain',
                'plain_english': (
                    f"{d['selector']}._domainkey is a CNAME to {d['cname_target']}, "
                    f"and {d['registrable']} is not a registered domain. Anyone who "
                    "registers it can publish a key there and sign mail that passes "
                    "DKIM as this domain. Remove the CNAME."
                ),
            })
    if timed_out:
        result['timed_out'] = True
        result['timeout_note'] = 'DKIM selector discovery timed out, results may be incomplete.'
    elif _dropping() and not found:
        # The zone stopped answering, so "checked N, no key" would overstate
        # what the sweep learned. Same not confirmed card as a sweep that ran
        # out of time, with the reason it stopped.
        result['timed_out'] = True
        result['stopped_reason'] = 'queries_dropped'

    return result
