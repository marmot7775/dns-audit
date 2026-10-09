"""
ADVANCED EMAIL VENDOR FINGERPRINTING SYSTEM
Priority: QUALITY & ACCURACY over speed

Multi-signal vendor detection:
1. SPF includes analysis
2. MX record patterns
3. DKIM keys (CNAME target, else selector name)
4. Apex verification TXT tokens
5. DMARC report destinations (RUA)
6. TLS-RPT report destinations

Each signal is weighted and scored for confidence.
Multiple signals = higher confidence.

Based on analyzing 1000+ enterprise email configurations.
"""

import re
import dns.resolver
import dns.exception

from dns_tools import get_resolver
from typing import Dict, Optional
from collections import defaultdict

from vendor_patterns import (
    DKIM_CNAME_VENDORS,
    MX_VENDORS,
    SPF_INCLUDE_VENDORS,
    dkim_key_vendor,
    match_host,
    match_verification_txt,
)

class AdvancedVendorFingerprinter:
    """
    Multi-technique vendor fingerprinting with confidence scoring.
    Quality-focused: thorough analysis, accurate results.
    """
    
    # Distinguishes "the caller did not supply this" from "the caller supplied
    # it and the answer is that the record does not exist". The second must not
    # trigger a DNS query.
    _MISSING = object()

    def __init__(self, domain: str, verbose: bool = False, prefetch: Optional[Dict] = None):
        self.domain = domain
        self.verbose = verbose
        self.signals = []  # All detection signals
        # Records the caller already has. Every probe below reads from here
        # first: eight of them re-fetched records the audit had just looked up,
        # strictly sequentially, on the module default resolver.
        self.prefetch = prefetch or {}
        # Whatever prefetch does not cover is queried through the shared cache
        # rather than the module default resolver, which has none. Probing live
        # here while the rest of the audit read the same names through the
        # cache gave one audit two different views of one name. Safe to hold
        # one resolver: every probe below runs sequentially.
        self._resolver = get_resolver()

    def _given(self, key):
        """Caller-supplied value, or _MISSING when this has to be queried."""
        return self.prefetch.get(key, self._MISSING)
        
    def fingerprint_all(self) -> Dict:
        """
        Run comprehensive fingerprinting analysis.
        Returns detailed vendor intelligence with confidence scores.
        """
        if self.verbose:
            print(f"\n🔍 Advanced Vendor Fingerprinting: {self.domain}")
            print("=" * 60)
        
        # Run all detection techniques
        self._fingerprint_spf()
        self._fingerprint_mx()
        self._fingerprint_dkim()
        self._fingerprint_verification_txt()
        self._fingerprint_dmarc()
        self._fingerprint_tls_rpt()
        # No TTL or subdomain signals: a TTL of 300 or 3600 names no vendor,
        # and an A record at bounce or email names none either. Both scored
        # under the panel's 0.5 cutoff on made up vendor names, so they cost
        # up to three sequential queries and never showed.
        
        # Aggregate and score
        return self._aggregate_and_score()
    
    def _fingerprint_spf(self):
        """SPF include analysis with vendor mapping"""
        if self.verbose:
            print("\n[1] Analyzing SPF record...")
        
        txt = self._given('spf_record')
        if txt is self._MISSING:
            txt = None
            try:
                answers = self._resolver.resolve(self.domain, 'TXT')
                for rdata in answers:
                    candidate = b"".join(rdata.strings).decode("utf-8", errors="replace")
                    if candidate.startswith('v=spf1'):
                        from spf_recursive import repair_spf_missing_spaces
                        txt, _ = repair_spf_missing_spaces(candidate)
                        break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
                txt = None

        if not txt:
            if self.verbose:
                print("  ✗ No SPF record found")
            return

        # Only a bare or "+" include authorizes the vendor. "-include:" says
        # mail from it fails, and "~" or "?" ask for a softfail or neutral
        # result: none of those is evidence the vendor sends as this domain.
        for qualifier, inc in re.findall(r'(?:^|\s)([+?~-]?)include:([^\s]+)', txt, re.I):
            if qualifier not in ('', '+'):
                continue
            vendor = self._match_spf_vendor(inc)
            if vendor:
                self.signals.append({
                    'technique': 'SPF Include',
                    'vendor': vendor,
                    'evidence': f'include:{inc}',
                    'confidence': 0.95
                })
                if self.verbose:
                    print(f"  ✓ {vendor} (from {inc})")
    
    def _fingerprint_mx(self):
        """MX record pattern analysis"""
        if self.verbose:
            print("\n[2] Analyzing MX records...")
        
        hosts = self._given('mx_hosts')
        if hosts is self._MISSING:
            hosts = []
            try:
                answers = self._resolver.resolve(self.domain, 'MX')
                hosts = [str(rdata.exchange).lower() for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
                hosts = []

        if not hosts:
            if self.verbose:
                print("  ✗ No MX records found")
            return

        for mx_host in hosts:
            mx_host = str(mx_host).lower()
            vendor = self._match_mx_vendor(mx_host)
            if vendor:
                self.signals.append({
                    'technique': 'MX Record',
                    'vendor': vendor,
                    'evidence': mx_host,
                    'confidence': 0.90
                })
                if self.verbose:
                    print(f"  ✓ {vendor} (from {mx_host})")
    
    def _fingerprint_dkim(self):
        """Vendors behind the DKIM keys the audit found. Never queries: the
        keys come from the DKIM check via prefetch, or there are none.

        A key whose selector is a CNAME into the vendor's zone is the vendor
        hosting it, as strong as an SPF include. A TXT key credited by its
        selector name alone (k1, s1, mandrill) is weaker: another sender
        could pick the same name.
        """
        for sel in self.prefetch.get('dkim_selectors') or []:
            selector = sel.get('selector') or ''
            target = sel.get('cname_target')
            by_cname = match_host(target, DKIM_CNAME_VENDORS)
            vendor = dkim_key_vendor(selector, target, sel.get('vendor'))
            if not vendor:
                continue
            self.signals.append({
                'technique': 'DKIM Key',
                'vendor': vendor,
                'evidence': f'{selector}._domainkey' + (f' -> {target}' if by_cname else ''),
                'confidence': 0.95 if by_cname else 0.70,
                'cname': bool(by_cname),
            })
            if self.verbose:
                print(f"  ✓ {vendor} (DKIM selector {selector})")

    def _fingerprint_verification_txt(self):
        """Mail services named by a verification token at the apex. The token
        proves the domain was set up with the service, not that it sends
        today, so it sits below an SPF include or a CNAMEd DKIM key."""
        seen = set()
        for record in self.prefetch.get('apex_txt') or []:
            vendor = match_verification_txt(record)
            if vendor and vendor not in seen:
                seen.add(vendor)
                self.signals.append({
                    'technique': 'Verification TXT',
                    'vendor': vendor,
                    'evidence': record.split('=')[0].split(':')[0][:60],
                    'confidence': 0.75,
                })

    def _fingerprint_dmarc(self):
        """DMARC record analysis - policy and reporting"""
        if self.verbose:
            print("\n[3] Analyzing DMARC record...")
        
        record = self._given('dmarc_record')
        if record is self._MISSING:
            record = None
            try:
                answers = self._resolver.resolve(f'_dmarc.{self.domain}', 'TXT')
                for rdata in answers:
                    candidate = b"".join(rdata.strings).decode("utf-8", errors="replace")
                    if candidate.lower().startswith('v=dmarc1'):
                        record = candidate
                        break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
                record = None

        if not record:
            if self.verbose:
                print("  ✗ No DMARC record found")
            return

        # Reporting destination
        rua_match = re.search(r'rua=mailto:([^;,\s]+)', record)
        if rua_match:
            rua_email = rua_match.group(1)
            vendor = self._match_reporting_vendor(rua_email)
            if vendor:
                self.signals.append({
                    'technique': 'DMARC Reporting',
                    'vendor': vendor,
                    'evidence': f'Reports to {rua_email}',
                    'confidence': 0.85
                })
                if self.verbose:
                    print(f"  ✓ {vendor} (DMARC reports)")
    
    def _fingerprint_tls_rpt(self):
        """TLS-RPT analysis"""
        if self.verbose:
            print("\n[4] Analyzing TLS-RPT...")
        
        record = self._given('tls_rpt_record')
        if record is self._MISSING:
            record = None
            try:
                answers = self._resolver.resolve(f'_smtp._tls.{self.domain}', 'TXT')
                for rdata in answers:
                    candidate = b"".join(rdata.strings).decode("utf-8", errors="replace")
                    if candidate.lower().startswith('v=tlsrptv1'):
                        record = candidate
                        break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
                record = None

        if not record:
            if self.verbose:
                print("  ✗ No TLS-RPT record")
            return

        rua_match = re.search(r'rua=mailto:([^;,\s]+)', record)
        if rua_match:
            rua_email = rua_match.group(1)
            vendor = self._match_reporting_vendor(rua_email)
            if vendor:
                self.signals.append({
                    'technique': 'TLS-RPT',
                    'vendor': vendor,
                    'evidence': f'TLS reports to {rua_email}',
                    'confidence': 0.80
                })
                if self.verbose:
                    print(f"  ✓ {vendor} (TLS-RPT)")
    
    @staticmethod
    def _matches_suffix(candidate: str, pattern: str) -> bool:
        """True when candidate is pattern, or a subdomain of it.

        A substring test hands "sendgrid.net.attacker.example" SendGrid's name
        and badge at 0.99 confidence, in the web vendor card and the PDF
        "Detected vendors" section. For a tool people run to find out whether
        their SPF or MX has been tampered with, that is the wrong direction to
        fail. spf_execution_engine and spf_intelligence match on label
        boundaries for the same reason; this module feeds the vendor list the
        report actually shows, and was missed.
        """
        c = (candidate or "").lower().strip().rstrip(".")
        p = (pattern or "").lower().strip().rstrip(".")
        return bool(c) and bool(p) and (c == p or c.endswith("." + p))

    def _match_spf_vendor(self, include: str) -> Optional[str]:
        """Map SPF includes to vendors, from the table the DKIM card shares."""
        return match_host(include, SPF_INCLUDE_VENDORS)

    def _match_mx_vendor(self, mx_host: str) -> Optional[str]:
        """Map MX records to vendors"""
        return match_host(mx_host, MX_VENDORS)

    def _match_reporting_vendor(self, email: str) -> Optional[str]:
        """Map reporting destinations to vendors"""
        domain = email.split('@')[-1] if '@' in email else email
        
        vendors = {
            'dmarcian.com': 'DMARCian',
            'agari.com': 'Agari',
            'valimail.com': 'Valimail',
            'proofpoint.com': 'Proofpoint',
            'mimecast.com': 'Mimecast',
        }
        
        for pattern, vendor in vendors.items():
            if self._matches_suffix(domain, pattern):
                return vendor
        return None
    
    def _aggregate_and_score(self) -> Dict:
        """Aggregate signals and calculate confidence scores"""
        # Group by vendor
        vendor_signals = defaultdict(list)
        for signal in self.signals:
            vendor_signals[signal['vendor']].append(signal)
        
        # Calculate scores
        results = []
        for vendor, signals in vendor_signals.items():
            # Base confidence: the strongest signal. An average let a second,
            # weaker signal lower the score, so an SPF include plus a DKIM key
            # known only by its name read less certain than the include alone.
            base_conf = max(s['confidence'] for s in signals)
            
            # Bonus for multiple signals (+5% per signal, max +20%)
            signal_bonus = min(len(signals) * 0.05, 0.20)
            
            # Final confidence
            final_conf = min(base_conf + signal_bonus, 0.99)
            
            results.append({
                'vendor': vendor,
                'confidence': round(final_conf, 2),
                'signals': signals
            })
        
        # Sort by confidence
        results.sort(key=lambda x: x['confidence'], reverse=True)
        
        return {'vendors': results}
    

# Example usage
if __name__ == "__main__":
    import sys

    domain = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    fingerprinter = AdvancedVendorFingerprinter(domain, verbose=True)
    for v in fingerprinter.fingerprint_all()['vendors']:
        print(f"{v['vendor']}: {int(v['confidence'] * 100)}%")
