#!/usr/bin/env python3
"""Hold Sendermap's map against the fingerprinter, domain by domain.

Sendermap step 1 of 2: before the fingerprinter, vendor_patterns.py and
comprehensive_selectors.py go, the map has to be at least as good on real
domains. For each domain this runs an email_full audit, so the fingerprinter
gets exactly the prefetch the audit gives it, and then map_senders over the
same cached resolver. One block per domain:

  both        services both name
  map only    services only Sendermap names, each with the record that decided it
  fp only     services only the fingerprinter names, each with its signals
  findings    Sendermap's findings
  run         Sendermap's lookups and elapsed time

then a totals line. Names are matched through Sendermap's catalog, so
"Office 365" and "Microsoft 365" are one service. The fingerprinter side is
the vendor panel's list: confidence 0.5 and up, as _format_vendors keeps it.

    python3 tools/compare_senders.py                  # tools/compare_senders.txt
    python3 tools/compare_senders.py FILE
    python3 tools/compare_senders.py --budget 20 FILE

This reads live DNS. It is a report, not a test.
"""
import argparse
import logging
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import audit_engine  # noqa: E402
from sendermap.catalog import load  # noqa: E402
from sendermap_adapter import map_senders  # noqa: E402

CATALOG = load()


def _key(name):
    """One spelling per service, so the two engines' names can meet."""
    return CATALOG.named(name) or name


def _domains(path):
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                yield line


def _fingerprint(domain):
    """The fingerprinter's vendors for `domain`, run inside a real audit.

    Wraps the class the audit instantiates, so the prefetch, the 8 s budget
    and the 0.5 confidence floor are the audit's own, not a copy of them.
    """
    seen = {}
    real = audit_engine.AdvancedVendorFingerprinter

    class Recording(real):
        def fingerprint_all(self):
            result = super().fingerprint_all()
            seen["vendors"] = result.get("vendors", [])
            return result

    audit_engine.AdvancedVendorFingerprinter = Recording
    try:
        started = time.perf_counter()
        audit_engine.run_full_audit(domain, scope="email_full")
        elapsed = time.perf_counter() - started
    finally:
        audit_engine.AdvancedVendorFingerprinter = real
    vendors = [v for v in seen.get("vendors", []) if v.get("confidence", 0) >= 0.5]
    return vendors, elapsed


def _signals(vendor):
    return "; ".join(
        f"{s.get('technique')}: {s.get('evidence')}" for s in vendor.get("signals", [])
    )


def compare(domain, budget):
    fp_vendors, audit_elapsed = _fingerprint(domain)
    smap = map_senders(domain, budget)
    lines = [f"== {domain}"]
    if smap is None:
        lines.append(f"   map         none (past the {budget:g}s budget or failed)")
        lines.append(f"   fp only     {', '.join(v['vendor'] for v in fp_vendors) or '-'}")
        return lines, {"both": 0, "map": 0, "fp": len(fp_vendors), "failed": 1}

    fp = {}
    for v in fp_vendors:
        fp.setdefault(_key(v["vendor"]), v)
    mp = {s.name: s for s in smap.services}
    both = [n for n in mp if n in fp]
    map_only = [n for n in mp if n not in fp]
    fp_only = [n for n in fp if n not in mp]

    lines.append(f"   both        {', '.join(both) or '-'}")
    lines.append("   map only    " + ("-" if not map_only else ""))
    for n in map_only:
        s = mp[n]
        c = s.decided_by
        tier = s.tier.value if s.tier else "no tier"
        lines.append(f"     {n} ({tier}, {s.role.value}): {c.kind.value} at {c.where}, "
                     f"{c.evidence.rtype} {c.evidence.name} = {c.evidence.value}")
    lines.append("   fp only     " + ("-" if not fp_only else ""))
    for n in fp_only:
        v = fp[n]
        lines.append(f"     {v['vendor']} ({int(v['confidence'] * 100)}%): {_signals(v)}")
    lines.append("   findings    " + ("-" if not smap.findings else ""))
    for f in smap.findings:
        lines.append(f"     [{f.severity.value}] {f.title}")
    lines.append(f"   run         {smap.run.lookups} lookups, {smap.run.elapsed:.2f}s "
                 f"(audit with fingerprinter {audit_elapsed:.1f}s)")
    return lines, {"both": len(both), "map": len(map_only), "fp": len(fp_only), "failed": 0,
                   "lookups": smap.run.lookups, "elapsed": smap.run.elapsed}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("file", nargs="?", default=os.path.join(ROOT, "tools", "compare_senders.txt"))
    ap.add_argument("--budget", type=float, default=20.0, help="seconds per map (default 20)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    totals = {"domains": 0, "both": 0, "map": 0, "fp": 0, "failed": 0,
              "lookups": 0, "elapsed": 0.0}
    for domain in _domains(args.file):
        lines, counts = compare(domain, args.budget)
        print("\n".join(lines))
        print()
        totals["domains"] += 1
        for k, v in counts.items():
            totals[k] += v
    mapped = totals["domains"] - totals["failed"]
    print(f"TOTAL {totals['domains']} domains: both name {totals['both']}, "
          f"only Sendermap {totals['map']}, only fingerprinter {totals['fp']}, "
          f"maps failed {totals['failed']}; Sendermap {totals['lookups']} lookups, "
          f"{totals['elapsed']:.1f}s"
          + (f" ({totals['elapsed'] / mapped:.2f}s a map)" if mapped else ""))


if __name__ == "__main__":
    main()
