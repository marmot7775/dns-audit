"""
SPF Execution Engine & DMARC Evaluation Summary
=================================================
Post-processes existing audit data to produce:
  1. SPF evaluation trace -- step-by-step mechanism walk
  2. DMARC evaluation summary -- alignment + disposition logic

Zero extra DNS queries. Transforms data already computed by the audit.
"""

from typing import Dict, List, Optional
from spf_intelligence import SPF_VENDOR_MAP
from spf_recursive import mechanism_is_all, mechanism_recurses, record_has_all


# ============================================================
# Vendor matching
# ============================================================

def _match_vendor(domain: str) -> tuple:
    """Match a domain against SPF_VENDOR_MAP. Returns (vendor, category) or (None, None).

    Matching is on label boundaries, not substrings. A substring test hands
    "sendgrid.net.attacker.example" SendGrid's name and badge, which is the
    wrong direction to fail for a tool people run to find out whether their
    SPF has been tampered with.
    """
    domain_lower = domain.lower().rstrip(".")
    for pattern, info in SPF_VENDOR_MAP.items():
        if domain_lower == pattern or domain_lower.endswith("." + pattern):
            return info["vendor"], info["category"]
    return None, None


# ============================================================
# SPF Execution Trace
# ============================================================

def _walk_tree(node: Dict, flat_steps: List[Dict], running_total: int,
               depth: int, limit: int, exceeded_flagged: List[bool]) -> int:
    """
    Depth-first, left-to-right walk of the SPF recursive tree.
    Mirrors RFC 7208 evaluation order.

    Args:
        node: A node from count_spf_lookups() tree
        flat_steps: Accumulator for the flat timeline
        running_total: DNS lookups consumed so far
        depth: Current nesting depth (0 = root)
        limit: SPF lookup limit (10)
        exceeded_flagged: Single-element list used as mutable flag

    Returns:
        Updated running_total after processing this node
    """
    mechanisms = node.get("mechanisms", [])
    # Children are pulled from an iterator, and only for mechanisms that were
    # actually recursed into. Pairing by position assumed every include and
    # redirect produced a child, which is false the moment one is suppressed:
    # the next include's subtree rendered under the wrong parent.
    children = iter(node.get("children", []))
    # RFC 7208 section 6.1 (redirect is ignored when 'all' is present) and
    # section 5.1 (terms after 'all' are never evaluated). The lookup counter
    # applies both, so the trace has to as well, or it prints a running total
    # that contradicts the total shown beside it.
    has_all = record_has_all(mechanisms)

    for mech in mechanisms:
        mtype = mech["type"]
        raw = mech.get("raw", "")
        qualifier = "+"
        if raw and raw[0] in "+-~?":
            qualifier = raw[0]

        if mtype == "redirect" and has_all:
            continue

        if mtype in ("include", "redirect"):
            # This mechanism costs 1 lookup itself, plus its children
            running_total += 1
            mechanism_start = running_total

            # Get the child subtree for this include/redirect. A macro
            # expanded target has none: it costs its lookup and stops there.
            child_node = (
                next(children, None) if mechanism_recurses(mech, has_all) else None
            )

            # Only match vendor on top-level includes (depth 0)
            vendor, vendor_category = (None, None)
            if depth == 0:
                value = mech.get("value", "")
                vendor, vendor_category = _match_vendor(value)

            status = "ok"

            # The step is placed before its children so the timeline reads in
            # evaluation order, then filled in once the subtree is walked and
            # the totals are known.
            step = {
                "mechanism": raw or f"{mtype}:{mech.get('value', '')}",
                "type": mtype,
                "qualifier": qualifier,
                "vendor": vendor,
                "vendor_category": vendor_category,
                "depth": depth,
            }
            flat_steps.append(step)

            # Process children recursively to get accurate running_total.
            # flat_steps is passed through, not replaced with a throwaway
            # list: discarding it left every nested mechanism out of the
            # timeline, so depth was always 0 and nothing below the top
            # level was ever rendered.
            old_total = running_total
            if child_node:
                running_total = _walk_tree(child_node, flat_steps, running_total, depth + 1, limit, exceeded_flagged)

            lookup_range = str(mechanism_start) if running_total == mechanism_start else f"{mechanism_start}-{running_total}"

            if not exceeded_flagged[0] and running_total > limit:
                status = "exceeded"
                exceeded_flagged[0] = True
            elif exceeded_flagged[0]:
                status = "exceeded"

            step.update({
                "lookup_cost": running_total - old_total + 1,
                "lookup_range": lookup_range,
                "running_total": running_total,
                "status": status,
            })

        elif mtype in ("a", "mx", "ptr", "exists"):
            running_total += 1
            status = "ok"
            if not exceeded_flagged[0] and running_total > limit:
                status = "exceeded"
                exceeded_flagged[0] = True
            elif exceeded_flagged[0]:
                status = "exceeded"

            flat_steps.append({
                "mechanism": raw or mtype,
                "type": mtype,
                "qualifier": qualifier,
                "vendor": None,
                "vendor_category": None,
                "lookup_cost": 1,
                "lookup_range": str(running_total),
                "running_total": running_total,
                "status": status,
                "depth": depth,
            })

        elif mtype == "no_lookup":
            # ip4, ip6, all -- no DNS lookup cost
            flat_steps.append({
                "mechanism": raw,
                "type": mtype,
                "qualifier": qualifier,
                "vendor": None,
                "vendor_category": None,
                "lookup_cost": 0,
                "lookup_range": None,
                "running_total": running_total,
                "status": "ok",
                "depth": depth,
            })
            if mechanism_is_all(mech):
                # RFC 7208 section 5.1: 'all' always matches, so nothing
                # after it is ever evaluated.
                break

        else:
            # Modifiers such as exp= and anything the parser could not
            # classify. These cost no lookup, but emitting nothing left them
            # invisible in the visualization even though audit_engine flags
            # them separately.
            flat_steps.append({
                "mechanism": raw or mtype,
                "type": mtype,
                "qualifier": qualifier,
                "vendor": None,
                "vendor_category": None,
                "lookup_cost": 0,
                "lookup_range": None,
                "running_total": running_total,
                "status": "unknown",
                "depth": depth,
            })

    return running_total


def build_spf_execution_trace(spf_recursive_result: Dict, spf_record: Optional[str]) -> Optional[Dict]:
    """
    Build a step-by-step SPF evaluation trace from existing recursive lookup data.

    Args:
        spf_recursive_result: The full result from count_spf_lookups()
        spf_record: The raw SPF record string

    Returns:
        Trace dict with steps[] and flat_steps[], or None on error
    """
    if not spf_recursive_result:
        return None

    tree = spf_recursive_result.get("tree")
    if not tree:
        return None

    total_lookups = spf_recursive_result.get("total_lookups", 0)
    limit = 10
    flat_steps = []
    exceeded_flagged = [False]

    _walk_tree(tree, flat_steps, 0, 0, limit, exceeded_flagged)

    return {
        "domain": spf_recursive_result.get("domain", ""),
        "record": spf_record or spf_recursive_result.get("record"),
        "total_lookups": total_lookups,
        "limit": limit,
        "over_limit": total_lookups > limit,
        "flat_steps": flat_steps,
    }


# ============================================================
# DMARC Evaluation Summary
# ============================================================

def build_dmarc_evaluation(raw_dmarc: Dict, raw_spf: Dict,
                           raw_dkim: Dict, tree_walk: Optional[Dict],
                           dkim_confirmed: bool = True) -> Optional[Dict]:
    """
    Build a DMARC evaluation summary showing how receivers would process
    legitimate mail from this domain's authorized servers.

    This is educational -- it shows the *best case* for properly configured mail,
    not a live message evaluation.

    Args:
        raw_dmarc: Raw DMARC check result
        raw_spf: Raw SPF check result
        raw_dkim: Raw DKIM check result
        tree_walk: Tree walk result (for inherited policies)
        dkim_confirmed: False when the DKIM card could not settle whether the
            domain signs (selectors cannot be enumerated). Finding no key then
            is "not confirmed", not "none".

    Returns:
        Evaluation dict, or None if insufficient data
    """
    if not raw_dmarc:
        return None

    # Need at least SPF or DKIM data to produce a meaningful evaluation.
    # Without them (e.g. dmarc-only scope), the eval would be misleading.
    has_spf_data = bool(raw_spf and raw_spf.get("record"))
    has_dkim_data = bool(raw_dkim and raw_dkim.get("found_selectors"))
    if not has_spf_data and not has_dkim_data:
        return None

    # --- SPF result ---
    spf_record = raw_spf.get("record") if raw_spf else None
    spf_lookup_count = raw_spf.get("lookup_count", 0) if raw_spf else 0

    if not spf_record:
        spf_result = "none"
    elif spf_lookup_count > 10:
        # Only treat as permerror when lookups genuinely exceed the RFC 7208
        # limit.  Syntax warnings (e.g. malformed but recovered records) should
        # NOT produce a permerror here -- the lenient parser result is the
        # single source of truth for the entire UI.
        spf_result = "permerror"
    else:
        spf_result = "configured"

    # --- DKIM result ---
    # A revoked key (empty p=) is published but signs nothing, so it is no
    # DKIM path. The DKIM card and the resilience block already split them.
    from result_transformer import _split_dkim_selectors
    found_selectors, _revoked = _split_dkim_selectors(
        (raw_dkim.get("found_selectors") or []) if raw_dkim else [])
    if found_selectors:
        dkim_result = "configured"
    elif not dkim_confirmed:
        dkim_result = "not confirmed"
    else:
        dkim_result = "none"

    # --- DMARC record and alignment modes ---
    dmarc_record = raw_dmarc.get("record")
    if not dmarc_record and not (tree_walk and tree_walk.get("policy_source")):
        return None  # No DMARC at all, nothing to evaluate

    aspf = raw_dmarc.get("aspf") or "r"  # default relaxed
    adkim = raw_dmarc.get("adkim") or "r"  # default relaxed

    spf_alignment_mode = "strict" if aspf == "s" else "relaxed"
    dkim_alignment_mode = "strict" if adkim == "s" else "relaxed"

    # For this educational display based on DNS records only (not live mail),
    # we show alignment as "possible" when the mechanism is configured
    spf_aligned = spf_result == "configured"
    dkim_aligned = dkim_result == "configured"

    # --- DMARC result ---
    # DMARC can pass if EITHER (SPF configured + aligned) OR (DKIM configured + aligned)
    dmarc_pass = spf_aligned or dkim_aligned
    dkim_unknown = dkim_result == "not confirmed"
    if dmarc_pass:
        dmarc_result = "configured"
    elif dkim_unknown:
        dmarc_result = "not confirmed"
    else:
        dmarc_result = "fail"

    # --- Policy ---
    policy = raw_dmarc.get("policy") or ""
    if not policy and tree_walk and tree_walk.get("effective_policy"):
        policy = tree_walk["effective_policy"]
    policy = policy.lower() if policy else "none"

    # Disposition: what happens to the message
    if dmarc_pass:
        disposition = "none"  # passes, delivered normally
    elif dkim_unknown:
        disposition = "unknown"
    else:
        disposition = policy  # apply the domain's policy

    # --- Explanation ---
    # This is a DNS-only assessment, not a live mail test
    if dmarc_pass:
        configured_methods = []
        alignment_modes = []
        if spf_aligned:
            configured_methods.append("SPF")
            alignment_modes.append(spf_alignment_mode)
        if dkim_aligned:
            configured_methods.append("DKIM")
            alignment_modes.append(dkim_alignment_mode)
        methods_str = " and ".join(configured_methods)
        modes_str = " and ".join(dict.fromkeys(alignment_modes))
        explanation = (
            f"{methods_str} {'are' if len(configured_methods) > 1 else 'is'} configured "
            f"with {modes_str} alignment, providing "
            f"{'redundant paths' if len(configured_methods) > 1 else 'a path'} to DMARC pass. "
            f"Based on DNS records only, not live mail testing."
        )
    elif dkim_unknown:
        explanation = (
            "SPF is not configured in a way that can satisfy DMARC alignment, and "
            "whether the domain signs with DKIM could not be confirmed from DNS. "
            "Based on DNS records only, not live mail testing."
        )
    else:
        explanation = (
            "Neither SPF nor DKIM is configured in a way that can satisfy DMARC alignment. "
            f"The domain's policy ({policy}) determines how receivers handle failing messages. "
            "Based on DNS records only, not live mail testing."
        )

    return {
        "spf_result": spf_result,
        "spf_aligned": spf_aligned,
        "spf_alignment_mode": spf_alignment_mode,
        "dkim_result": dkim_result,
        "dkim_aligned": dkim_aligned,
        "dkim_alignment_mode": dkim_alignment_mode,
        "dmarc_result": dmarc_result,
        "policy": policy,
        "disposition": disposition,
        "explanation": explanation,
    }


# ============================================================
# SPF Include Tree Visualization
# ============================================================

def _build_tree_node(node: Dict, depth: int, total_lookups: int) -> Optional[Dict]:
    """Recursively build a tree node for the SPF include tree visualization."""
    if not node:
        return None

    domain = node.get("domain", "")
    record = node.get("record")
    mechanisms = node.get("mechanisms", [])
    children = node.get("children", [])
    lookups_here = node.get("lookups_here", 0)
    subtree_total = node.get("total", 0)

    # Vendor match (depth 0-1 only)
    vendor, vendor_category = (None, None)
    if depth <= 1:
        vendor, vendor_category = _match_vendor(domain)

    # Collect leaf IPs
    ips = []
    for mech in mechanisms:
        if mech["type"] == "no_lookup":
            raw = mech.get("raw", "")
            # SPF terms are case-insensitive (RFC 7208 section 4.6.1) and any
            # qualifier may precede them, so normalize before matching.
            clean = raw.lstrip("+-~?")
            if clean.lower().startswith(("ip4:", "ip6:")):
                ips.append(clean)

    # Terminal mechanism
    terminal = None
    for mech in mechanisms:
        if mech["type"] == "no_lookup":
            raw = mech.get("raw", "").lower().lstrip("+-~?")
            if raw == "all":
                qualifier = mech.get("raw", "+all")[0] if mech.get("raw", "") and mech["raw"][0] in "+-~?" else "+"
                terminal = qualifier + "all"

    # Recurse into children. Same iterator rule as the trace: only the
    # mechanisms the counter actually resolved consumed a child node, so
    # pairing by position nests one include's targets under another.
    has_all = record_has_all(mechanisms)
    child_iter = iter(children)
    child_nodes = []
    for mech in mechanisms:
        if mechanism_is_all(mech):
            break
        if mechanism_recurses(mech, has_all):
            child = next(child_iter, None)
            if child is None:
                continue
            child_node = _build_tree_node(child, depth + 1, total_lookups)
            if child_node:
                child_nodes.append(child_node)

    result = {
        "domain": domain,
        "record": record,
        "lookups_here": lookups_here,
        "subtree_lookups": subtree_total,
        "vendor": vendor,
        "vendor_category": vendor_category,
        "ips": ips if ips else None,
        "children": child_nodes,
        "terminal": terminal,
        "depth": depth,
    }

    return result


def build_spf_tree_viz(spf_recursive_result: Dict) -> Optional[Dict]:
    """
    Build a hierarchical SPF include tree from existing recursive lookup data.

    Args:
        spf_recursive_result: The full result from count_spf_lookups()

    Returns:
        Tree viz dict, or None on error
    """
    if not spf_recursive_result:
        return None

    tree = spf_recursive_result.get("tree")
    if not tree:
        return None

    total_lookups = spf_recursive_result.get("total_lookups", 0)
    limit = 10

    root = _build_tree_node(tree, 0, total_lookups)
    if not root:
        return None

    return {
        "domain": spf_recursive_result.get("domain", ""),
        "record": tree.get("record"),
        "total_lookups": total_lookups,
        "limit": limit,
        "over_limit": total_lookups > limit,
        "root": root,
    }


# ============================================================
# DMARC Migration Roadmap
# ============================================================

