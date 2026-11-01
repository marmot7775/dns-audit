"""Sendermap on the audit's own resolver.

Sendermap (PyPI sendermap) is the sender engine: every service it names
carries the record that decided it, and an absence says what was checked.
This module lets it run inside an audit without a second view of DNS.
AuditResolver answers Sendermap's questions from dns_tools.get_resolver(),
whose cache the checks have already filled, so a name the checks asked is
not asked again and the map sees the answers the cards saw.

audit_engine runs map_senders where the fingerprinter used to run, and the
vendor panel, the DKIM card and the PDF read the map. The helpers below read
Sendermap's catalog for what the map itself does not say: the include a
vendor's setup asks for, and the provider of a key the audit's own DKIM probe
found and the map did not.
"""
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import cache
from typing import Any, Dict, Iterable, Optional, Tuple

import dns.exception
import dns.rdata
import dns.resolver
from sendermap.dns import Answer, Status, norm
# SystemResolver's own rendering rules, so an answer reads the same here as
# from Sendermap's resolver: TXT strings joined, MX as "preference host",
# names lowercased without the trailing dot, the CNAME chain in order.
from sendermap.dns import _cname_chain, _nx_chain, _text
from sendermap.catalog import Catalog, load
from sendermap.engine import map_domain
from sendermap.model import Kind, Need, SenderMap

import dns_tools
from config import MAX_CONCURRENT_AUDITS

log = logging.getLogger(__name__)

# SystemResolver's default lifetime per question.
QUERY_TIMEOUT = 4.0
# Questions one map has in flight at once. Sendermap asks up to 32; the
# audit's own pools already hold most of the threads the droplet allows
# (Doc 102).
MAP_THREADS = 8

# Every map's questions run on this one pool, never on a pool per map: a map
# past its budget leaves its in-flight lookups running for up to
# QUERY_TIMEOUT, and with a pool per map, audits started meanwhile would add
# pools of their own past the unit's task limit. Bounded here, the threads
# can never exceed what AUDIT_THREAD_CEILING counts for them.
_MAP_EXECUTOR = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_AUDITS * MAP_THREADS,
                                   thread_name_prefix="sendermap")


class AuditResolver:
    """sendermap.dns.Resolver over the audit's cached dnspython resolver."""

    name = "system"

    def __init__(self, timeout: float = QUERY_TIMEOUT) -> None:
        self._timeout = timeout
        self._slots = asyncio.Semaphore(MAP_THREADS)

    async def query(self, name: str, rtype: str) -> Answer:
        # dns_tools' resolver is synchronous; a worker thread keeps the
        # map's other questions moving while this one waits. Not
        # asyncio.to_thread: that uses the loop's own default executor.
        async with self._slots:
            return await asyncio.get_running_loop().run_in_executor(
                _MAP_EXECUTOR, self._query, norm(name), rtype)

    def _query(self, name: str, rtype: str) -> Answer:
        try:
            result = dns_tools.get_resolver(self._timeout).resolve(
                name, rtype, raise_on_no_answer=False
            )
        except dns.resolver.NXDOMAIN as e:
            return Answer(name, rtype, Status.NXDOMAIN, chain=_nx_chain_of(e, name))
        except dns.resolver.NoAnswer:  # a stub that ignores raise_on_no_answer
            return Answer(name, rtype, Status.NOANSWER)
        except dns.resolver.NoNameservers:  # every server answered SERVFAIL or REFUSED
            return Answer(name, rtype, Status.FAILED, servfail=True)
        except dns.exception.DNSException:  # timeout, network error
            return Answer(name, rtype, Status.FAILED)
        chain = _cname_chain(result.response, name)
        if result.rrset is None:
            return Answer(name, rtype, Status.NOANSWER, chain=chain)
        return Answer(name, rtype, Status.OK, tuple(_render(r) for r in result.rrset), chain)


def _render(rdata: Any) -> str:
    """One record as SystemResolver renders it (_text). A record that is not
    dnspython's own TXT or MX class but has its shape, as the test suite's
    fake zones serve, renders the same way rather than as quoted lowercase."""
    if not isinstance(rdata, dns.rdata.Rdata):
        if hasattr(rdata, "strings"):
            return "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
        if hasattr(rdata, "preference") and hasattr(rdata, "exchange"):
            return f"{rdata.preference} {norm(str(rdata.exchange))}"
    return _text(rdata)


def _nx_chain_of(error: dns.resolver.NXDOMAIN, name: str) -> Tuple[str, ...]:
    """The CNAMEs that led to a name that does not exist. An NXDOMAIN raised
    without the responses dnspython's resolver attaches (a stub, a cache)
    shows no chain rather than failing the whole map."""
    try:
        return _nx_chain(error, name)
    except KeyError:
        return ()


def map_senders(domain: str, budget_seconds: float) -> Optional[SenderMap]:
    """Sendermap's map of `domain` from DNS alone, or None past the budget.

    DNS only: no website or certificate log reads. Two maps run at once, one
    with the sending subdomains Sendermap finds by DNS (em., mail., send. and
    the like) and one of the domain alone. The subdomain map is the answer
    when it finishes within the budget; a large domain's can take 10 to 15
    seconds, so past it the domain-only map stands in, which finishes in one
    or two. Runs its own event loop, so call it from a worker thread, the way
    the audit runs the fingerprinter.

    Not asyncio.run: on the way out it waits for every question already
    queued, so a map past its budget would keep the caller waiting for all
    of them. Here cancelling the map drops its queued questions from the
    shared pool and abandons those in flight, which end within one
    QUERY_TIMEOUT.
    """
    loop = asyncio.new_event_loop()
    checked_at = datetime.now(timezone.utc)
    full, apex = (loop.create_task(map_domain(
        domain,
        checked_at=checked_at,
        resolver=AuditResolver(),
        use_web=False,
        use_subdomains=subdomains,
        use_ct=False,
    )) for subdomains in (True, False))
    try:
        end = loop.time() + budget_seconds
        for task in (full, apex):
            loop.run_until_complete(asyncio.wait({task}, timeout=max(0.0, end - loop.time())))
            if task.done() and not task.cancelled() and task.exception() is None:
                return task.result()
        failed = [t.exception() for t in (full, apex)
                  if t.done() and not t.cancelled() and t.exception() is not None]
        if failed:
            log.warning("Sender map for %s failed: %r", domain, failed[0])
        if not all(t.done() for t in (full, apex)):
            log.warning("Sender map for %s exceeded its %gs budget", domain, budget_seconds)
    except Exception:
        log.warning("Sender map for %s failed", domain, exc_info=True)
    finally:
        _drain(loop)
        loop.close()
    return None


def _drain(loop: asyncio.AbstractEventLoop) -> None:
    """Cancel every task on `loop` and run it until they have all ended.

    One step of the loop after the cancel used to be the whole of this. It
    reached the outermost tasks only, so the loop closed with tasks nested in
    gathers and task groups still pending, and asyncio logged "Task was
    destroyed but it is pending!" for the losing map on nearly every audit.
    A cancelled task waits on nothing slow: a question in flight runs on in
    _MAP_EXECUTOR, but the future the task awaits is cancelled at once. The
    rounds and the timeout only bound a task that suppresses its cancel.
    """
    for _ in range(5):
        pending = asyncio.all_tasks(loop)
        if not pending:
            return
        for task in pending:
            task.cancel()
        loop.run_until_complete(asyncio.wait(pending, timeout=1.0))
        for task in pending:
            if task.done() and not task.cancelled():
                task.exception()


@cache
def catalog() -> Catalog:
    """Sendermap's vendor catalog, loaded once."""
    return load()


def spf_include(service: str) -> Optional[str]:
    """The include a service's documented setup requires in the domain's
    SPF record ("include:_spf.google.com"), or None when its setup needs no
    include, or the catalog describes no setup for it. None too for a
    vendor whose block names published_spf: its include values are zones
    that hold per-customer names (HubSpot's <id>.spf0N.hubspotemail.net),
    so "include:hubspotemail.net" would authorize the vendor's office mail,
    not the customer's sending."""
    if catalog().services.get(service, {}).get("published_spf"):
        return None
    for rule in catalog().setups.get(service, ()):
        if rule.record == "spf" and rule.need is Need.REQUIRED and rule.values:
            return f"include:{rule.values[0]}"
    return None


def spf_hosts(service: str) -> Tuple[str, ...]:
    """Every SPF include host the catalog knows for a service: a name in the
    SPF tree equal to one of these, or under one, covers the service."""
    return tuple(catalog().services.get(service, {}).get("spf_includes") or ())


def hosted_spf_service(host: str) -> Optional[str]:
    """The hosted SPF service (Valimail, OnDMARC, EasyDMARC, AutoSPF) whose
    include or redirect host this is, or None."""
    service = catalog().spf(host)
    return service if catalog().is_hosted_spf(service) else None


def dkim_cname_service(target: Optional[str]) -> Optional[str]:
    """The service whose zone a DKIM CNAME target sits in, or None."""
    return catalog().dkim_cname([target]) if target else None


def dkim_key_provider(selector: Optional[str], chain: Iterable[str] = (),
                      backed: Optional[str] = None) -> Optional[str]:
    """Who a DKIM key the audit's probe found belongs to, by the catalog's
    rule (sendermap.catalog.Catalog.dkim_key): a CNAME into the service's
    zone first, then the selector name. `backed` is the service the audit's
    discovery tagged the selector with from SPF or MX."""
    if not selector:
        return None
    hops = tuple(h for h in chain if h)
    return catalog().dkim_key(selector, hops, backed)


# DKIM claim kinds that name the provider of a key at a selector, strongest
# first: a CNAME into the service's zone, then the selector name.
_KEY_KINDS = (Kind.DKIM_CNAME, Kind.DKIM_NAME, Kind.DKIM_REVOKED, Kind.DKIM_DANGLING)


def map_dkim_providers(smap: Optional[SenderMap]) -> Dict[str, str]:
    """{selector: service} for every DKIM key the map credits at the domain
    itself. A selector two services claim goes to the stronger claim: the
    CNAME target before the selector name."""
    best: Dict[str, Tuple[int, str]] = {}
    if smap is None:
        return {}
    suffix = f"._domainkey.{smap.domain}"
    for service in smap.services:
        for claim in service.claims:
            if claim.kind not in _KEY_KINDS or claim.where != smap.domain:
                continue
            name = claim.evidence.name.lower()
            if not name.endswith(suffix):
                continue
            selector = name[: -len(suffix)]
            rank = _KEY_KINDS.index(claim.kind)
            if selector not in best or rank < best[selector][0]:
                best[selector] = (rank, service.name)
    return {selector: name for selector, (_rank, name) in best.items()}
