"""Sendermap on the audit's own resolver.

Sendermap (PyPI sendermap) is the sender engine: every service it names
carries the record that decided it, and an absence says what was checked.
This module lets it run inside an audit without a second view of DNS.
AuditResolver answers Sendermap's questions from dns_tools.get_resolver(),
whose cache the checks have already filled, so a name the checks asked is
not asked again and the map sees the answers the cards saw.

Step 1 of 2 is a shadow run: nothing in audit_engine calls map_senders yet.
tools/compare_senders.py holds its output against the fingerprinter's.
"""
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Optional

import dns.exception
import dns.resolver
from sendermap.dns import Answer, Status, norm
# SystemResolver's own rendering rules, so an answer reads the same here as
# from Sendermap's resolver: TXT strings joined, MX as "preference host",
# names lowercased without the trailing dot, the CNAME chain in order.
from sendermap.dns import _cname_chain, _nx_chain, _text
from sendermap.engine import map_domain
from sendermap.model import SenderMap

import dns_tools

log = logging.getLogger(__name__)

# SystemResolver's default lifetime per question.
QUERY_TIMEOUT = 4.0
# Questions in flight at once. Sendermap asks up to 32; the audit's own
# pools already hold most of the threads the droplet allows (Doc 102).
MAP_THREADS = 8


class AuditResolver:
    """sendermap.dns.Resolver over the audit's cached dnspython resolver."""

    name = "system"

    def __init__(self, timeout: float = QUERY_TIMEOUT) -> None:
        self._timeout = timeout

    async def query(self, name: str, rtype: str) -> Answer:
        # dns_tools' resolver is synchronous; a worker thread keeps the
        # map's other questions moving while this one waits.
        return await asyncio.to_thread(self._query, norm(name), rtype)

    def _query(self, name: str, rtype: str) -> Answer:
        try:
            result = dns_tools.get_resolver(self._timeout).resolve(
                name, rtype, raise_on_no_answer=False
            )
        except dns.resolver.NXDOMAIN as e:
            return Answer(name, rtype, Status.NXDOMAIN, chain=_nx_chain(e, name))
        except dns.resolver.NoNameservers:  # every server answered SERVFAIL or REFUSED
            return Answer(name, rtype, Status.FAILED, servfail=True)
        except dns.exception.DNSException:  # timeout, network error
            return Answer(name, rtype, Status.FAILED)
        chain = _cname_chain(result.response, name)
        if result.rrset is None:
            return Answer(name, rtype, Status.NOANSWER, chain=chain)
        return Answer(name, rtype, Status.OK, tuple(_text(r) for r in result.rrset), chain)


def map_senders(domain: str, budget_seconds: float) -> Optional[SenderMap]:
    """Sendermap's map of `domain` from DNS alone, or None past the budget.

    DNS only: no website, subdomain or certificate log reads, which would
    reach beyond what an audit fetches. Runs its own event loop, so call it
    from a worker thread, the way the audit runs the fingerprinter.

    Not asyncio.run: on the way out it waits for every question already
    queued on its thread pool, so a map past its budget would keep the
    caller waiting for all of them. This loop's own pool drops what is
    queued and abandons what is in flight, which ends within one
    QUERY_TIMEOUT. Step 2 counts MAP_THREADS into AUDIT_THREAD_CEILING.
    """
    loop = asyncio.new_event_loop()
    pool = ThreadPoolExecutor(max_workers=MAP_THREADS, thread_name_prefix="sendermap")
    loop.set_default_executor(pool)
    task = loop.create_task(map_domain(
        domain,
        checked_at=datetime.now(timezone.utc),
        resolver=AuditResolver(),
        use_web=False,
        use_subdomains=False,
        use_ct=False,
    ))
    try:
        return loop.run_until_complete(asyncio.wait_for(task, timeout=budget_seconds))
    except TimeoutError:
        log.warning("Sender map for %s exceeded its %gs budget", domain, budget_seconds)
    except Exception:
        log.debug("Sender map failed", exc_info=True)
    finally:
        for pending in asyncio.all_tasks(loop):
            pending.cancel()
        loop.run_until_complete(asyncio.sleep(0))
        pool.shutdown(wait=False, cancel_futures=True)
        loop.close()
    return None
