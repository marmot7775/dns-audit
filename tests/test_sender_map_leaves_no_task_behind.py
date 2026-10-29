"""map_senders closes its event loop with no task still pending.

Two maps run at once and the first to finish is the answer, so the other is
cancelled on almost every audit. The loop used to be closed one step after
the cancel, before it reached tasks nested inside gathers. asyncio then
logged "Task was destroyed but it is pending!" and "_GatheringFuture
exception was never retrieved" at error level, and Sentry filed them as 17
issues and several hundred events in a day of production.
"""
import asyncio
import gc
import logging

import sendermap_adapter


async def _nested_wait(seconds, depth=4):
    """Gathers inside gathers, as Sendermap's sources nest them. Each level
    takes the loop one more step to hear about a cancel."""
    if depth == 0:
        await asyncio.sleep(seconds)
        return
    await asyncio.gather(_nested_wait(seconds, depth - 1), _nested_wait(seconds, depth - 1))


def _fake_map(domain, *, use_subdomains, **_):
    async def run():
        if use_subdomains:
            return "map"
        await _nested_wait(30)
    return run()


def test_cancelled_map_logs_nothing(monkeypatch, caplog):
    monkeypatch.setattr(sendermap_adapter, "map_domain", _fake_map)
    caplog.set_level(logging.ERROR, logger="asyncio")
    assert sendermap_adapter.map_senders("example.com", 5) == "map"
    gc.collect()
    assert not [r for r in caplog.records if r.name == "asyncio"], caplog.text


def test_map_past_its_budget_logs_nothing(monkeypatch, caplog):
    async def slow():
        await _nested_wait(30)
    monkeypatch.setattr(sendermap_adapter, "map_domain", lambda *a, **k: slow())
    caplog.set_level(logging.ERROR, logger="asyncio")
    assert sendermap_adapter.map_senders("example.com", 0.05) is None
    gc.collect()
    assert not [r for r in caplog.records if r.name == "asyncio"], caplog.text
