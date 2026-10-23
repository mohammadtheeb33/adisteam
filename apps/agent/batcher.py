"""Sender: drains the spool to the ingestion API in batches.

Events leave the spool only when the server has acknowledged them, or when the server
rejected them permanently, in which case they are quarantined with the reason. Every
other failure keeps them queued and retries with exponential backoff, indefinitely.

| Outcome | Action |
|---|---|
| delivered | acknowledge accepted events; quarantine per-event rejections |
| rejected (422) | quarantine the rejected events |
| too large (413) / malformed (400) | halve the batch; quarantine a single failing event |
| rate limited (429) | wait ``Retry-After`` |
| unauthorized / misconfigured | keep everything, back off, log an error |
| unavailable (5xx, network, timeout) | keep everything, back off |
"""

import asyncio
import logging
from collections.abc import Sequence

from apps.agent.backoff import Backoff
from apps.agent.client import IngestSender, Outcome, SendResult
from apps.agent.spool import Spool, SpooledEvent

logger = logging.getLogger(__name__)


class Batcher:
    """Sends spooled events every ``flush_interval_seconds``, or as soon as a batch fills."""

    def __init__(
        self,
        spool: Spool,
        client: IngestSender,
        *,
        batch_size: int,
        flush_interval_seconds: float,
        backoff: Backoff,
        wake: asyncio.Event | None = None,
    ) -> None:
        self._spool = spool
        self._client = client
        self._configured_batch_size = batch_size
        self._batch_size = batch_size
        self._flush_interval = flush_interval_seconds
        self._backoff = backoff
        self._wake = wake or asyncio.Event()

    @property
    def wake(self) -> asyncio.Event:
        """Set to request an immediate flush (e.g. when a full batch is queued)."""
        return self._wake

    @property
    def batch_size(self) -> int:
        """Current batch size (reduced after ``413`` responses)."""
        return self._batch_size

    async def run(self, stop: asyncio.Event) -> None:
        """Flush repeatedly until ``stop`` is set."""
        while not stop.is_set():
            delay, backing_off = await self.flush()
            await self._pause(stop, delay, interruptible=not backing_off)

    async def flush(self) -> tuple[float, bool]:
        """Send until the spool is drained or a request fails.

        Returns:
            How long to wait before the next flush, and whether that wait is a backoff
            (during which queue growth must not trigger an early retry).
        """
        while True:
            records = await self._spool.peek(self._batch_size)
            if not records:
                self._backoff.reset()
                return self._flush_interval, False
            result = await self._client.send_batch([record.payload for record in records])
            wait = await self._handle(records, result)
            if wait is not None:
                return wait, True

    async def _handle(self, records: Sequence[SpooledEvent], result: SendResult) -> float | None:
        """Apply a result; returns a backoff delay, or ``None`` to continue sending."""
        match result.outcome:
            case Outcome.DELIVERED | Outcome.REJECTED:
                if await self._settle(records, result):
                    self._backoff.reset()
                    return None
                # Some events were neither accepted nor rejected; resending them at once
                # could loop, so treat the batch as a transient failure.
                return self._backoff.next_delay()
            case Outcome.TOO_LARGE | Outcome.MALFORMED:
                await self._isolate(records, result)
                return None
            case Outcome.RATE_LIMITED:
                if result.retry_after is not None:
                    return result.retry_after
                return self._backoff.next_delay()
            case Outcome.UNAUTHORIZED | Outcome.MISCONFIGURED:
                delay = self._backoff.next_delay()
                logger.error(
                    "ingestion API refused the agent; events are kept",
                    extra={
                        "action": "agent_send_refused",
                        "status_code": result.status,
                        "error_code": result.code,
                        "retry_in_ms": round(delay * 1000),
                        "request_id": result.request_id,
                    },
                )
                return delay
            case Outcome.UNAVAILABLE:
                delay = result.retry_after or self._backoff.next_delay()
                logger.warning(
                    "ingestion API unavailable; events are kept",
                    extra={
                        "action": "agent_send_retry",
                        "status_code": result.status,
                        "detail": result.detail,
                        "attempt": self._backoff.failures,
                        "retry_in_ms": round(delay * 1000),
                        "request_id": result.request_id,
                    },
                )
                return delay

    async def _settle(self, records: Sequence[SpooledEvent], result: SendResult) -> bool:
        """Acknowledge and quarantine per ``result``; ``False`` if events stay unresolved."""
        accepted = [records[index].seq for index in result.accepted if index < len(records)]
        rejected = {
            records[index].seq: reason
            for index, reason in result.rejected.items()
            if index < len(records) and index not in result.accepted
        }
        await self._spool.acknowledge(accepted)
        if rejected:
            await self._quarantine(rejected, result)
        unresolved = len(records) - len(accepted) - len(rejected)
        if unresolved:
            logger.warning(
                "server reported neither acceptance nor rejection; events stay queued",
                extra={"action": "agent_send_unresolved", "events": unresolved},
            )
        if accepted:
            logger.debug(
                "events delivered",
                extra={"action": "agent_events_delivered", "events": len(accepted)},
            )
        return unresolved == 0

    async def _isolate(self, records: Sequence[SpooledEvent], result: SendResult) -> None:
        if len(records) > 1:
            self._batch_size = max(1, len(records) // 2)
            logger.warning(
                "request refused as too large or malformed; halving the batch",
                extra={
                    "action": "agent_batch_split",
                    "status_code": result.status,
                    "batch_size": self._batch_size,
                },
            )
            return
        await self._quarantine({records[0].seq: result.code or result.detail}, result)
        if self._batch_size != self._configured_batch_size:
            # The culprit is isolated and gone: the rest goes out in full batches again,
            # not one request per event (a too-large batch is halved again if needed).
            self._batch_size = self._configured_batch_size
            logger.info(
                "offending event quarantined; batch size restored",
                extra={"action": "agent_batch_restored", "batch_size": self._batch_size},
            )

    async def _quarantine(self, reasons: dict[int, str], result: SendResult) -> None:
        outcome = await self._spool.quarantine(reasons)
        logger.error(
            "events permanently rejected by the server were quarantined",
            extra={
                "action": "agent_events_quarantined",
                "events": outcome.moved,
                "status_code": result.status,
                "request_id": result.request_id,
            },
        )
        if outcome.evicted:
            logger.error(
                "quarantine full: oldest quarantined events were evicted",
                extra={"action": "agent_quarantine_evicted", "events": outcome.evicted},
            )

    async def _pause(self, stop: asyncio.Event, delay: float, *, interruptible: bool) -> None:
        waiters = [asyncio.ensure_future(stop.wait())]
        if interruptible:
            waiters.append(asyncio.ensure_future(self._wake.wait()))
        try:
            await asyncio.wait(waiters, timeout=delay, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for waiter in waiters:
                waiter.cancel()
            self._wake.clear()
