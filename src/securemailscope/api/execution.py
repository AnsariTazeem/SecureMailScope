"""Bounded thread execution for the deployment's synchronous upload API."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from securemailscope.orchestration import OrchestrationError, OrchestrationErrorCode


class BoundedAnalysisExecution:
    """Admit immediately or reject; retain admission until request cleanup finishes."""

    def __init__(self, max_concurrent: int) -> None:
        if type(max_concurrent) is not int or max_concurrent < 1:
            raise ValueError("analysis concurrency must be a positive integer")
        self._slots = threading.BoundedSemaphore(max_concurrent)

    @contextmanager
    def admit(self) -> Iterator[None]:
        # Admission happens before multipart parsing, so excess requests do not spool.
        if not self._slots.acquire(blocking=False):
            raise OrchestrationError(
                OrchestrationErrorCode.REPOSITORY_CAPACITY,
                "admission",
                "analysis capacity is unavailable",
            )
        try:
            yield
        finally:
            self._slots.release()

    async def run[T](self, operation: Callable[[], T]) -> T:
        """Defer cancellation until the thread stops using its temporary capture.

        asyncio cannot stop a running thread. Shielding alone is insufficient:
        the cancelled caller must also wait before unwinding its file/slot contexts.
        Repeated cancellation is deferred, then propagated after the thread exits.
        """
        task = asyncio.create_task(asyncio.to_thread(operation))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError as cancellation:
            completion = asyncio.gather(task, return_exceptions=True)
            while not completion.done():
                try:
                    await asyncio.shield(completion)
                except asyncio.CancelledError:
                    # Continue waiting for cleanup safety, never abandon the worker.
                    continue
            outcome = completion.result()[0]
            if isinstance(outcome, BaseException):
                raise cancellation from outcome
            raise cancellation
