# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""A tiny in-process pub/sub bus so every open role window stays in sync.

When one window causes a ledger change (a report lands, a disclosure is
released), the server publishes an event and every connected browser receives
it over its WebSocket, without polling.
"""

import asyncio
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    async def publish(self, kind: str, **data: Any) -> None:
        event = {"kind": kind, **data}
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # a stalled subscriber must not block the publisher
