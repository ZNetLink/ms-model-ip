from __future__ import annotations

from collections import deque
from typing import Deque, Optional

import miaosuan as ms

from .ip_support import PktWithInfo, QueueSystem, register_queue_system


class _FifoQueue(QueueSystem):
    def __init__(self, capacity: int) -> None:
        self._queue: Deque[PktWithInfo] = deque()
        self._capacity = max(0, capacity)

    def enqueue(self, pkt: PktWithInfo) -> None:
        if self.is_full():
            ms.pk_destroy(pkt.pkt)
            return
        self._queue.append(pkt)

    def dequeue(self) -> Optional[PktWithInfo]:
        if self.is_empty():
            return None
        return self._queue.popleft()

    def is_empty(self) -> bool:
        return not self._queue

    def is_full(self) -> bool:
        return self._capacity > 0 and len(self._queue) >= self._capacity

    def length(self) -> int:
        return len(self._queue)

    def capacity(self) -> int:
        return self._capacity


def _register_defaults() -> None:
    register_queue_system("FIFO", lambda: _FifoQueue(100))
    register_queue_system("FIFO(100)", lambda: _FifoQueue(100))
    register_queue_system("FIFO(1000)", lambda: _FifoQueue(1000))


_register_defaults()

