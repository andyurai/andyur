"""One breaker for "the workflow engine is unreachable", shared by every
heartbeat phase that admits runs through it.

WHY ONE. The drain and the schedule phase both admit a run, ask the provider to
start it, and abandon the run as failed when the engine cannot be reached. Each
retries every tick, so an outage turned into a stream of failed runs from
whichever phase had no backoff of its own -- and the drain had one while the
schedules did not. The engine is one dependency; its outage is one state.

WHAT CLOSES IT. Only evidence that the engine answered: a run admitted and
started. A tick that simply had nothing to do says nothing about the engine,
and resetting on it kept a long outage at the minimum wait forever.
"""

import threading
import time

MIN_SECONDS = 30.0
MAX_SECONDS = 300.0


class EngineBreaker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._until = 0.0
        self._backoff = 0.0

    def open_for(self) -> float:
        """Seconds until the engine may be tried again; 0 when it may be now."""
        with self._lock:
            return max(0.0, self._until - time.monotonic())

    def trip(self) -> float:
        """The engine could not be reached. Wait longer than last time, up to
        the cap, and return the wait."""
        with self._lock:
            self._backoff = min(max(self._backoff * 2, MIN_SECONDS), MAX_SECONDS)
            self._until = time.monotonic() + self._backoff
            return self._backoff

    def answered(self) -> None:
        """The engine accepted work, so the next outage starts from the minimum."""
        with self._lock:
            self._backoff = 0.0
            self._until = 0.0

    def reset(self) -> None:
        """For tests: forget any outage."""
        self.answered()


ENGINE = EngineBreaker()
