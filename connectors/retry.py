# connectors/retry.py
# Shared policy for a source that is not answering right now: retry a transient
# failure, pace against a rate limit, and tell a refusal apart from an empty
# answer. One module, because those are three branches of the same decision.

import logging
import threading
import time

import requests

from config import VIRUSTOTAL_PER_MINUTE

logger = logging.getLogger(__name__)

# Server-side failures only. A 4xx is the source's considered answer and is
# never retried; a 429 is handled by the pacing and the classification below
# rather than by a short backoff, since retrying into a closed window spends
# what is left of it and still fails.
RETRY_STATUS = {500, 502, 503, 504}


def get_with_retry(url: str, *, timeout: int, attempts: int = 2,
                   backoff: float = 2.0, source: str = "", **kwargs):
    """
    GET that retries a 5xx or a transport fault, returning the last response.

    Exceptions from the final attempt propagate, so each caller decides what an
    exhausted retry means for its own result shape.
    """
    for attempt in range(attempts):
        last = attempt == attempts - 1
        try:
            response = requests.get(url, timeout=timeout, **kwargs)
            if response.status_code in RETRY_STATUS and not last:
                logger.warning(
                    f"{source or url}: HTTP {response.status_code}, "
                    f"retrying in {backoff}s"
                )
                time.sleep(backoff)
                continue
            return response
        except (requests.exceptions.Timeout,
                requests.exceptions.ConnectionError) as e:
            if last:
                raise
            logger.warning(
                f"{source or url}: {type(e).__name__}, retrying in {backoff}s"
            )
            time.sleep(backoff)


# Phrases a source uses when it is refusing rather than failing. "exceeded" is
# deliberately absent: a Playwright timeout reads "Timeout 8000ms exceeded", and
# matching on that alone would file every slow source as rate limited.
QUOTA_MARKERS = (
    "429",
    "too many requests",
    "quota",
    "rate limit",
    "insufficient balance",
)


def is_quota_error(error) -> bool:
    """
    Whether a failure is the source refusing on quota rather than failing.

    The distinction is the whole point. A refusal means the indicator was never
    checked, and an empty answer means it was checked and nothing was found.
    Reporting both as "no data" makes an unchecked indicator indistinguishable
    from a clean one, which is the reading this codebase keeps having to undo.
    """
    text = str(error or "").lower()
    return any(marker in text for marker in QUOTA_MARKERS)


def quota_error(error, indicator: str, source: str) -> dict:
    """
    The error dict a connector returns for a failed lookup.

    Carries `quota_exceeded` only when the source refused, so downstream code
    can separate "we were turned away" from "we asked and got nothing". No
    result fields are included: a refusal has no votes, not zero votes.
    """
    shaped = {"error": str(error), "indicator": indicator, "source": source}
    if is_quota_error(error):
        shaped["quota_exceeded"] = True
    return shaped


class RateLimiter:
    """
    Spaces calls to a source that caps requests per minute.

    Blocks only when a call would breach the spacing, so a chain running well
    under the limit pays nothing. Locked because the executor fans connectors
    out across threads.

    Pacing rather than retrying, for the reason RETRY_STATUS gives above.
    """

    def __init__(self, per_minute: int) -> None:
        self.interval = 60.0 / per_minute if per_minute > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> float:
        """Sleeps if the next call is too soon. Returns the delay it imposed."""
        if not self.interval:
            return 0.0

        with self._lock:
            waited = 0.0
            if self._last:
                waited = self.interval - (time.monotonic() - self._last)
                if waited > 0:
                    time.sleep(waited)
                else:
                    waited = 0.0
            self._last = time.monotonic()
            return waited
