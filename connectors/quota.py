# connectors/quota.py
# Request pacing, and telling a source that refused on quota apart from one
# that failed.

import threading
import time

# VirusTotal's free tier is 4 requests a minute and 500 a day. The minute rate
# is what a pivot chain hits, since every pivot makes one lookup; the daily cap
# is what an evaluation sweep hits. Read from config so a paid key is not stuck
# behind the free tier's spacing.
from config import VIRUSTOTAL_PER_MINUTE

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

    Pacing rather than retrying. A 429 means the window is closed, so retrying
    into it spends what is left of the window and still fails.
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
