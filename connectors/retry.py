# connectors/retry.py
# Shared HTTP retry for sources that fail transiently.

import logging
import time

import requests

logger = logging.getLogger(__name__)

# Server-side failures only. A 4xx is the source's considered answer and is
# never retried; 429 is excluded because a rate limit needs a quota strategy
# rather than a short backoff.
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
