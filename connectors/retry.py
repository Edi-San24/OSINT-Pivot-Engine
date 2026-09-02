# connectors/retry.py
# Shared retry for the sources that fail transiently rather than permanently.

import logging
import time

import requests

logger = logging.getLogger(__name__)

# Only 5xx. A 4xx is the source's answer and must never be retried: the Censys
# 422 that was diagnosed as an API change was a spent balance, and retrying it
# would have buried the body that said so. 429 is left out too, since a rate
# limit needs a quota strategy rather than a two-second backoff.
RETRY_STATUS = {500, 502, 503, 504}


def get_with_retry(url: str, *, timeout: int, attempts: int = 2,
                   backoff: float = 2.0, source: str = "", **kwargs):
    """
    GET that retries a 5xx or a transport fault, and returns the last response.

    Exceptions from the final attempt are re-raised rather than swallowed, so
    each caller keeps deciding what an exhausted retry means for its own result
    shape.
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
