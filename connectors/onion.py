# connectors/onion.py
# Dark web search connector for the OSINT Pivot Engine.

import logging
import urllib.parse
from playwright.sync_api import sync_playwright
from config import MAX_RESULTS_PER_SOURCE

logger = logging.getLogger(__name__)

class OnionConnector:
    """
    Dark web search connector using Playwright headless browser.
    Queries Ahmia dark web search engine with full JavaScript execution.
    """

    def __init__(self):
        pass

    def search(self, indicator: str) -> dict:
        """
        Searches Ahmia for dark web references to an indicator.
        Uses headless Chromium to execute JavaScript and parse results.
        """
        logger.info(f"Searching dark web indexes for: {indicator[:50]}")

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()

                page.goto("https://ahmia.fi/", wait_until="networkidle", timeout=30000)
                page.fill("input#id_q", indicator)
                page.press("input#id_q", "Enter")
                page.wait_for_load_state("networkidle", timeout=30000)


                results = []
                items = page.query_selector_all("li.result")[:MAX_RESULTS_PER_SOURCE]

                for item in items:
                    title_el = item.query_selector("h4")
                    link_el = item.query_selector("a")
                    snippet_el = item.query_selector("p")

                    title = title_el.inner_text() if title_el else "unknown"
                    raw_link = link_el.get_attribute("href") if link_el else ""
                    snippet = snippet_el.inner_text() if snippet_el else "unknown"

                    onion_url = "unknown"
                    if "redirect_url=" in raw_link:
                        parsed = urllib.parse.urlparse(raw_link)
                        params = urllib.parse.parse_qs(parsed.query)
                        onion_url = params.get("redirect_url", ["unknown"])[0]

                    if ".onion" in onion_url:
                        results.append({
                            "title": title.strip(),
                            "onion_url": onion_url,
                            "snippet": snippet.strip(),
                            "engine": "ahmia"
                        })

                browser.close()

                return {
                    "indicator": indicator,
                    "source": "dark_web_search",
                    "result_count": len(results),
                    "results": results
                }

        except Exception as e:
            return {"error": str(e), "indicator": indicator, "source": "dark_web_search"}