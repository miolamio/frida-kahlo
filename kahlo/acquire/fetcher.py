"""APK Fetcher — download APKs from mirror sites using Playwright with stealth."""
from __future__ import annotations

import asyncio
import logging
import os
import re
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)


class APKFetcherError(Exception):
    pass


class APKFetcher:
    """Downloads APK from APKPure/APKCombo using headless Playwright with stealth."""

    def __init__(self, headless: bool = True, timeout: int = 60000):
        self.headless = headless
        self.timeout = timeout

    async def fetch(self, query: str, output_dir: str | None = None) -> str | None:
        """Search and download APK.

        Args:
            query: App name to search for (e.g. "yakitoriya").
            output_dir: Directory to save downloaded APK. Defaults to temp dir.

        Returns:
            Path to downloaded file, or None if all sources failed.
        """
        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix="kahlo_fetch_")
        os.makedirs(output_dir, exist_ok=True)

        # Try sources in order
        for source_fn in [self._try_apkpure, self._try_apkcombo]:
            try:
                path = await source_fn(query, output_dir)
                if path and os.path.exists(path) and os.path.getsize(path) > 100_000:
                    logger.info("Downloaded APK: %s", path)
                    return path
            except Exception as e:
                logger.warning("Source failed: %s — %s", source_fn.__name__, e)
                continue

        logger.error("All sources failed for query: %s", query)
        return None

    async def _try_apkpure(self, query: str, output_dir: str) -> str | None:
        """Try downloading from APKPure."""
        try:
            from playwright.async_api import async_playwright
            from playwright_stealth import stealth_async
        except ImportError:
            logger.warning("playwright or playwright-stealth not installed")
            return None

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                viewport={"width": 1920, "height": 1080},
            )
            page = await context.new_page()
            await stealth_async(page)

            try:
                # Search
                search_url = f"https://apkpure.com/search?q={query}"
                logger.info("APKPure search: %s", search_url)
                await page.goto(search_url, wait_until="domcontentloaded", timeout=self.timeout)
                await page.wait_for_timeout(2000)

                # Find first result
                first_result = await page.query_selector("a.first-info")
                if not first_result:
                    first_result = await page.query_selector(".search-title a")
                if not first_result:
                    first_result = await page.query_selector("a[href*='/apk/']")

                if not first_result:
                    logger.warning("APKPure: no search results for %s", query)
                    return None

                href = await first_result.get_attribute("href")
                if not href:
                    return None

                # Navigate to app page
                if not href.startswith("http"):
                    href = f"https://apkpure.com{href}"
                logger.info("APKPure app page: %s", href)
                await page.goto(href, wait_until="domcontentloaded", timeout=self.timeout)
                await page.wait_for_timeout(2000)

                # Find download button
                download_btn = await page.query_selector("a.download-start-btn")
                if not download_btn:
                    download_btn = await page.query_selector("a[href*='/download']")
                if not download_btn:
                    download_btn = await page.query_selector(".download-btn a")

                if not download_btn:
                    logger.warning("APKPure: no download button found")
                    return None

                # Try to download
                download_href = await download_btn.get_attribute("href")
                if download_href and not download_href.startswith("http"):
                    download_href = f"https://apkpure.com{download_href}"

                # Navigate to download page
                if download_href:
                    await page.goto(download_href, wait_until="domcontentloaded", timeout=self.timeout)
                    await page.wait_for_timeout(2000)

                # Look for the actual download link and try to catch the download
                async with page.expect_download(timeout=self.timeout) as download_info:
                    # Click the main download trigger
                    dl_trigger = await page.query_selector("a#download_link")
                    if not dl_trigger:
                        dl_trigger = await page.query_selector("a.ga-click[data-dt-file_name]")
                    if not dl_trigger:
                        dl_trigger = await page.query_selector("a[href*='.apk'], a[href*='.xapk']")
                    if dl_trigger:
                        await dl_trigger.click()
                    else:
                        return None

                download = await download_info.value
                # Save downloaded file
                filename = download.suggested_filename or f"{query}.apk"
                save_path = os.path.join(output_dir, filename)
                await download.save_as(save_path)
                logger.info("APKPure download saved: %s", save_path)
                return save_path

            except Exception as e:
                logger.warning("APKPure error: %s", e)
                return None
            finally:
                await browser.close()

    async def _try_apkcombo(self, query: str, output_dir: str) -> str | None:
        """Try downloading from APKCombo."""
        try:
            from playwright.async_api import async_playwright
            from playwright_stealth import stealth_async
        except ImportError:
            logger.warning("playwright or playwright-stealth not installed")
            return None

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                viewport={"width": 1920, "height": 1080},
            )
            page = await context.new_page()
            await stealth_async(page)

            try:
                search_url = f"https://apkcombo.com/search/{query}"
                logger.info("APKCombo search: %s", search_url)
                await page.goto(search_url, wait_until="domcontentloaded", timeout=self.timeout)
                await page.wait_for_timeout(2000)

                # Find first result
                first_result = await page.query_selector("a.content")
                if not first_result:
                    first_result = await page.query_selector(".list-app a[href*='/apk/']")
                if not first_result:
                    first_result = await page.query_selector("a[href*='/apk/']")

                if not first_result:
                    logger.warning("APKCombo: no search results for %s", query)
                    return None

                href = await first_result.get_attribute("href")
                if not href:
                    return None

                if not href.startswith("http"):
                    href = f"https://apkcombo.com{href}"

                # Navigate to app page
                logger.info("APKCombo app page: %s", href)
                await page.goto(href, wait_until="domcontentloaded", timeout=self.timeout)
                await page.wait_for_timeout(2000)

                # Find download link
                download_link = await page.query_selector("a.variant[href*='/download/']")
                if not download_link:
                    download_link = await page.query_selector("a[href*='/download/']")

                if not download_link:
                    logger.warning("APKCombo: no download link found")
                    return None

                dl_href = await download_link.get_attribute("href")
                if dl_href and not dl_href.startswith("http"):
                    dl_href = f"https://apkcombo.com{dl_href}"

                # Navigate to download page
                if dl_href:
                    await page.goto(dl_href, wait_until="domcontentloaded", timeout=self.timeout)
                    await page.wait_for_timeout(3000)

                # Try to catch the download
                async with page.expect_download(timeout=self.timeout) as download_info:
                    dl_btn = await page.query_selector("a.file-list__button--download")
                    if not dl_btn:
                        dl_btn = await page.query_selector("a[href*='.apk'], a[href*='.xapk']")
                    if dl_btn:
                        await dl_btn.click()
                    else:
                        return None

                download = await download_info.value
                filename = download.suggested_filename or f"{query}.apk"
                save_path = os.path.join(output_dir, filename)
                await download.save_as(save_path)
                logger.info("APKCombo download saved: %s", save_path)
                return save_path

            except Exception as e:
                logger.warning("APKCombo error: %s", e)
                return None
            finally:
                await browser.close()

    def fetch_sync(self, query: str, output_dir: str | None = None) -> str | None:
        """Synchronous wrapper for fetch()."""
        return asyncio.run(self.fetch(query, output_dir))
