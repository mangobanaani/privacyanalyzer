"""Web page processing and content extraction."""

import re
from typing import List, Tuple, Dict, Optional
from urllib.parse import urljoin, urlparse
from urllib import robotparser
import requests
from bs4 import BeautifulSoup

from src.utils import get_logger

logger = get_logger(__name__)


class WebProcessor:
    """Extract content and analyze web pages."""

    def __init__(
        self,
        user_agent: str = "PrivacyAnalyzer/1.0",
        timeout: int = 10,
        follow_links: bool = False,
        max_pages: int = 10,
        respect_robots_txt: bool = True,
    ):
        """
        Initialize web processor.

        Args:
            user_agent: User agent string
            timeout: Request timeout in seconds
            follow_links: Whether to follow internal links
            max_pages: Maximum pages to scan per site
            respect_robots_txt: Whether to respect robots.txt
        """
        self.user_agent = user_agent
        self.timeout = timeout
        self.follow_links = follow_links
        self.max_pages = max_pages
        self.respect_robots_txt = respect_robots_txt
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.robots_parsers = {}  # Cache robots.txt parsers per domain

    def process(self, url: str) -> List[Tuple[str, dict]]:
        """
        Process a web page and extract content.

        Args:
            url: URL to process

        Returns:
            List of (text, metadata) tuples
        """
        results = []
        visited = set()
        to_visit = [url]
        base_domain = urlparse(url).netloc

        while to_visit and len(visited) < self.max_pages:
            current_url = to_visit.pop(0)

            if current_url in visited:
                continue

            try:
                page_result = self._process_single_page(current_url)
                if page_result:
                    text, metadata = page_result
                    results.append((text, metadata))
                    visited.add(current_url)

                    # Extract links if following
                    if self.follow_links and len(visited) < self.max_pages:
                        links = self._extract_links(text, current_url, base_domain)
                        for link in links:
                            if link not in visited and link not in to_visit:
                                to_visit.append(link)

            except Exception as e:
                logger.warning(f"Failed to process {current_url}: {e}")
                continue

        logger.info(f"Processed {len(visited)} pages from {url}")
        return results

    def _can_fetch(self, url: str) -> bool:
        """
        Check if URL can be fetched according to robots.txt.

        Args:
            url: URL to check

        Returns:
            True if allowed to fetch
        """
        if not self.respect_robots_txt:
            return True

        parsed = urlparse(url)
        domain = parsed.netloc

        # Get or create robots parser for this domain
        if domain not in self.robots_parsers:
            robots_url = f"{parsed.scheme}://{domain}/robots.txt"
            parser = robotparser.RobotFileParser()
            parser.set_url(robots_url)

            try:
                parser.read()
                self.robots_parsers[domain] = parser
            except Exception as e:
                logger.debug(f"Could not read robots.txt for {domain}: {e}")
                # If robots.txt unavailable, allow crawling
                return True

        parser = self.robots_parsers[domain]
        can_fetch = parser.can_fetch(self.user_agent, url)

        if not can_fetch:
            logger.info(f"Skipping {url} (disallowed by robots.txt)")

        return can_fetch

    def _process_single_page(self, url: str) -> Optional[Tuple[str, dict]]:
        """
        Process a single web page.

        Args:
            url: Page URL

        Returns:
            (text, metadata) tuple or None
        """
        # Check robots.txt
        if not self._can_fetch(url):
            return None

        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            response.raise_for_status()

            # Check content type
            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                logger.debug(f"Skipping non-HTML content: {content_type}")
                return None

            soup = BeautifulSoup(response.content, "lxml")

            # Extract text content
            text = self._extract_text(soup)

            # Extract metadata
            metadata = {
                "source": url,
                "title": soup.title.string if soup.title else "",
                "status_code": response.status_code,
                "content_type": content_type,
                "cookies": self._analyze_cookies(response.cookies),
                "forms": self._analyze_forms(soup),
                "links_count": len(soup.find_all("a")),
                "has_privacy_policy": self._has_privacy_policy(soup),
                "security": self._check_security(response, url),
            }

            return (text, metadata)

        except requests.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            return None

    def _extract_text(self, soup: BeautifulSoup) -> str:
        """
        Extract readable text from HTML.

        Args:
            soup: BeautifulSoup object

        Returns:
            Extracted text
        """
        # Remove script and style elements
        for script in soup(["script", "style", "noscript"]):
            script.decompose()

        # Get text
        text = soup.get_text(separator="\n")

        # Clean up whitespace
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = "\n".join(chunk for chunk in chunks if chunk)

        return text

    def _extract_links(self, text: str, base_url: str, base_domain: str) -> List[str]:
        """
        Extract internal links from page.

        Args:
            text: Page HTML
            base_url: Current page URL
            base_domain: Base domain to filter

        Returns:
            List of internal URLs
        """
        soup = BeautifulSoup(text, "lxml")
        links = []

        for a in soup.find_all("a", href=True):
            href = a["href"]
            absolute_url = urljoin(base_url, href)

            # Only include internal links
            if urlparse(absolute_url).netloc == base_domain:
                links.append(absolute_url)

        return links

    def _analyze_cookies(self, cookies) -> Dict:
        """
        Analyze cookies set by the page.

        Args:
            cookies: Response cookies

        Returns:
            Cookie analysis
        """
        analysis = {
            "total_count": len(cookies),
            "has_cookies": len(cookies) > 0,
            "types": [],
        }

        for cookie in cookies:
            cookie_info = {
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "samesite": cookie.get_nonstandard_attr("SameSite"),
            }

            # Classify cookie type
            name_lower = cookie.name.lower()
            if any(x in name_lower for x in ["analytics", "ga", "_ga", "_gid"]):
                cookie_info["type"] = "analytics"
            elif any(x in name_lower for x in ["ad", "doubleclick", "fbp"]):
                cookie_info["type"] = "advertising"
            elif any(x in name_lower for x in ["session", "sess", "auth"]):
                cookie_info["type"] = "functional"
            else:
                cookie_info["type"] = "unknown"

            analysis["types"].append(cookie_info)

        return analysis

    def _analyze_forms(self, soup: BeautifulSoup) -> List[Dict]:
        """
        Analyze forms for PII collection.

        Args:
            soup: BeautifulSoup object

        Returns:
            List of form analyses
        """
        forms = []

        for form in soup.find_all("form"):
            form_data = {
                "action": form.get("action", ""),
                "method": form.get("method", "get").upper(),
                "inputs": [],
                "collects_pii": False,
            }

            # PII-related input names/types
            pii_indicators = {
                "email",
                "phone",
                "name",
                "address",
                "ssn",
                "dob",
                "birth",
                "credit",
                "card",
                "passport",
            }

            for input_field in form.find_all(["input", "textarea", "select"]):
                name = input_field.get("name", "")
                input_type = input_field.get("type", "text")
                placeholder = input_field.get("placeholder", "")

                input_info = {
                    "name": name,
                    "type": input_type,
                    "placeholder": placeholder,
                }

                # Check if potentially collecting PII
                name_lower = name.lower()
                placeholder_lower = placeholder.lower()

                if any(indicator in name_lower for indicator in pii_indicators) or any(
                    indicator in placeholder_lower for indicator in pii_indicators
                ):
                    input_info["may_collect_pii"] = True
                    form_data["collects_pii"] = True
                else:
                    input_info["may_collect_pii"] = False

                form_data["inputs"].append(input_info)

            forms.append(form_data)

        return forms

    def _has_privacy_policy(self, soup: BeautifulSoup) -> bool:
        """
        Check if page has link to privacy policy.

        Args:
            soup: BeautifulSoup object

        Returns:
            True if privacy policy link found
        """
        privacy_keywords = ["privacy", "policy", "privacy policy", "data protection"]

        for a in soup.find_all("a", href=True):
            text = a.get_text().lower()
            href = a["href"].lower()

            if any(keyword in text or keyword in href for keyword in privacy_keywords):
                return True

        return False

    def _check_security(self, response, url: str) -> Dict:
        """
        Check security headers and HTTPS usage.

        Args:
            response: Response object
            url: Request URL

        Returns:
            Security analysis
        """
        headers = response.headers

        security = {
            "uses_https": url.startswith("https://"),
            "headers": {
                "strict_transport_security": "Strict-Transport-Security" in headers,
                "content_security_policy": "Content-Security-Policy" in headers,
                "x_frame_options": "X-Frame-Options" in headers,
                "x_content_type_options": "X-Content-Type-Options" in headers,
            },
        }

        return security
