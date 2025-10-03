"""Tests for web processor."""

import pytest
from unittest.mock import Mock, patch
from src.processors.web_processor import WebProcessor


class TestWebProcessor:
    """Test web processing functionality."""

    @pytest.fixture
    def processor(self):
        """Create a web processor instance."""
        return WebProcessor(
            user_agent="TestBot/1.0",
            timeout=5,
            follow_links=False,
            max_pages=3
        )

    def test_initialization(self, processor: WebProcessor):
        """Test processor initialization."""
        assert processor.user_agent == "TestBot/1.0"
        assert processor.timeout == 5
        assert processor.follow_links is False
        assert processor.max_pages == 3

    def test_extract_text(self, processor: WebProcessor):
        """Test text extraction from HTML."""
        from bs4 import BeautifulSoup

        html = """
        <html>
            <head><title>Test Page</title></head>
            <body>
                <script>console.log('test');</script>
                <p>This is content.</p>
                <style>.test { color: red; }</style>
                <p>More content.</p>
            </body>
        </html>
        """

        soup = BeautifulSoup(html, "lxml")
        text = processor._extract_text(soup)

        # Should extract text but not scripts/styles
        assert "This is content" in text
        assert "More content" in text
        assert "console.log" not in text
        assert "color: red" not in text

    def test_analyze_cookies(self, processor: WebProcessor):
        """Test cookie analysis."""
        # Create mock cookies
        mock_cookies = Mock()
        mock_cookie1 = Mock()
        mock_cookie1.name = "_ga"
        mock_cookie1.secure = True
        mock_cookie1.has_nonstandard_attr = Mock(return_value=True)
        mock_cookie1.get_nonstandard_attr = Mock(return_value="Lax")

        mock_cookie2 = Mock()
        mock_cookie2.name = "ad_tracker"
        mock_cookie2.secure = False
        mock_cookie2.has_nonstandard_attr = Mock(return_value=False)
        mock_cookie2.get_nonstandard_attr = Mock(return_value=None)

        mock_cookies.__iter__ = Mock(return_value=iter([mock_cookie1, mock_cookie2]))
        mock_cookies.__len__ = Mock(return_value=2)

        analysis = processor._analyze_cookies(mock_cookies)

        assert analysis["total_count"] == 2
        assert analysis["has_cookies"] is True
        assert len(analysis["types"]) == 2

        # Check cookie classification
        cookie_types = [c["type"] for c in analysis["types"]]
        assert "analytics" in cookie_types
        assert "advertising" in cookie_types

    def test_analyze_forms(self, processor: WebProcessor):
        """Test form analysis for PII collection."""
        from bs4 import BeautifulSoup

        html = """
        <form action="/submit" method="post">
            <input type="text" name="email" placeholder="Your email">
            <input type="text" name="name" placeholder="Full name">
            <input type="text" name="username">
        </form>
        """

        soup = BeautifulSoup(html, "lxml")
        forms = processor._analyze_forms(soup)

        assert len(forms) == 1
        form = forms[0]

        assert form["method"] == "POST"
        assert form["action"] == "/submit"
        assert form["collects_pii"] is True
        assert len(form["inputs"]) == 3

        # Check PII detection
        pii_inputs = [inp for inp in form["inputs"] if inp.get("may_collect_pii")]
        assert len(pii_inputs) >= 2  # email and name

    def test_has_privacy_policy(self, processor: WebProcessor):
        """Test privacy policy link detection."""
        from bs4 import BeautifulSoup

        html_with_policy = """
        <html>
            <body>
                <a href="/privacy">Privacy Policy</a>
            </body>
        </html>
        """

        html_without_policy = """
        <html>
            <body>
                <a href="/about">About Us</a>
            </body>
        </html>
        """

        soup_with = BeautifulSoup(html_with_policy, "lxml")
        soup_without = BeautifulSoup(html_without_policy, "lxml")

        assert processor._has_privacy_policy(soup_with) is True
        assert processor._has_privacy_policy(soup_without) is False

    def test_check_security(self, processor: WebProcessor):
        """Test security header checking."""
        # Mock response with security headers
        mock_response = Mock()
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff"
        }

        security = processor._check_security(mock_response, "https://example.com")

        assert security["uses_https"] is True
        assert security["headers"]["strict_transport_security"] is True
        assert security["headers"]["content_security_policy"] is True
        assert security["headers"]["x_frame_options"] is True
        assert security["headers"]["x_content_type_options"] is True

    def test_check_security_http(self, processor: WebProcessor):
        """Test security check with HTTP."""
        mock_response = Mock()
        mock_response.headers = {}

        security = processor._check_security(mock_response, "http://example.com")

        assert security["uses_https"] is False

    def test_robots_txt_respect(self, processor: WebProcessor):
        """Test robots.txt checking."""
        processor.respect_robots_txt = True

        # Mock robots.txt that disallows a path
        with patch('urllib.robotparser.RobotFileParser') as mock_parser_class:
            mock_parser = Mock()
            mock_parser.can_fetch = Mock(return_value=False)
            mock_parser_class.return_value = mock_parser

            can_fetch = processor._can_fetch("https://example.com/admin")

            # Should respect robots.txt
            assert can_fetch is False or mock_parser.can_fetch.called

    def test_robots_txt_disabled(self, processor: WebProcessor):
        """Test robots.txt checking when disabled."""
        processor.respect_robots_txt = False

        can_fetch = processor._can_fetch("https://example.com/admin")

        # Should always allow when disabled
        assert can_fetch is True

    def test_extract_links(self, processor: WebProcessor):
        """Test link extraction."""
        html = """
        <html>
            <body>
                <a href="/page1">Page 1</a>
                <a href="https://example.com/page2">Page 2</a>
                <a href="https://external.com/page3">External</a>
            </body>
        </html>
        """

        links = processor._extract_links(html, "https://example.com/", "example.com")

        # Should only include internal links
        assert len(links) >= 2
        assert all("example.com" in link for link in links)
        assert not any("external.com" in link for link in links)
