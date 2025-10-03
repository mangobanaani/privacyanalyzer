"""Email file processing for .eml and .msg files."""

import email
import email.policy
from email import message_from_bytes, message_from_file
from pathlib import Path
from typing import List, Tuple, Dict
import re

from src.utils import get_logger

logger = get_logger(__name__)


class EmailProcessor:
    """Extract text and metadata from email files."""

    def __init__(self):
        """Initialize email processor."""
        self.policy = email.policy.default

    def process_eml(self, file_path: str) -> List[Tuple[str, dict]]:
        """
        Process .eml file.

        Args:
            file_path: Path to .eml file

        Returns:
            List of (text, metadata) tuples
        """
        try:
            with open(file_path, "rb") as f:
                msg = message_from_bytes(f.read(), policy=self.policy)

            return self._extract_email_content(msg, file_path)

        except Exception as e:
            logger.error(f"Error processing EML file: {e}")
            raise

    def process_msg(self, file_path: str) -> List[Tuple[str, dict]]:
        """
        Process .msg file (Outlook).

        Args:
            file_path: Path to .msg file

        Returns:
            List of (text, metadata) tuples
        """
        try:
            # Try using extract_msg library if available
            try:
                import extract_msg

                msg = extract_msg.Message(file_path)

                text_parts = []
                metadata = {
                    "source": Path(file_path).name,
                    "from": msg.sender,
                    "to": msg.to,
                    "subject": msg.subject,
                    "date": str(msg.date) if msg.date else None,
                    "type": "msg",
                }

                # Body
                if msg.body:
                    text_parts.append(f"Subject: {msg.subject}\n")
                    text_parts.append(f"From: {msg.sender}\n")
                    text_parts.append(f"To: {msg.to}\n")
                    text_parts.append(f"\n{msg.body}")

                # Attachments metadata
                if msg.attachments:
                    metadata["attachments"] = [att.longFilename for att in msg.attachments]

                msg.close()

                full_text = "\n".join(text_parts)
                return [(full_text, metadata)]

            except ImportError:
                logger.warning(
                    "extract_msg not installed. Install with: pip install extract-msg"
                )
                # Fallback: try to read as text
                with open(file_path, "rb") as f:
                    content = f.read()
                    # Try to decode
                    try:
                        text = content.decode("utf-8", errors="ignore")
                    except:
                        text = content.decode("latin-1", errors="ignore")

                metadata = {
                    "source": Path(file_path).name,
                    "type": "msg",
                    "note": "Partial extraction - install extract_msg for full support",
                }

                return [(text, metadata)]

        except Exception as e:
            logger.error(f"Error processing MSG file: {e}")
            raise

    def _extract_email_content(
        self, msg: email.message.EmailMessage, file_path: str
    ) -> List[Tuple[str, dict]]:
        """
        Extract content from email message.

        Args:
            msg: Email message object
            file_path: Source file path

        Returns:
            List of (text, metadata) tuples
        """
        results = []

        # Extract metadata
        metadata = {
            "source": Path(file_path).name,
            "from": msg.get("From", ""),
            "to": msg.get("To", ""),
            "cc": msg.get("Cc", ""),
            "subject": msg.get("Subject", ""),
            "date": msg.get("Date", ""),
            "type": "eml",
        }

        # Extract body text
        text_parts = []

        # Add headers to text for PII detection
        text_parts.append(f"From: {metadata['from']}")
        text_parts.append(f"To: {metadata['to']}")
        if metadata["cc"]:
            text_parts.append(f"Cc: {metadata['cc']}")
        text_parts.append(f"Subject: {metadata['subject']}")
        text_parts.append("")

        # Get email body
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # Skip attachments
                if "attachment" in content_disposition:
                    continue

                # Extract text/plain and text/html
                if content_type == "text/plain":
                    try:
                        body = part.get_content()
                        text_parts.append(body)
                    except Exception as e:
                        logger.warning(f"Could not extract text part: {e}")

                elif content_type == "text/html":
                    try:
                        html_body = part.get_content()
                        # Basic HTML stripping
                        text = self._strip_html(html_body)
                        text_parts.append(text)
                    except Exception as e:
                        logger.warning(f"Could not extract HTML part: {e}")
        else:
            # Not multipart - just get the content
            try:
                body = msg.get_content()
                if isinstance(body, str):
                    text_parts.append(body)
            except Exception as e:
                logger.warning(f"Could not extract body: {e}")

        full_text = "\n".join(text_parts)

        # Extract attachment names for metadata
        attachments = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == "attachment":
                    filename = part.get_filename()
                    if filename:
                        attachments.append(filename)

        if attachments:
            metadata["attachments"] = attachments

        results.append((full_text, metadata))
        return results

    def _strip_html(self, html: str) -> str:
        """
        Simple HTML tag stripping.

        Args:
            html: HTML content

        Returns:
            Plain text
        """
        # Remove HTML tags
        text = re.sub(r"<[^>]+>", " ", html)

        # Remove extra whitespace
        text = re.sub(r"\s+", " ", text)

        # Decode HTML entities
        try:
            import html as html_lib

            text = html_lib.unescape(text)
        except:
            pass

        return text.strip()
