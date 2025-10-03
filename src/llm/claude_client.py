"""Claude API client with retry logic and caching."""

import asyncio
import time
from typing import Optional, Dict, Any
import hashlib
import json
from functools import lru_cache

from anthropic import Anthropic, AsyncAnthropic
from anthropic import APIError, RateLimitError, APIConnectionError

from src.models import get_settings
from src.utils import get_logger

logger = get_logger(__name__)


class ClaudeClient:
    """
    Claude API client with retry logic, rate limiting, and caching.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        max_retries: int = 3,
        timeout: int = 60,
    ):
        """
        Initialize Claude client.

        Args:
            api_key: Anthropic API key (or from settings)
            model: Model to use (or from settings)
            max_retries: Maximum retry attempts
            timeout: Request timeout in seconds
        """
        settings = get_settings()

        self.api_key = api_key or settings.anthropic_api_key

        if not self.api_key:
            raise ValueError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY environment variable or pass api_key parameter."
            )

        self.model = model or settings.llm_model
        self.max_retries = max_retries
        self.timeout = timeout

        # Initialize clients
        self.client = Anthropic(api_key=self.api_key, timeout=timeout)
        self.async_client = AsyncAnthropic(api_key=self.api_key, timeout=timeout)

        # Cache for responses (in-memory)
        self._cache: Dict[str, Any] = {}

        # Rate limiting
        self._last_request_time = 0
        self._min_request_interval = 0.1  # 100ms between requests

        logger.info(f"Claude client initialized with model: {self.model}")

    def _generate_cache_key(self, prompt: str, **kwargs) -> str:
        """Generate cache key from prompt and parameters."""
        key_data = {"prompt": prompt, **kwargs}
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_string.encode()).hexdigest()

    async def _rate_limit(self) -> None:
        """Implement rate limiting between requests."""
        current_time = time.time()
        time_since_last_request = current_time - self._last_request_time

        if time_since_last_request < self._min_request_interval:
            await asyncio.sleep(self._min_request_interval - time_since_last_request)

        self._last_request_time = time.time()

    async def complete(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        use_cache: bool = True,
        system: Optional[str] = None,
    ) -> str:
        """
        Get completion from Claude with retry logic.

        Args:
            prompt: User prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            use_cache: Whether to use response cache
            system: Optional system prompt

        Returns:
            Generated text
        """
        # Check cache
        if use_cache:
            cache_key = self._generate_cache_key(
                prompt, max_tokens=max_tokens, temperature=temperature, system=system
            )

            if cache_key in self._cache:
                logger.debug("Cache hit for prompt")
                return self._cache[cache_key]

        # Rate limiting
        await self._rate_limit()

        # Retry loop
        last_error = None
        for attempt in range(self.max_retries):
            try:
                logger.debug(f"Claude API call (attempt {attempt + 1}/{self.max_retries})")

                messages = [{"role": "user", "content": prompt}]

                response = await self.async_client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    messages=messages,
                    system=system if system else None,
                )

                # Extract text from response
                result = response.content[0].text

                # Cache the result
                if use_cache:
                    self._cache[cache_key] = result

                logger.debug(f"Claude response received ({len(result)} chars)")
                return result

            except RateLimitError as e:
                last_error = e
                wait_time = 2**attempt  # Exponential backoff
                logger.warning(f"Rate limit hit, waiting {wait_time}s before retry")
                await asyncio.sleep(wait_time)

            except APIConnectionError as e:
                last_error = e
                wait_time = 2**attempt
                logger.warning(f"Connection error, waiting {wait_time}s before retry")
                await asyncio.sleep(wait_time)

            except APIError as e:
                last_error = e
                logger.error(f"API error: {e}")

                # Don't retry on certain errors
                if e.status_code in [400, 401, 403]:
                    raise

                wait_time = 2**attempt
                logger.warning(f"Retrying after {wait_time}s")
                await asyncio.sleep(wait_time)

            except Exception as e:
                last_error = e
                logger.error(f"Unexpected error: {e}")
                raise

        # All retries exhausted
        logger.error(f"All retries exhausted for Claude API call")
        raise last_error if last_error else Exception("Failed after all retries")

    async def batch_complete(
        self, prompts: list[str], max_tokens: int = 4096, temperature: float = 0.0
    ) -> list[str]:
        """
        Process multiple prompts with concurrency control.

        Args:
            prompts: List of prompts
            max_tokens: Maximum tokens per response
            temperature: Sampling temperature

        Returns:
            List of responses
        """
        # Process with limited concurrency to respect rate limits
        semaphore = asyncio.Semaphore(3)  # Max 3 concurrent requests

        async def process_one(prompt: str) -> str:
            async with semaphore:
                return await self.complete(prompt, max_tokens, temperature)

        tasks = [process_one(p) for p in prompts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Batch item {i} failed: {result}")
                processed_results.append("")
            else:
                processed_results.append(result)

        return processed_results

    def clear_cache(self) -> None:
        """Clear response cache."""
        self._cache.clear()
        logger.info("Cache cleared")

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {"cached_items": len(self._cache)}
