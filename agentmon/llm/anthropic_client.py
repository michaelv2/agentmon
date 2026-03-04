"""Thin wrapper around the Anthropic SDK for Claude Sonnet analysis.

Used by the alert review dashboard and reassessment features.
Follows the same pattern as the Ollama-based classifier: config dataclass,
.available property, graceful degradation when no API key.
"""

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)

ENV_ANTHROPIC_API_KEY = "ANTHROPIC_API_KEY"


@dataclass
class AnthropicConfig:
    """Configuration for the Anthropic client."""

    model: str = "claude-sonnet-4-6"
    max_tokens: int = 2048
    temperature: float = 0.2


class AnthropicClient:
    """Wrapper around the Anthropic SDK for domain/alert analysis."""

    def __init__(
        self,
        api_key: str,
        config: AnthropicConfig | None = None,
    ) -> None:
        self.config = config or AnthropicConfig()
        self._client: object | None = None
        self._available = False

        try:
            import anthropic

            self._client = anthropic.Anthropic(api_key=api_key)
            self._available = True
            logger.info(f"Anthropic client initialized (model: {self.config.model})")
        except ImportError:
            logger.warning(
                "anthropic package not installed. "
                "Install with: pip install -e '.[cloud-llm]'"
            )
        except Exception as e:
            logger.warning(f"Failed to initialize Anthropic client: {e}")

    @property
    def available(self) -> bool:
        """Check if the client is ready."""
        return self._available

    def complete(self, system_prompt: str, user_message: str) -> str | None:
        """Send a prompt to Claude and return the response text.

        Args:
            system_prompt: System-level instructions.
            user_message: The user message / query content.

        Returns:
            Response text, or None on failure.
        """
        if not self._available or self._client is None:
            return None

        try:
            response = self._client.messages.create(  # type: ignore[union-attr]
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": user_message}],
            )
            # Extract text from response
            for block in response.content:
                if block.type == "text":
                    return block.text  # type: ignore[return-value]
            return None
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            return None


def get_anthropic_client(
    config: AnthropicConfig | None = None,
) -> AnthropicClient | None:
    """Factory: create an AnthropicClient if an API key is available.

    Checks ANTHROPIC_API_KEY env var.

    Returns:
        AnthropicClient instance, or None if no key is set.
    """
    api_key = os.environ.get(ENV_ANTHROPIC_API_KEY)
    if not api_key:
        logger.debug(f"No {ENV_ANTHROPIC_API_KEY} environment variable set")
        return None

    client = AnthropicClient(api_key, config)
    return client if client.available else None
