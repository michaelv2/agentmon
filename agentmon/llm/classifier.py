"""LLM-based domain classifier.

Uses Ollama for local LLM classification of domains.
"""

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class DomainCategory(Enum):
    """Categories for domain classification."""
    BENIGN = "benign"
    ADVERTISING = "advertising"
    TRACKING = "tracking"
    CDN = "cdn"
    CLOUD_PROVIDER = "cloud_provider"
    API_SERVICE = "api_service"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    DGA = "dga"
    UNKNOWN = "unknown"


@dataclass
class ClassificationResult:
    """Result of domain classification."""
    domain: str
    category: DomainCategory
    confidence: float  # 0.0 to 1.0
    reasoning: str


@dataclass
class LLMConfig:
    """Configuration for LLM classifier."""
    model: str = "llama3.2"
    timeout_seconds: float = 30.0


CLASSIFICATION_PROMPT = """You are a network security analyst classifying domain names.

Analyze this domain and classify it into ONE of these categories:
- benign: Normal, well-known legitimate service
- advertising: Ad network or ad-related service
- tracking: Analytics, telemetry, or user tracking
- cdn: Content delivery network
- cloud_provider: Cloud infrastructure (AWS, Azure, GCP, etc.)
- api_service: Known API endpoint for legitimate services
- suspicious: Unusual but not clearly malicious
- likely_malicious: Shows signs of malware, phishing, or C2
- dga: Appears to be algorithmically generated (random-looking)
- unknown: Cannot determine

Domain to classify: {domain}

Additional context:
- Client IP: {client}
- Query type: {query_type}
- Was blocked by Pi-hole: {blocked}

Respond with ONLY a JSON object (no markdown, no explanation outside JSON):
{{
    "category": "<category>",
    "confidence": <0.0-1.0>,
    "reasoning": "<brief explanation>"
}}"""


class DomainClassifier:
    """Classifies domains using Ollama."""

    def __init__(self, config: Optional[LLMConfig] = None) -> None:
        self.config = config or LLMConfig()
        self._client = None
        self._available = False
        self._init_client()

    def _init_client(self) -> None:
        """Initialize the Ollama client."""
        try:
            import ollama
            # Test connection by listing models
            ollama.list()
            self._client = ollama
            self._available = True
            logger.info(f"Ollama connected, using model: {self.config.model}")
        except Exception as e:
            logger.warning(f"Ollama not available: {e}")
            self._available = False

    @property
    def available(self) -> bool:
        """Check if the classifier is available."""
        return self._available

    def classify(
        self,
        domain: str,
        client: str = "",
        query_type: str = "",
        blocked: bool = False,
    ) -> ClassificationResult:
        """Classify a domain using Ollama.

        Args:
            domain: The domain to classify
            client: Client IP that made the query
            query_type: DNS query type (A, AAAA, etc.)
            blocked: Whether Pi-hole blocked this query

        Returns:
            Classification result
        """
        if not self._available:
            return ClassificationResult(
                domain=domain,
                category=DomainCategory.UNKNOWN,
                confidence=0.0,
                reasoning="Ollama not available",
            )

        prompt = CLASSIFICATION_PROMPT.format(
            domain=domain,
            client=client or "unknown",
            query_type=query_type or "unknown",
            blocked="yes" if blocked else "no",
        )

        try:
            response = self._client.chat(
                model=self.config.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.1},  # Low temperature for consistency
            )

            content = response["message"]["content"]
            return self._parse_response(domain, content)

        except Exception as e:
            logger.debug(f"Ollama classification failed for {domain}: {e}")
            return ClassificationResult(
                domain=domain,
                category=DomainCategory.UNKNOWN,
                confidence=0.0,
                reasoning=f"Classification failed: {e}",
            )

    def _parse_response(self, domain: str, content: str) -> ClassificationResult:
        """Parse LLM response into ClassificationResult."""
        try:
            # Handle potential markdown code blocks
            content = content.strip()
            if content.startswith("```"):
                lines = content.split("\n")
                # Remove first and last line (``` markers)
                content = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])

            data = json.loads(content)

            category_str = data.get("category", "unknown").lower()
            try:
                category = DomainCategory(category_str)
            except ValueError:
                category = DomainCategory.UNKNOWN

            return ClassificationResult(
                domain=domain,
                category=category,
                confidence=float(data.get("confidence", 0.5)),
                reasoning=data.get("reasoning", ""),
            )
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.debug(f"Failed to parse LLM response: {e}")
            return ClassificationResult(
                domain=domain,
                category=DomainCategory.UNKNOWN,
                confidence=0.0,
                reasoning=f"Failed to parse response: {content[:100]}",
            )

    def classify_batch(self, domains: list[str]) -> list[ClassificationResult]:
        """Classify multiple domains.

        Note: Processes sequentially. For better performance with many domains,
        consider implementing async batch processing.
        """
        return [self.classify(domain) for domain in domains]
