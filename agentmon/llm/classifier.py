"""LLM-based domain classifier with two-tier triage/escalation.

Uses a fast local model for initial triage, escalating suspicious
results to a larger model for deeper analysis.
"""

import json
import logging
from dataclasses import dataclass, field
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
    escalated: bool = False  # True if escalation model was used
    triage_category: Optional[str] = None  # Original triage result if escalated


@dataclass
class LLMConfig:
    """Configuration for LLM classifier."""
    # Two-tier model config
    triage_model: str = "gpt-oss:20b"
    escalation_model: str = "gpt-oss:20b"

    # Escalation triggers
    escalation_categories: list[str] = field(default_factory=lambda: [
        "suspicious", "likely_malicious", "dga", "unknown",
    ])
    escalation_confidence_threshold: float = 0.7

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
    """Classifies domains using two-tier Ollama models."""

    def __init__(self, config: Optional[LLMConfig] = None) -> None:
        self.config = config or LLMConfig()
        self._client = None
        self._available = False
        self._init_client()

    def _init_client(self) -> None:
        """Initialize the Ollama client."""
        try:
            import ollama
            ollama.list()
            self._client = ollama
            self._available = True
            logger.info(
                f"Ollama connected - triage: {self.config.triage_model}, "
                f"escalation: {self.config.escalation_model}"
            )
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
        """Classify a domain using two-tier triage/escalation.

        1. Fast triage model classifies first
        2. If suspicious/low-confidence, escalation model re-classifies

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

        # Step 1: Triage
        triage_result = self._query_model(
            self.config.triage_model, domain, client, query_type, blocked,
        )

        if triage_result is None:
            return ClassificationResult(
                domain=domain,
                category=DomainCategory.UNKNOWN,
                confidence=0.0,
                reasoning="Triage classification failed",
            )

        # Step 2: Check if escalation is needed
        needs_escalation = (
            triage_result.category.value in self.config.escalation_categories
            or triage_result.confidence < self.config.escalation_confidence_threshold
        )

        if not needs_escalation or self.config.triage_model == self.config.escalation_model:
            return triage_result

        # Step 3: Escalate
        logger.info(
            f"Escalating {domain}: triage={triage_result.category.value} "
            f"(conf={triage_result.confidence:.2f})"
        )

        escalation_result = self._query_model(
            self.config.escalation_model, domain, client, query_type, blocked,
        )

        if escalation_result is None:
            # Fall back to triage result
            return triage_result

        escalation_result.escalated = True
        escalation_result.triage_category = triage_result.category.value
        return escalation_result

    def _query_model(
        self,
        model: str,
        domain: str,
        client: str,
        query_type: str,
        blocked: bool,
    ) -> Optional[ClassificationResult]:
        """Query a specific model for classification."""
        prompt = CLASSIFICATION_PROMPT.format(
            domain=domain,
            client=client or "unknown",
            query_type=query_type or "unknown",
            blocked="yes" if blocked else "no",
        )

        try:
            response = self._client.chat(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.1},
            )

            content = response["message"]["content"]
            result = self._parse_response(domain, content)
            if result:
                logger.debug(f"{model} → {domain}: {result.category.value} ({result.confidence:.2f})")
            return result

        except Exception as e:
            logger.debug(f"{model} classification failed for {domain}: {e}")
            return None

    def _parse_response(self, domain: str, content: str) -> Optional[ClassificationResult]:
        """Parse LLM response into ClassificationResult."""
        try:
            content = content.strip()
            if content.startswith("```"):
                lines = content.split("\n")
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
            return None

    def classify_batch(self, domains: list[str]) -> list[ClassificationResult]:
        """Classify multiple domains."""
        return [self.classify(domain) for domain in domains]
