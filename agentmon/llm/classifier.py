"""LLM-based domain classifier.

Uses local LLM for initial classification, with optional escalation
to frontier models for ambiguous cases.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional
import json

import httpx


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
    escalated: bool = False


@dataclass
class LLMConfig:
    """Configuration for LLM classifier."""
    local_endpoint: str = "http://localhost:8080/v1"
    local_model: str = "llama3.3-70b"
    frontier_endpoint: Optional[str] = None
    frontier_api_key: Optional[str] = None
    frontier_model: Optional[str] = None
    timeout_seconds: float = 30.0
    escalation_confidence_threshold: float = 0.6


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
    """Classifies domains using local and optionally frontier LLMs."""

    def __init__(self, config: Optional[LLMConfig] = None) -> None:
        self.config = config or LLMConfig()
        self._client = httpx.Client(timeout=self.config.timeout_seconds)

    def classify(
        self,
        domain: str,
        client: str = "",
        query_type: str = "",
        blocked: bool = False,
    ) -> ClassificationResult:
        """Classify a domain using the local LLM.

        Args:
            domain: The domain to classify
            client: Client IP that made the query
            query_type: DNS query type (A, AAAA, etc.)
            blocked: Whether Pi-hole blocked this query

        Returns:
            Classification result
        """
        prompt = CLASSIFICATION_PROMPT.format(
            domain=domain,
            client=client or "unknown",
            query_type=query_type or "unknown",
            blocked="yes" if blocked else "no",
        )

        # Try local LLM first
        result = self._query_llm(
            self.config.local_endpoint,
            self.config.local_model,
            prompt,
        )

        if result is None:
            return ClassificationResult(
                domain=domain,
                category=DomainCategory.UNKNOWN,
                confidence=0.0,
                reasoning="LLM query failed",
            )

        # Check if we should escalate
        if (
            result.confidence < self.config.escalation_confidence_threshold
            and self.config.frontier_endpoint
            and self.config.frontier_api_key
        ):
            escalated_result = self._escalate(domain, client, query_type, blocked)
            if escalated_result:
                escalated_result.escalated = True
                return escalated_result

        return result

    def _query_llm(
        self,
        endpoint: str,
        model: str,
        prompt: str,
        api_key: Optional[str] = None,
    ) -> Optional[ClassificationResult]:
        """Query an LLM endpoint."""
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,  # Low temperature for consistent classification
            "max_tokens": 256,
        }

        try:
            response = self._client.post(
                f"{endpoint}/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()

            data = response.json()
            content = data["choices"][0]["message"]["content"]

            # Parse the JSON response
            return self._parse_response(content)

        except (httpx.HTTPError, KeyError, json.JSONDecodeError) as e:
            # Log error in production
            return None

    def _parse_response(self, content: str) -> Optional[ClassificationResult]:
        """Parse LLM response into ClassificationResult."""
        try:
            # Handle potential markdown code blocks
            content = content.strip()
            if content.startswith("```"):
                lines = content.split("\n")
                content = "\n".join(lines[1:-1])

            data = json.loads(content)

            category_str = data.get("category", "unknown").lower()
            try:
                category = DomainCategory(category_str)
            except ValueError:
                category = DomainCategory.UNKNOWN

            return ClassificationResult(
                domain="",  # Will be filled in by caller
                category=category,
                confidence=float(data.get("confidence", 0.5)),
                reasoning=data.get("reasoning", ""),
            )
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def _escalate(
        self,
        domain: str,
        client: str,
        query_type: str,
        blocked: bool,
    ) -> Optional[ClassificationResult]:
        """Escalate to frontier model for better classification."""
        if not self.config.frontier_endpoint or not self.config.frontier_model:
            return None

        prompt = CLASSIFICATION_PROMPT.format(
            domain=domain,
            client=client or "unknown",
            query_type=query_type or "unknown",
            blocked="yes" if blocked else "no",
        )

        result = self._query_llm(
            self.config.frontier_endpoint,
            self.config.frontier_model,
            prompt,
            self.config.frontier_api_key,
        )

        if result:
            result.domain = domain

        return result

    def classify_batch(
        self,
        domains: list[str],
    ) -> list[ClassificationResult]:
        """Classify multiple domains.

        Note: This currently processes sequentially. For better performance
        with many domains, consider implementing async batch processing.
        """
        return [self.classify(domain) for domain in domains]

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> "DomainClassifier":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
