#!/usr/bin/env python3
"""Benchmark Ollama models for domain classification accuracy and speed.

Usage:
    python scripts/benchmark_models.py
    python scripts/benchmark_models.py --models gemma3:27b,llama3.3:70b
    python scripts/benchmark_models.py --models gemma3:27b --verbose
"""

import argparse
import json
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agentmon.llm.classifier import (
    CLASSIFICATION_PROMPT,
    ClassificationResult,
    DomainCategory,
)

# Ground truth test set
# (domain, expected_category, description)
BENCHMARK_DOMAINS = [
    # Benign - well-known services
    ("google.com", "benign", "Major search engine"),
    ("github.com", "benign", "Code hosting"),
    ("stackoverflow.com", "benign", "Developer Q&A"),
    ("en.wikipedia.org", "benign", "Encyclopedia"),
    ("reddit.com", "benign", "Social news"),
    ("nytimes.com", "benign", "News outlet"),

    # Advertising
    ("doubleclick.net", "advertising", "Google ad network"),
    ("adnxs.com", "advertising", "AppNexus ad platform"),
    ("moatads.com", "advertising", "Ad verification"),

    # Tracking
    ("google-analytics.com", "tracking", "Google analytics"),
    ("hotjar.com", "tracking", "Session recording"),
    ("segment.io", "tracking", "Analytics platform"),

    # CDN
    ("cdn.cloudflare.com", "cdn", "Cloudflare CDN"),
    ("akamaiedge.net", "cdn", "Akamai CDN"),
    ("fastly.net", "cdn", "Fastly CDN"),

    # Cloud providers
    ("ec2.amazonaws.com", "cloud_provider", "AWS EC2"),
    ("blob.core.windows.net", "cloud_provider", "Azure Blob"),
    ("storage.googleapis.com", "cloud_provider", "GCP Storage"),

    # API services
    ("api.stripe.com", "api_service", "Payment API"),
    ("api.twilio.com", "api_service", "Communication API"),

    # DGA-like (algorithmically generated)
    ("xj3k9f2m1p.xyz", "dga", "Random characters"),
    ("a1b2c3d4e5f6g7h8.net", "dga", "Alternating pattern"),
    ("qwrtpsdfghjkl.com", "dga", "No vowels, consonant soup"),
    ("7f8a2b3c9d1e4f5a.org", "dga", "Hex-like pattern"),

    # Suspicious
    ("free-vpn-download.xyz", "suspicious", "Suspicious VPN offer"),
    ("login-verify-account.com", "suspicious", "Phishing pattern"),
    ("update-flash-player.net", "suspicious", "Fake update pattern"),
    ("paypal-security-check.com", "suspicious", "Brand impersonation"),
]

# Categories that are "dangerous" - triage model must not call these benign
DANGEROUS_CATEGORIES = {"suspicious", "likely_malicious", "dga"}

# Categories that are acceptable alternatives (partial credit)
ACCEPTABLE_ALTERNATIVES = {
    "advertising": {"tracking"},  # ad/tracking often overlap
    "tracking": {"advertising"},
    "suspicious": {"likely_malicious"},
    "likely_malicious": {"suspicious"},
    "dga": {"suspicious", "likely_malicious"},
    "cloud_provider": {"api_service", "cdn"},
    "api_service": {"cloud_provider"},
}


def classify_with_model(model: str, domain: str, client: str = "192.168.1.100") -> tuple[ClassificationResult | None, float]:
    """Classify a domain and measure time.

    Returns (result, elapsed_seconds).
    """
    import ollama

    prompt = CLASSIFICATION_PROMPT.format(
        domain=domain,
        client=client,
        query_type="A",
        blocked="no",
    )

    start = time.monotonic()
    try:
        response = ollama.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1},
        )
        elapsed = time.monotonic() - start

        content = response["message"]["content"].strip()

        # Handle markdown code blocks
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])

        data = json.loads(content)
        category_str = data.get("category", "unknown").lower()
        try:
            category = DomainCategory(category_str)
        except ValueError:
            category = DomainCategory.UNKNOWN

        result = ClassificationResult(
            domain=domain,
            category=category,
            confidence=float(data.get("confidence", 0.5)),
            reasoning=data.get("reasoning", ""),
        )
        return result, elapsed

    except json.JSONDecodeError:
        elapsed = time.monotonic() - start
        return None, elapsed
    except Exception as e:
        elapsed = time.monotonic() - start
        print(f"  Error classifying {domain}: {e}", file=sys.stderr)
        return None, elapsed


def score_result(result: ClassificationResult | None, expected: str) -> tuple[str, bool, bool]:
    """Score a classification result.

    Returns (status, is_correct, is_safe).
    - status: "correct", "acceptable", "wrong", "parse_fail"
    - is_correct: exact or acceptable match
    - is_safe: dangerous domains not classified as benign
    """
    if result is None:
        return "parse_fail", False, False

    actual = result.category.value

    # Exact match
    if actual == expected:
        return "correct", True, True

    # Acceptable alternative
    alternatives = ACCEPTABLE_ALTERNATIVES.get(expected, set())
    if actual in alternatives:
        return "acceptable", True, True

    # Safety check: did it classify a dangerous domain as benign?
    is_safe = True
    if expected in DANGEROUS_CATEGORIES and actual == "benign":
        is_safe = False

    return "wrong", False, is_safe


def run_benchmark(models: list[str], verbose: bool = False) -> None:
    """Run benchmark across all models and print results."""
    import ollama

    # Verify models exist
    available = {m["name"] for m in ollama.list()["models"]}
    for model in models:
        if model not in available:
            # Try without tag
            if not any(m.startswith(model.split(":")[0]) for m in available):
                print(f"WARNING: Model '{model}' not found in Ollama", file=sys.stderr)

    results_by_model: dict[str, dict] = {}

    for model in models:
        print(f"\n{'='*60}")
        print(f"Benchmarking: {model}")
        print(f"{'='*60}")

        correct = 0
        acceptable = 0
        wrong = 0
        parse_fails = 0
        unsafe = 0
        total_time = 0.0
        details = []

        for domain, expected, description in BENCHMARK_DOMAINS:
            result, elapsed = classify_with_model(model, domain)
            total_time += elapsed

            status, is_correct, is_safe = score_result(result, expected)

            if status == "correct":
                correct += 1
            elif status == "acceptable":
                acceptable += 1
            elif status == "parse_fail":
                parse_fails += 1
            else:
                wrong += 1

            if not is_safe:
                unsafe += 1

            actual_cat = result.category.value if result else "PARSE_FAIL"
            confidence = result.confidence if result else 0.0

            # Status indicator
            if status == "correct":
                indicator = "OK"
            elif status == "acceptable":
                indicator = "~OK"
            elif not is_safe:
                indicator = "UNSAFE"
            elif status == "parse_fail":
                indicator = "FAIL"
            else:
                indicator = "WRONG"

            details.append({
                "domain": domain,
                "expected": expected,
                "actual": actual_cat,
                "confidence": confidence,
                "status": indicator,
                "time": elapsed,
                "reasoning": result.reasoning if result else "",
            })

            if verbose:
                print(f"  [{indicator:>6}] {domain:<35} expected={expected:<18} got={actual_cat:<18} conf={confidence:.2f}  {elapsed:.1f}s")
                if result and result.reasoning:
                    print(f"          {result.reasoning[:80]}")
            else:
                print(f"  [{indicator:>6}] {domain:<35} → {actual_cat:<18} ({elapsed:.1f}s)")

        total = len(BENCHMARK_DOMAINS)
        avg_time = total_time / total if total > 0 else 0
        accuracy = (correct + acceptable) / total * 100
        exact_accuracy = correct / total * 100
        safety_rate = (total - unsafe) / total * 100

        print(f"\n--- {model} Summary ---")
        print(f"  Exact accuracy:  {correct}/{total} ({exact_accuracy:.0f}%)")
        print(f"  With acceptable: {correct + acceptable}/{total} ({accuracy:.0f}%)")
        print(f"  Wrong:           {wrong}/{total}")
        print(f"  Parse failures:  {parse_fails}/{total}")
        print(f"  Safety rate:     {total - unsafe}/{total} ({safety_rate:.0f}%) (dangerous domains not marked benign)")
        print(f"  Avg time/domain: {avg_time:.1f}s")
        print(f"  Total time:      {total_time:.0f}s")

        results_by_model[model] = {
            "exact_accuracy": exact_accuracy,
            "accuracy": accuracy,
            "safety_rate": safety_rate,
            "avg_time": avg_time,
            "total_time": total_time,
            "parse_fails": parse_fails,
            "details": details,
        }

    # Comparison table
    if len(models) > 1:
        print(f"\n{'='*60}")
        print("COMPARISON")
        print(f"{'='*60}")
        print(f"{'Model':<25} {'Accuracy':>10} {'Safety':>10} {'Avg Time':>10} {'Parse OK':>10}")
        print("-" * 65)
        for model in models:
            r = results_by_model[model]
            parse_ok = f"{len(BENCHMARK_DOMAINS) - r['parse_fails']}/{len(BENCHMARK_DOMAINS)}"
            print(f"{model:<25} {r['accuracy']:>9.0f}% {r['safety_rate']:>9.0f}% {r['avg_time']:>9.1f}s {parse_ok:>10}")

        # Recommendation
        print(f"\nRecommendation:")
        # Sort by safety first, then accuracy, then speed
        ranked = sorted(
            results_by_model.items(),
            key=lambda x: (-x[1]["safety_rate"], -x[1]["accuracy"], x[1]["avg_time"]),
        )
        fastest = min(results_by_model.items(), key=lambda x: x[1]["avg_time"])
        most_accurate = max(results_by_model.items(), key=lambda x: x[1]["accuracy"])

        print(f"  Triage (fast):     {fastest[0]} ({fastest[1]['avg_time']:.1f}s/domain, {fastest[1]['accuracy']:.0f}% accuracy)")
        print(f"  Escalation (best): {most_accurate[0]} ({most_accurate[1]['avg_time']:.1f}s/domain, {most_accurate[1]['accuracy']:.0f}% accuracy)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Ollama models for domain classification")
    parser.add_argument(
        "--models",
        type=str,
        default=None,
        help="Comma-separated list of models to test (default: all local models)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output including reasoning",
    )
    args = parser.parse_args()

    if args.models:
        models = [m.strip() for m in args.models.split(",")]
    else:
        # Default: test all local (non-cloud) models
        import ollama
        all_models = ollama.list()["models"]
        models = [
            m["name"] for m in all_models
            if "cloud" not in m["name"] and m.get("size", 0) > 0
        ]
        if not models:
            print("No local models found. Pull a model first: ollama pull gemma3:27b")
            sys.exit(1)
        print(f"Testing {len(models)} local models: {', '.join(models)}")

    run_benchmark(models, verbose=args.verbose)


if __name__ == "__main__":
    main()
