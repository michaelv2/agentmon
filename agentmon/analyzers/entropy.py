"""Entropy calculation for domain analysis.

High-entropy domain names are often indicators of:
- Domain Generation Algorithms (DGA) used by malware
- Data exfiltration via DNS tunneling
- Random subdomains used for tracking/beaconing
"""

import math
import re
from collections import Counter


def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string.

    Returns a value between 0 (all same character) and ~4.7 (random alphanumeric).

    Args:
        s: Input string

    Returns:
        Shannon entropy in bits per character
    """
    if not s:
        return 0.0

    # Count character frequencies
    freq = Counter(s.lower())
    length = len(s)

    # Calculate entropy: -sum(p * log2(p))
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def calculate_domain_entropy(domain: str) -> float:
    """Calculate entropy specifically for domain analysis.

    This removes common TLDs and focuses on the meaningful parts
    of the domain name.

    Args:
        domain: Full domain name (e.g., "abc123xyz.example.com")

    Returns:
        Entropy of the domain excluding TLD
    """
    parts = domain.lower().split(".")

    # Remove common TLDs for analysis
    common_tlds = {"com", "net", "org", "io", "co", "uk", "de", "fr", "eu"}

    # Find where TLD starts
    meaningful_parts = []
    for i, part in enumerate(parts):
        if part in common_tlds and i >= len(parts) - 2:
            break
        meaningful_parts.append(part)

    if not meaningful_parts:
        meaningful_parts = parts[:-1] if len(parts) > 1 else parts

    # Calculate entropy on the joined meaningful parts
    meaningful_str = "".join(meaningful_parts)
    return calculate_entropy(meaningful_str)


def is_high_entropy_domain(
    domain: str,
    threshold: float = 3.5,
    min_length: int = 10,
) -> tuple[bool, float]:
    """Check if a domain has suspiciously high entropy.

    Args:
        domain: The domain to check
        threshold: Entropy threshold (default 3.5 bits)
        min_length: Minimum length to consider (short domains can have high entropy naturally)

    Returns:
        Tuple of (is_suspicious, entropy_score)
    """
    parts = domain.lower().split(".")

    # Skip very short domains
    meaningful = "".join(parts[:-1]) if len(parts) > 1 else domain
    if len(meaningful) < min_length:
        return (False, 0.0)

    entropy = calculate_domain_entropy(domain)

    return (entropy > threshold, entropy)


def has_excessive_consonants(domain: str, threshold: float = 0.7) -> bool:
    """Check if domain has an unusually high consonant ratio.

    DGA domains often have unusual consonant/vowel ratios.

    Args:
        domain: Domain to check
        threshold: Consonant ratio threshold (default 0.7)

    Returns:
        True if consonant ratio exceeds threshold
    """
    # Remove TLD for analysis
    parts = domain.lower().split(".")
    check_str = "".join(parts[:-1]) if len(parts) > 1 else domain

    # Only consider alphabetic characters
    alpha_only = re.sub(r"[^a-z]", "", check_str)
    if len(alpha_only) < 5:
        return False

    vowels = set("aeiou")
    consonant_count = sum(1 for c in alpha_only if c not in vowels)

    return (consonant_count / len(alpha_only)) > threshold


def looks_like_dga(domain: str) -> tuple[bool, list[str]]:
    """Heuristic check for DGA-like domains.

    Combines multiple signals to detect potential DGA domains.

    Args:
        domain: Domain to analyze

    Returns:
        Tuple of (is_suspicious, list of reasons)
    """
    reasons: list[str] = []

    parts = domain.lower().split(".")
    if len(parts) < 2:
        return (False, [])

    # Check the subdomain/main domain part (excluding TLD)
    check_part = parts[0] if len(parts) == 2 else ".".join(parts[:-1])

    # High entropy check
    is_high_ent, entropy = is_high_entropy_domain(domain)
    if is_high_ent:
        reasons.append(f"high entropy ({entropy:.2f})")

    # Excessive consonants
    if has_excessive_consonants(domain):
        reasons.append("unusual consonant ratio")

    # Long random-looking strings
    if len(check_part) > 20 and re.search(r"[a-z0-9]{15,}", check_part):
        reasons.append("long alphanumeric sequence")

    # Digit/letter mixing patterns common in DGA
    if re.search(r"[a-z]+\d+[a-z]+\d+", check_part):
        reasons.append("alternating letter-digit pattern")

    # No vowels in a long string
    if len(check_part) > 8:
        vowel_count = sum(1 for c in check_part if c in "aeiou")
        if vowel_count == 0:
            reasons.append("no vowels in domain")

    return (len(reasons) >= 2, reasons)
