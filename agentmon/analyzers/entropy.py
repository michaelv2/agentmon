"""Entropy calculation for domain analysis.

High-entropy domain names are often indicators of:
- Domain Generation Algorithms (DGA) used by malware
- Data exfiltration via DNS tunneling
- Random subdomains used for tracking/beaconing
"""

import math
import re
from collections import Counter

# CDN/infrastructure parent domains where high-entropy subdomains are normal.
# These providers use algorithmically generated hostnames for load balancing,
# edge routing, and asset distribution.
DEFAULT_TRUSTED_INFRASTRUCTURE: frozenset[str] = frozenset({
    "akadns.net",
    "akamaiedge.net",
    "akamaized.net",
    "aaplimg.com",
    "apple.com",
    "apple-dns.net",
    "cloudfront.net",
    "amazonaws.com",
    "azure.com",
    "azureedge.net",
    "googleusercontent.com",
    "googlevideo.com",
    "gstatic.com",
    "fbcdn.net",
    "edgekey.net",
    "edgesuite.net",
    "llnwd.net",
    "fastly.net",
    "cloudflare.net",
    "cdn77.org",
})


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
    labels = parts[:-1] if len(parts) > 1 else parts

    # Check each label individually — concatenating labels like
    # "push"+"prod"+"netflix" inflates consonant ratio for legitimate
    # multi-label domains.  Require 8+ alpha chars per label to avoid
    # false positives on short brand names (e.g. "netflix" = 71%).
    vowels = set("aeiou")
    for label in labels:
        alpha_only = re.sub(r"[^a-z]", "", label)
        if len(alpha_only) < 8:
            continue
        consonant_count = sum(1 for c in alpha_only if c not in vowels)
        if (consonant_count / len(alpha_only)) > threshold:
            return True

    return False


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

    # Long random-looking strings — require the sequence itself to have
    # high entropy so compound words like "googleusercontent" don't match.
    match = re.search(r"[a-z0-9]{15,}", check_part)
    if len(check_part) > 20 and match and calculate_entropy(match.group()) > 3.5:
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


def get_parent_domain(domain: str, levels: int = 2) -> str:
    """Extract the parent domain (last N labels) from a FQDN.

    Examples:
        get_parent_domain("e1234.dscd.akamaiedge.net") -> "akamaiedge.net"
        get_parent_domain("ocsp2.g.aaplimg.com") -> "aaplimg.com"
        get_parent_domain("example.com") -> "example.com"
    """
    parts = domain.lower().split(".")
    if len(parts) <= levels:
        return domain.lower()
    return ".".join(parts[-levels:])


def is_trusted_infrastructure(
    domain: str,
    trusted: frozenset[str] | None = None,
) -> bool:
    """Check if domain is under a known CDN/infrastructure parent.

    High-entropy subdomains are expected under these parents and should
    not trigger DGA/entropy alerts.
    """
    if trusted is None:
        trusted = DEFAULT_TRUSTED_INFRASTRUCTURE
    parent = get_parent_domain(domain)
    return parent in trusted
