"""
=====================================================================
  AI-Based Phishing Attack Detection - Feature Extractor
  File: features/feature_extractor.py
  Description: Extracts numerical features from a given URL string
               for phishing detection. These features are used both
               during model training and during real-time inference.
=====================================================================
"""

import re
import urllib.parse
import ipaddress


# ─── Suspicious Keywords often found in phishing URLs ─────────────
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "banking", "paypal", "ebay", "amazon", "apple",
    "microsoft", "google", "suspended", "wallet", "password",
    "credential", "alert", "recover", "unlock", "validate",
    "authorize", "billing", "invoice", "prize", "winner", "free",
    "click", "now", "urgent", "limited", "offer", "bonus"
]

# ─── Common phishing TLDs ──────────────────────────────────────────
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".pw", ".cc", ".ru", ".cn", ".info", ".biz"
]

# ─── Shortening services ───────────────────────────────────────────
SHORTENER_SERVICES = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "tiny.cc"
]


def has_ip_address(url: str) -> int:
    """
    Returns 1 if the URL contains an IP address instead of a domain name.
    Phishing sites often use IP addresses to avoid domain registration.
    """
    try:
        # Extract host from URL
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc.split(":")[0]  # Remove port if present
        host = re.sub(r"@", "", host)       # Remove @ if present
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0


def has_at_symbol(url: str) -> int:
    """
    Returns 1 if URL contains '@' symbol.
    Browser ignores everything before '@', so it's a common phishing trick.
    e.g., http://legitimate.com@evil.com/
    """
    return 1 if "@" in url else 0


def get_url_length(url: str) -> int:
    """Returns the total character length of the URL."""
    return len(url)


def get_domain_length(url: str) -> int:
    """Returns the length of the domain (netloc) portion."""
    try:
        parsed = urllib.parse.urlparse(url)
        return len(parsed.netloc)
    except Exception:
        return 0


def count_dots(url: str) -> int:
    """
    Counts the number of '.' in the URL.
    Phishing URLs often have many subdomains, increasing dot count.
    """
    return url.count(".")


def count_hyphens(url: str) -> int:
    """
    Counts hyphens in the domain.
    Legitimate sites rarely use hyphens; phishing sites often do.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.count("-")
    except Exception:
        return 0


def count_slashes(url: str) -> int:
    """
    Counts the number of '/' in the URL path.
    Deeply nested paths are more common in phishing URLs.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.path.count("/")
    except Exception:
        return 0


def count_question_marks(url: str) -> int:
    """Counts '?' characters — more query strings can indicate phishing."""
    return url.count("?")


def count_equals(url: str) -> int:
    """Counts '=' characters in query strings."""
    return url.count("=")


def count_ampersands(url: str) -> int:
    """Counts '&' — multiple query parameters is a phishing indicator."""
    return url.count("&")


def count_digits_in_domain(url: str) -> int:
    """
    Counts digits in the domain name.
    Legitimate domains rarely have many numbers.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.split(":")[0]
        return sum(1 for c in domain if c.isdigit())
    except Exception:
        return 0


def uses_https(url: str) -> int:
    """Returns 1 if the URL uses HTTPS (secure), 0 if HTTP."""
    return 1 if url.lower().startswith("https://") else 0


def count_subdomains(url: str) -> int:
    """
    Counts the number of subdomains.
    Multiple subdomains (e.g., login.secure.paypal.verify.com) indicate phishing.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc.split(":")[0]
        # Remove www. prefix
        if host.startswith("www."):
            host = host[4:]
        parts = host.split(".")
        # Subtract 2 for domain + TLD
        return max(0, len(parts) - 2)
    except Exception:
        return 0


def has_suspicious_keyword(url: str) -> int:
    """
    Returns 1 if the URL contains any suspicious keyword.
    These words are commonly used to trick users.
    """
    url_lower = url.lower()
    return 1 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0


def count_suspicious_keywords(url: str) -> int:
    """Counts how many suspicious keywords appear in the URL."""
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)


def has_suspicious_tld(url: str) -> int:
    """Returns 1 if the URL uses a TLD commonly associated with phishing."""
    url_lower = url.lower()
    return 1 if any(url_lower.endswith(tld) or (tld + "/") in url_lower
                    for tld in SUSPICIOUS_TLDS) else 0


def is_shortened_url(url: str) -> int:
    """Returns 1 if the URL uses a URL shortening service."""
    url_lower = url.lower()
    return 1 if any(svc in url_lower for svc in SHORTENER_SERVICES) else 0


def get_path_length(url: str) -> int:
    """Returns the length of the URL path component."""
    try:
        parsed = urllib.parse.urlparse(url)
        return len(parsed.path)
    except Exception:
        return 0


def count_special_chars(url: str) -> int:
    """
    Counts special characters in the URL (excluding standard URL chars).
    High special character count can indicate obfuscation.
    """
    special = set("~!#$%^&*(){}<>|\\;'\"`,")
    return sum(1 for c in url if c in special)


def has_port_in_url(url: str) -> int:
    """
    Returns 1 if URL specifies a non-standard port.
    Phishing sites sometimes use unusual ports to avoid detection.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        port = parsed.port
        if port and port not in (80, 443):
            return 1
        return 0
    except Exception:
        return 0


def count_digits_in_url(url: str) -> int:
    """Counts total digits in the entire URL."""
    return sum(1 for c in url if c.isdigit())


# ─── Master Feature Extraction Function ───────────────────────────

def extract_features(url: str) -> dict:
    """
    Extracts all features from a URL and returns them as a dictionary.
    This is the main function called by both the trainer and the Flask app.

    Args:
        url (str): The URL to analyze.

    Returns:
        dict: A dictionary mapping feature names to their values.
    """
    url = url.strip()

    # Add protocol if missing (for proper parsing)
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    features = {
        "url_length":               get_url_length(url),
        "domain_length":            get_domain_length(url),
        "path_length":              get_path_length(url),
        "count_dots":               count_dots(url),
        "count_hyphens":            count_hyphens(url),
        "count_slashes":            count_slashes(url),
        "count_question_marks":     count_question_marks(url),
        "count_equals":             count_equals(url),
        "count_ampersands":         count_ampersands(url),
        "count_digits_in_domain":   count_digits_in_domain(url),
        "count_digits_in_url":      count_digits_in_url(url),
        "count_subdomains":         count_subdomains(url),
        "count_suspicious_keywords": count_suspicious_keywords(url),
        "count_special_chars":      count_special_chars(url),
        "uses_https":               uses_https(url),
        "has_ip_address":           has_ip_address(url),
        "has_at_symbol":            has_at_symbol(url),
        "has_suspicious_keyword":   has_suspicious_keyword(url),
        "has_suspicious_tld":       has_suspicious_tld(url),
        "is_shortened_url":         is_shortened_url(url),
        "has_port_in_url":          has_port_in_url(url),
    }

    return features


def get_feature_names() -> list:
    """Returns the ordered list of feature names used by the model."""
    return list(extract_features("http://example.com").keys())


# ─── Quick Test ───────────────────────────────────────────────────
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=hello",
        "http://paypal-verify-account-12345.tk/secure-login?id=abc&ref=phish",
        "http://192.168.1.1/admin/login",
        "https://www.amazon.com/products",
    ]

    for url in test_urls:
        print(f"\nURL: {url}")
        features = extract_features(url)
        for k, v in features.items():
            print(f"  {k:35s}: {v}")
