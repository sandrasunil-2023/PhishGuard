"""
PhishGuard - URL Feature Extractor
Extracts heuristic features from URLs to feed into the ML classifier.
"""

import re
import math
import urllib.parse
import tldextract

# Use tldextract's packaged suffix snapshot. URL scanning must remain local and
# responsive; it should never try to contact publicsuffix.org for first use.
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


# --- Suspicious patterns ---
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account", "banking",
    "paypal", "amazon", "google", "microsoft", "apple", "netflix", "confirm",
    "password", "credential", "free", "prize", "winner", "click", "urgent",
    "limited", "offer", "suspended", "unusual", "activity", "alert",
    "webscr", "ebayisapi", "cmd", "dispatch"
]

BRAND_NAMES = [
    "paypal", "google", "amazon", "microsoft", "apple", "facebook",
    "instagram", "netflix", "bank", "wells", "chase", "citibank",
    "dropbox", "linkedin", "twitter", "whatsapp", "ebay", "dhl",
    "fedex", "irs", "usps", "ubi", "coinbase", "binance"
]


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    n = len(s)
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_features(url: str) -> dict:
    """
    Extract a feature vector from a URL for phishing detection.
    Returns a dict of feature_name -> numeric value.
    """
    features = {}

    # Ensure URL has a scheme for parsing
    if not url.startswith(("http://", "https://", "ftp://")):
        url_for_parse = "http://" + url
    else:
        url_for_parse = url

    try:
        parsed = urllib.parse.urlparse(url_for_parse)
    except Exception:
        parsed = urllib.parse.urlparse("http://invalid.com")

    extracted = _TLD_EXTRACTOR(url_for_parse)
    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain
    full_domain = parsed.netloc
    path = parsed.path
    query = parsed.query

    # --- Length-based features ---
    features["url_length"] = len(url)
    features["domain_length"] = len(full_domain)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    # --- Scheme ---
    features["is_https"] = 1 if parsed.scheme == "https" else 0

    # --- IP address as hostname ---
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    features["has_ip_address"] = 1 if re.match(ip_pattern, full_domain.split(":")[0]) else 0

    # --- Special character counts ---
    features["count_dots"] = url.count(".")
    features["count_hyphens"] = url.count("-")
    features["count_underscores"] = url.count("_")
    features["count_slashes"] = url.count("/")
    features["count_at"] = url.count("@")
    features["count_question"] = url.count("?")
    features["count_equals"] = url.count("=")
    features["count_ampersand"] = url.count("&")
    features["count_percent"] = url.count("%")
    features["count_hash"] = url.count("#")
    features["count_digits"] = sum(c.isdigit() for c in url)

    # --- Subdomain depth ---
    subdomains = [s for s in subdomain.split(".") if s] if subdomain else []
    features["subdomain_count"] = len(subdomains)
    features["has_www"] = 1 if "www" in subdomains else 0

    # --- Suspicious TLDs ---
    suspicious_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "pw", "cc", "top", "work", "click"}
    features["suspicious_tld"] = 1 if suffix.lower() in suspicious_tlds else 0

    # --- Keyword-based features ---
    url_lower = url.lower()
    features["has_suspicious_keyword"] = 1 if any(k in url_lower for k in SUSPICIOUS_KEYWORDS) else 0
    features["suspicious_keyword_count"] = sum(1 for k in SUSPICIOUS_KEYWORDS if k in url_lower)

    # --- Brand impersonation ---
    # A brand name in subdomain/path but not as the actual domain
    brand_in_url = [b for b in BRAND_NAMES if b in url_lower]
    features["has_brand_name"] = 1 if brand_in_url else 0
    features["brand_not_in_domain"] = (
        1 if brand_in_url and not any(b in domain.lower() for b in brand_in_url) else 0
    )

    # --- Digit-heavy domain ---
    features["domain_digit_ratio"] = (
        sum(c.isdigit() for c in domain) / max(len(domain), 1)
    )

    # --- Hyphen in domain ---
    features["hyphen_in_domain"] = 1 if "-" in domain else 0

    # --- URL shortener patterns ---
    shorteners = {"bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "is.gd",
                  "buff.ly", "short.link", "rb.gy", "cutt.ly"}
    features["is_url_shortener"] = 1 if any(s in url_lower for s in shorteners) else 0

    # --- Encoded characters ---
    features["has_encoded_chars"] = 1 if "%" in url else 0

    # --- Multiple subdomains of same brand ---
    features["double_slash_in_path"] = 1 if "//" in path else 0

    # --- Port in URL ---
    features["has_port"] = 1 if parsed.port else 0

    # --- Entropy of domain ---
    features["domain_entropy"] = _shannon_entropy(domain)

    # --- Path depth ---
    path_parts = [p for p in path.split("/") if p]
    features["path_depth"] = len(path_parts)

    # --- Redirection pattern ---
    features["has_redirect"] = 1 if "redirect" in url_lower or "url=" in url_lower else 0

    return features


def features_to_vector(features: dict) -> list:
    """Convert features dict to ordered list for ML model."""
    ordered_keys = [
        "url_length", "domain_length", "path_length", "query_length",
        "is_https", "has_ip_address",
        "count_dots", "count_hyphens", "count_underscores", "count_slashes",
        "count_at", "count_question", "count_equals", "count_ampersand",
        "count_percent", "count_hash", "count_digits",
        "subdomain_count", "has_www", "suspicious_tld",
        "has_suspicious_keyword", "suspicious_keyword_count",
        "has_brand_name", "brand_not_in_domain",
        "domain_digit_ratio", "hyphen_in_domain", "is_url_shortener",
        "has_encoded_chars", "double_slash_in_path", "has_port",
        "domain_entropy", "path_depth", "has_redirect"
    ]
    return [features.get(k, 0) for k in ordered_keys]


FEATURE_NAMES = [
    "url_length", "domain_length", "path_length", "query_length",
    "is_https", "has_ip_address",
    "count_dots", "count_hyphens", "count_underscores", "count_slashes",
    "count_at", "count_question", "count_equals", "count_ampersand",
    "count_percent", "count_hash", "count_digits",
    "subdomain_count", "has_www", "suspicious_tld",
    "has_suspicious_keyword", "suspicious_keyword_count",
    "has_brand_name", "brand_not_in_domain",
    "domain_digit_ratio", "hyphen_in_domain", "is_url_shortener",
    "has_encoded_chars", "double_slash_in_path", "has_port",
    "domain_entropy", "path_depth", "has_redirect"
]
