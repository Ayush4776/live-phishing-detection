import re
import urllib.parse
from typing import Dict, Any, List

SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "banking", "secure", "update", "signin",
    "paypal", "apple", "amazon", "google", "microsoft", "netflix", "bank",
    "wallet", "crypto", "confirm", "claim", "free", "bonus", "credential",
    "security", "support", "service", "password", "validation", "authenticate"
]

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "has_ip",
    "count_at",
    "count_double_slash",
    "count_hyphen",
    "count_dot",
    "count_subdomains",
    "is_https",
    "suspicious_keywords_count",
    "path_depth",
    "digit_ratio",
    "count_equal",
    "count_question",
    "prefix_suffix",
    "has_shortener"
]

def is_ip_address(domain: str) -> int:
    """Check if domain is IPv4 or IPv6 address."""
    # IPv4 regex pattern
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    # Hexadecimal IP pattern (e.g. 0x76.0x5d.0x34.0xab)
    hex_ip_pattern = r"^0x[0-9a-fA-F]+\."
    if re.match(ipv4_pattern, domain) or re.match(hex_ip_pattern, domain):
        return 1
    return 0

def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract 16 lexical and structural features from a URL string.
    Returns a dictionary with raw values and numerical feature vector.
    """
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc.split(":")[0].lower() # strip port if present
    path = parsed.path
    query = parsed.query

    # 1. URL length
    url_len = len(url)

    # 2. Domain length
    domain_len = len(domain)

    # 3. Has IP address
    has_ip = is_ip_address(domain)

    # 4. Count of `@` symbol
    count_at = url.count("@")

    # 5. Count of double slashes in path (after initial scheme)
    count_double_slash = path.count("//")

    # 6. Count of hyphens in domain
    count_hyphen = domain.count("-")

    # 7. Count of dots in URL
    count_dot = url.count(".")

    # 8. Subdomains count
    domain_parts = [p for p in domain.split(".") if p]
    count_subdomains = max(0, len(domain_parts) - 2) if len(domain_parts) > 2 else 0

    # 9. HTTPS protocol presence
    is_https = 1 if parsed.scheme.lower() == "https" else 0

    # 10. Suspicious keyword search
    url_lower = url.lower()
    suspicious_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # 11. Path depth
    path_segments = [s for s in path.split("/") if s]
    path_depth = len(path_segments)

    # 12. Digit ratio
    digits_count = sum(c.isdigit() for c in url)
    digit_ratio = round(digits_count / url_len, 4) if url_len > 0 else 0.0

    # 13. Count of `=`
    count_equal = url.count("=")

    # 14. Count of `?`
    count_question = url.count("?")

    # 15. Prefix / Suffix (hyphen in domain name)
    prefix_suffix = 1 if "-" in domain else 0

    # 16. Has URL Shortening service
    has_shortener = 1 if any(short in domain for short in SHORTENING_SERVICES) else 0

    features_dict = {
        "url_length": url_len,
        "domain_length": domain_len,
        "has_ip": has_ip,
        "count_at": count_at,
        "count_double_slash": count_double_slash,
        "count_hyphen": count_hyphen,
        "count_dot": count_dot,
        "count_subdomains": count_subdomains,
        "is_https": is_https,
        "suspicious_keywords_count": suspicious_count,
        "path_depth": path_depth,
        "digit_ratio": digit_ratio,
        "count_equal": count_equal,
        "count_question": count_question,
        "prefix_suffix": prefix_suffix,
        "has_shortener": has_shortener
    }

    # Vector in exact order of FEATURE_NAMES
    feature_vector = [features_dict[name] for name in FEATURE_NAMES]

    # Human-readable breakdown for UI front-end
    breakdown = []
    if is_https == 0:
        breakdown.append({"feature": "Insecure Connection", "risk": "High", "detail": "URL uses HTTP instead of secure HTTPS protocol"})
    if has_ip == 1:
        breakdown.append({"feature": "Raw IP Address Domain", "risk": "High", "detail": "Domain uses numeric IP address instead of domain name"})
    if prefix_suffix == 1:
        breakdown.append({"feature": "Hyphen in Domain", "risk": "Medium", "detail": "Domain name contains hyphens often used in typosquatting"})
    if count_at > 0:
        breakdown.append({"feature": "@ Symbol in URL", "risk": "High", "detail": "URL contains '@' character which ignores preceding hostname"})
    if suspicious_count > 0:
        breakdown.append({"feature": "Suspicious Keywords", "risk": "High", "detail": f"Found {suspicious_count} security/login related keyword(s)"})
    if url_len > 75:
        breakdown.append({"feature": "Excessive URL Length", "risk": "Medium", "detail": f"URL length is unusually long ({url_len} chars)"})
    if has_shortener == 1:
        breakdown.append({"feature": "URL Shortener Service", "risk": "Medium", "detail": "Uses a known URL shortening domain which obscures destination"})

    return {
        "url": url,
        "domain": domain,
        "features": features_dict,
        "feature_vector": feature_vector,
        "breakdown": breakdown
    }
