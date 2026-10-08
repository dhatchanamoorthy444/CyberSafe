import math
from urllib.parse import urlparse


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log2(p) for p in prob if p > 0])
    return entropy


def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def analyze_heuristics(url: str):
    score = 0
    flags = []
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Raw IP check
    if hostname.replace(".", "").isdigit():
        score += 40
        flags.append("Raw IP address host detected")

    # Length check
    if len(url) > 75:
        score += 15
        flags.append("URL exceeds 75 characters")

    # Subdomain count
    subdomains = hostname.split(".")
    if len(subdomains) >= 3:
        score += 10
        flags.append(f"High subdomain count ({len(subdomains)})")

    # Entropy
    ent = calculate_entropy(url)
    if ent > 4.5:
        score += 20
        flags.append(f"High entropy string detected ({ent:.2f})")

    # Brand typo-squatting
    brands = ["google", "paypal", "amazon", "microsoft", "bankofamerica"]
    for brand in brands:
        dist = levenshtein_distance(hostname, brand)
        if 0 < dist < 3:
            score += 30
            flags.append(f"Possible typo-squatting targeting {brand}")

    # Sensitive keywords
    keywords = ["login", "verify", "banking", "secure", "update"]
    path = parsed.path.lower()
    for kw in keywords:
        if kw in path:
            score += 10
            flags.append(f"Sensitive keyword '{kw}' in path")

    score = min(100, score)
    return score, flags
