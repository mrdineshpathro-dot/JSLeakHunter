import math
from collections import Counter

def shannon_entropy(value: str) -> float:
    if not value: return 0.0
    n = len(value); counts = Counter(value)
    return round(-sum((c/n) * math.log2(c/n) for c in counts.values()), 3)

def looks_placeholder(value: str) -> bool:
    v = value.lower().strip(" '\"`")
    bad = {"test", "example", "changeme", "change_me", "your_api_key", "null", "undefined", "password", "secret"}
    return v in bad or len(set(v)) <= 2 or "your_" in v or "xxx" in v or "dummy" in v
