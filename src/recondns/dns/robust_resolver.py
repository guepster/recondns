from __future__ import annotations

import dns.resolver
from cachetools import TTLCache
from typing import List, Optional, Dict


# Cache DNS TTL (modifiable via CLI)
DNS_CACHE = TTLCache(maxsize=5000, ttl=30)


def make_resolver(servers: List[str], timeout: float = 2.0, retries: int = 1) -> dns.resolver.Resolver:
    """
    Crée un résolveur DNS robuste avec timeout et retries.
    """
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = servers
    r.lifetime = timeout
    r.retry_servfail = False
    r.timeout = timeout
    return r


def resolve_cached(
    hostname: str,
    qtype: str,
    resolver: dns.resolver.Resolver,
) -> List[str]:
    """
    Essaie de résoudre <hostname>.<qtype> avec cache TTL.
    """
    key = f"{hostname}|{qtype}"

    # Cache hit
    if key in DNS_CACHE:
        return DNS_CACHE[key]

    try:
        ans = resolver.resolve(hostname, qtype)
        out = [r.to_text() for r in ans]
    except Exception:
        out = []

    DNS_CACHE[key] = out
    return out
