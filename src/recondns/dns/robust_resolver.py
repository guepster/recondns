import dns.resolver
from cachetools import TTLCache

# --- Defaults (nécessaires au resolver)
DEFAULT_TIMEOUT = 3.0
DEFAULT_RETRIES = 1

# --- Cache DNS global
DNS_CACHE = TTLCache(maxsize=5000, ttl=30)


def make_resolver(
    nameservers=None,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)

    # Normalise nameservers en liste de chaînes
    ns_list = []
    if isinstance(nameservers, str):
        # "1.1.1.1,8.8.8.8"
        ns_list = [s.strip() for s in nameservers.split(",") if s.strip()]
    elif isinstance(nameservers, list | tuple):
        ns_list = [str(s).strip() for s in nameservers if str(s).strip()]

    # Si rien fourni, on prend ceux du système, sinon fallback sur un DNS public
    if not ns_list:
        current = list(getattr(r, "nameservers", []) or [])
        if current:
            ns_list = current
        else:
            ns_list = ["8.8.8.8"]

    r.nameservers = ns_list
    r.timeout = timeout
    r.lifetime = timeout
    return r


def resolve_cached(
    hostname: str,
    qtype: str,
    resolver: dns.resolver.Resolver,
) -> list[str]:
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
