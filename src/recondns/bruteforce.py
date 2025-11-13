from __future__ import annotations


def _load_wordlist(path: str) -> list[str]:
    """Charge une wordlist (une entrée par ligne)."""
    words: list[str] = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if not w or w.startswith("#"):
                continue
            words.append(w.lower())
    return words


def bruteforce_subdomains(root: str, wordlist_path: str, depth: int = 1) -> set[str]:
    """
    Génère des sous-domaines de type <word>.<root>.

    depth est là pour le futur (permutations plus avancées),
    pour l'instant on reste sur du léger.
    """
    root = root.strip().strip(".").lower()
    subs: set[str] = set()

    words = _load_wordlist(wordlist_path)
    for w in words:
        subs.add(f"{w}.{root}")

    # Un petit set de préfixes communs (au cas où la wordlist ne les ait pas)
    common_prefixes = ["www", "dev", "api", "staging"]
    for p in common_prefixes:
        subs.add(f"{p}.{root}")

    return subs
