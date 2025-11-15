# src/recondns/webscan.py

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

import requests

DEFAULT_HTTP_TIMEOUT = 5.0
DEFAULT_USER_AGENT = "recondns-web/0.1"


def _http_get(url: str, timeout: float) -> Tuple[int | None, str | None, Dict[str, str]]:
    """
    Fait un GET simple, renvoie (status, body, headers) ou (None, None, {}).
    """
    try:
        r = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": DEFAULT_USER_AGENT},
            allow_redirects=True,
        )
        return r.status_code, (r.text or ""), dict(r.headers)
    except requests.RequestException:
        return None, None, {}


def _extract_title(html: str | None) -> str | None:
    """
    Extrait le <title> de la page si présent.
    """
    if not html:
        return None
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    title = m.group(1)
    # Nettoyage espaces
    title = re.sub(r"\s+", " ", title).strip()
    return title or None


def _detect_tech(headers: Dict[str, str], body: str | None) -> List[str]:
    """
    Détecte rapidement quelques technos via les headers + body.
    (C'est volontairement simple, tu pourras enrichir plus tard.)
    """
    tech: List[str] = []

    server = headers.get("Server") or headers.get("server")
    powered = headers.get("X-Powered-By") or headers.get("x-powered-by")

    def add_from_header(val: str | None):
        if not val:
            return
        for piece in re.split(r"[;,]\s*", val):
            piece = piece.strip()
            if piece and piece not in tech:
                tech.append(piece)

    add_from_header(server)
    add_from_header(powered)

    if body:
        low = body.lower()
        if "wordpress" in low and "wordpress" not in tech:
            tech.append("wordpress")
        if "drupal" in low and "drupal" not in tech:
            tech.append("drupal")
        if "nginx" in low and "nginx" not in tech:
            tech.append("nginx")

    return tech


def scan_web_host(host: str, timeout: float = DEFAULT_HTTP_TIMEOUT) -> Dict[str, Any]:
    ports: Dict[int, str] = {}
    http_info: Dict[str, Any] = {}

    # ---- HTTP (80) ----
    status_http, body_http, headers_http = _http_get(f"http://{host}", timeout=timeout)
    redirect_to_https = False
    hsts = False

    if status_http is not None:
        ports[80] = "open"
        http_info["status"] = status_http
        http_info["title"] = _extract_title(body_http)
        http_info["server"] = headers_http.get("Server") or headers_http.get("server")
        http_info["powered_by"] = headers_http.get("X-Powered-By") or headers_http.get(
            "x-powered-by"
        )
        http_info["tech"] = _detect_tech(headers_http, body_http)

        # Redirect HTTP -> HTTPS ?
        location = headers_http.get("Location") or headers_http.get("location") or ""
        if status_http in (301, 302, 307, 308) and location.lower().startswith("https://"):
            redirect_to_https = True

        # HSTS ?
        hsts = any(h.lower() == "strict-transport-security" for h in headers_http.keys())
    else:
        ports[80] = "closed"

    # ---- HTTPS (443) ----
    status_https, body_https, headers_https = _http_get(f"https://{host}", timeout=timeout)
    if status_https is not None:
        ports[443] = "open"

        # si rien n'a été rempli par HTTP, on prend HTTPS comme source principale
        if "status" not in http_info:
            http_info["status"] = status_https
            http_info["title"] = _extract_title(body_https)
            http_info["server"] = headers_https.get("Server") or headers_https.get("server")
            http_info["powered_by"] = headers_https.get("X-Powered-By") or headers_https.get(
                "x-powered-by"
            )
            http_info["tech"] = _detect_tech(headers_https, body_https)
        else:
            # on merge juste les technos détectées sur HTTPS
            extra_tech = _detect_tech(headers_https, body_https)
            if extra_tech:
                http_info["tech"] = sorted(set((http_info.get("tech") or []) + extra_tech))

        # HSTS sur HTTPS aussi ?
        if any(h.lower() == "strict-transport-security" for h in headers_https.keys()):
            hsts = True
    else:
        ports[443] = "closed"

    # Normalisation
    if "tech" not in http_info:
        http_info["tech"] = []

    http_info["redirect_to_https"] = redirect_to_https
    http_info["hsts"] = hsts

    return {
        "ports": ports,
        "http": http_info,
    }


__all__ = ["scan_web_host"]
