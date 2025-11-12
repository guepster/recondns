import dns.resolver
import dns.reversename
import requests
import time
import os
import yaml
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from recondns.sources.passive import gather_passive

# Logging basic
logger = logging.getLogger("recondns")
if not logger.handlers:
    h = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    h.setFormatter(formatter)
    logger.addHandler(h)
logger.setLevel(logging.INFO)

# CRT.SH defaults
DEFAULT_CRTSH_SLEEP = 1.0
DEFAULT_CRTSH_RETRIES = 3
DEFAULT_CRTSH_TIMEOUT = 10.0

# HTTP / takeover defaults
HTTP_TIMEOUT = 6.0
USER_AGENT = "recondns/0.2 (+https://github.com/yourname/recondns-cli)"
HTTP_RETRIES = 2
HTTP_BACKOFF = 1.5  # multiplier
DEFAULT_MAX_WORKERS = 8
DEFAULT_TAKEOVER_DELAY = 0.2  # delay between host checks to be polite

def resource_path(rel: str):
    base = os.path.dirname(__file__)
    return os.path.join(base, rel)

def load_takeover_signatures(path: Optional[str] = None) -> List[dict]:
    if path is None:
        path = resource_path("signatures.yaml")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, list):
                return data
            return []
    except FileNotFoundError:
        logger.warning("signatures.yaml not found at %s", path)
        return []
    except Exception as e:
        logger.exception("Failed to load signatures.yaml: %s", e)
        return []

def make_resolver(resolver_ip: Optional[str], timeout: float = 5.0):
    r = dns.resolver.Resolver(configure=True)
    r.timeout = timeout
    r.lifetime = timeout
    if resolver_ip:
        r.nameservers = [resolver_ip]
    return r

def get_dns_records(domain: str, record_types: Optional[List[str]] = None,
                    timeout: float = 5.0, resolver_ip: Optional[str] = None) -> Dict[str, List[str]]:
    if record_types is None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    res = make_resolver(resolver_ip, timeout=timeout)
    out: Dict[str, List[str]] = {}
    for rtype in record_types:
        try:
            answers = res.resolve(domain, rtype, raise_on_no_answer=False)
            values: List[str] = []
            if answers is not None:
                for r in answers:
                    values.append(r.to_text())
            out[rtype] = values
        except Exception:
            out[rtype] = []
    return out

def reverse_lookup(ip: str, resolver_ip: Optional[str] = None) -> Optional[str]:
    try:
        rev = dns.reversename.from_address(ip)
        res = make_resolver(resolver_ip)
        return str(res.resolve(rev, "PTR")[0])
    except Exception:
        return None

def fetch_crtsh_subdomains(domain: str, timeout: float = DEFAULT_CRTSH_TIMEOUT,
                           sleep_between: float = DEFAULT_CRTSH_SLEEP,
                           retries: int = DEFAULT_CRTSH_RETRIES) -> List[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    attempt = 0
    while attempt < retries:
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
            if r.status_code == 200:
                data = r.json()
                subs = set()
                for entry in data:
                    name = entry.get("name_value") or entry.get("common_name")
                    if not name:
                        continue
                    for n in name.splitlines():
                        n = n.strip()
                        if n.endswith(domain):
                            subs.add(n.lstrip("*."))
                time.sleep(sleep_between)
                return sorted(subs)
            elif r.status_code in (429, 502, 503, 504):
                attempt += 1
                backoff = 1 + attempt * 2
                logger.debug("crt.sh returned %s — backoff %s", r.status_code, backoff)
                time.sleep(backoff)
            else:
                logger.debug("crt.sh returned status %s", r.status_code)
                return []
        except requests.exceptions.RequestException as e:
            attempt += 1
            logger.debug("crt.sh request exception: %s — attempt %s", e, attempt)
            time.sleep(1 + attempt)
    return []

def _http_get_with_retries(host: str, scheme: str = "http", timeout: float = HTTP_TIMEOUT,
                           retries: int = HTTP_RETRIES, backoff: float = HTTP_BACKOFF) -> (Optional[int], Optional[str], Optional[dict]):
    url = f"{scheme}://{host}"
    headers = {"User-Agent": USER_AGENT}
    attempt = 0
    delay = 1.0
    while attempt <= retries:
        try:
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            # return status, text, headers
            return r.status_code, (r.text or ""), dict(r.headers)
        except requests.RequestException as e:
            attempt += 1
            if attempt > retries:
                logger.debug("HTTP GET failed for %s after %s attempts: %s", url, attempt, e)
                return None, None, None
            # exponential-ish backoff
            time.sleep(delay)
            delay *= backoff
    return None, None, None

def _match_signature_from_response(sig: dict, status: Optional[int], body: Optional[str], headers: Optional[dict]) -> bool:
    method = sig.get("method", "body_contains")
    match = (sig.get("match") or "").lower()
    expected_status = sig.get("status")
    if method == "body_contains" and match and body:
        return match in body.lower()
    if method == "status" and expected_status and status is not None:
        return status == expected_status
    if method == "header_contains" and match and headers:
        header_name = sig.get("header", "").lower()
        for hn, hv in headers.items():
            if hn.lower() == header_name and match in str(hv).lower():
                return True
    if method == "status_or_body":
        if expected_status and status == expected_status:
            return True
        if match and body and match in body.lower():
            return True
    return False

def check_single_host_takeover(host: str, signatures: List[dict], verbose: bool = False) -> List[dict]:
    alerts: List[dict] = []
    if not signatures:
        return alerts
    # try http then https
    for scheme in ("http", "https"):
        status, body, headers = _http_get_with_retries(host, scheme=scheme)
        if status is None:
            if verbose:
                logger.debug("No response for %s://%s", scheme, host)
            continue
        if verbose:
            logger.debug("Checked %s://%s -> status %s", scheme, host, status)
        for sig in signatures:
            try:
                if _match_signature_from_response(sig, status, body, headers):
                    alerts.append({
                        "host": host,
                        "provider": sig.get("provider") or sig.get("id"),
                        "method": sig.get("method"),
                        "match": sig.get("match"),
                        "scheme": scheme,
                        "status": status
                    })
            except Exception:
                # do not let signature matching crash
                continue
    return alerts

def check_hosts_takeover_parallel(hosts: List[str], signatures: List[dict],
                                  max_workers: int = DEFAULT_MAX_WORKERS,
                                  delay_between: float = DEFAULT_TAKEOVER_DELAY,
                                  verbose: bool = False) -> List[dict]:
    results: List[dict] = []
    if not hosts:
        return results
    # ThreadPool for concurrency
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_host = {ex.submit(check_single_host_takeover, h, signatures, verbose): h for h in hosts}
        for fut in as_completed(future_to_host):
            h = future_to_host[fut]
            try:
                alerts = fut.result()
                if alerts:
                    results.extend(alerts)
            except Exception as e:
                logger.debug("Error checking host %s: %s", h, e)
            # polite delay between consuming futures (helps reduce bursts)
            time.sleep(delay_between)
    return results

def snapshot_domain(domain: str, use_crt: bool = True,
                    resolver_ip: Optional[str] = None,
                    resolve_limit: Optional[int] = None,
                    check_takeover: bool = False,
                    signatures_path: Optional[str] = None,
                    takeover_max_workers: int = DEFAULT_MAX_WORKERS,
                    takeover_delay: float = DEFAULT_TAKEOVER_DELAY,
                    takeover_verbose: bool = False) -> Dict[str, Any]:
    now = datetime.utcnow().isoformat() + "Z"
    dns_records = get_dns_records(domain, resolver_ip=resolver_ip)
    crt_subs: List[str] = []
    passive_subs = gather_passive(domain, sources=chosen_sources)
    all_subdomains |= passive_subs
    subs_data: Dict[str, Dict[str, List[str]]] = {}
    takeover_checks: List[dict] = []

    signatures = []
    if check_takeover:
        signatures = load_takeover_signatures(signatures_path)

    if use_crt:
        crt_subs = fetch_crtsh_subdomains(domain)
        if resolve_limit is not None and isinstance(resolve_limit, int):
            to_resolve = crt_subs[:resolve_limit]
        else:
            to_resolve = crt_subs
        for s in to_resolve:
            subs_data[s] = {"A": get_dns_records(s, ["A"], resolver_ip=resolver_ip).get("A", [])}

    if check_takeover:
        hosts_to_check = set()
        hosts_to_check.add(domain)
        # CNAMEs
        for c in dns_records.get("CNAME", []):
            hosts_to_check.add(c.strip().rstrip("."))
        # include crt subdomains (prefer resolved subset to limit calls)
        for s in list(subs_data.keys()):
            hosts_to_check.add(s)
        # add de-duplicated list
        hosts_list = [h for h in sorted(hosts_to_check) if any(ch.isalpha() for ch in h)]
        if takeover_verbose:
            logger.info("Takeover: checking %s hosts (workers=%s, delay=%s)", len(hosts_list), takeover_max_workers, takeover_delay)
        takeover_checks = check_hosts_takeover_parallel(hosts_list, signatures,
                                                       max_workers=takeover_max_workers,
                                                       delay_between=takeover_delay,
                                                       verbose=takeover_verbose)
    report = {
        "domain": domain,
        "timestamp": now,
        "dns": dns_records,
        "crt_subdomains": crt_subs,
        "crt_subdomains_resolved": subs_data,
        "takeover_checks": takeover_checks
    }
    return report
