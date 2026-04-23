# phish_utils.py
import os
import re
import socket
import ssl
import base64
from urllib.parse import urlparse
import requests
import tldextract
import validators
import whois
from datetime import datetime, timezone

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly"
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "secure", "bank", "ebay", "paypal", "update", "verify",
    "account", "confirm", "password", "webscr"
]

def is_ip(domain):
    try:
        socket.inet_aton(domain)
        return True
    except Exception:
        return False

def get_hostname_parts(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = ext.registered_domain or parsed.hostname or ""
    subdomain = ext.subdomain or ""
    return parsed, domain.lower(), subdomain.lower()

def check_ssl_certificate(hostname, port=443, timeout=4):
    try:
        conn = socket.create_connection((hostname, port), timeout=timeout)
        context = ssl.create_default_context()
        sock = context.wrap_socket(conn, server_hostname=hostname)
        cert = sock.getpeercert()
        issuer = None
        try:
            issuer = dict(x[0] for x in cert.get('issuer', ())).get('commonName', '')
        except Exception:
            issuer = None
        not_after = cert.get('notAfter')
        sock.close()
        return True, issuer, not_after
    except Exception:
        return False, None, None

def fetch_page(url, timeout=6):
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "PhishDetect/1.0"})
        return resp.status_code, resp.text
    except Exception:
        return None, ""

def whois_domain_age(domain):
    """Return domain age in days or None on failure"""
    try:
        w = whois.whois(domain)
        # try creation_date field (may be list)
        created = w.creation_date
        if not created:
            return None
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, str):
            created = datetime.fromisoformat(created)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - created
        return age.days
    except Exception:
        return None

def vt_lookup(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return False, "No API key provided"
    try:
        b64 = base64.urlsafe_b64encode(url.encode()).rstrip(b'=').decode()
        headers = {"x-apikey": api_key}
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{b64}", headers=headers, timeout=8)
        if r.status_code == 200:
            j = r.json()
            stats = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            positives = sum(v for k, v in stats.items() if k != "harmless")
            return True, {"positives": positives, "stats": stats}
        else:
            return False, f"VT HTTP {r.status_code}"
    except Exception as e:
        return False, f"VT error: {e}"

def phishtank_lookup(url):
    """PhishTank simple lookup using API key env PHISHTANK_API_KEY.
       Note: PhishTank API details can change; this uses the 'checkurl' style JSON endpoint assumption.
    """
    api_key = os.getenv("PHISHTANK_API_KEY")
    if not api_key:
        return False, "No API key provided"
    try:
        # example endpoint style — if your PhishTank account uses another endpoint adjust here
        r = requests.post("https://checkurl.phishtank.com/checkurl/", data={"url": url, "format":"json", "app_key": api_key}, timeout=8)
        if r.status_code == 200:
            j = r.json()
            return True, j
        else:
            return False, f"PhishTank HTTP {r.status_code}"
    except Exception as e:
        return False, f"PhishTank error: {e}"

def heuristic_features(url):
    """Return a dict of heuristic features (ints/bools) and reasons list."""
    reasons = []
    score = 0
    parsed, domain, subdomain = get_hostname_parts(url)

    if not validators.url(url):
        reasons.append("Invalid URL format")
        return {"score": 3, "reasons": reasons, "features": {}}

    hostname = parsed.hostname or ""
    features = {}
    # IP in host
    features["is_ip"] = int(is_ip(hostname))
    if features["is_ip"]:
        reasons.append("Hostname is IP address")
        score += 2

    # @ symbol
    features["has_at"] = int("@" in url)
    if features["has_at"]:
        reasons.append("'@' in URL")
        score += 1

    # URL length
    features["len_url"] = len(url)
    if len(url) > 75:
        reasons.append("Long URL")
        score += 1

    # subdomain count
    features["subdomain_count"] = len(subdomain.split('.')) if subdomain else 0
    if features["subdomain_count"] >= 3:
        reasons.append("Many subdomains")
        score += 1

    # hyphen in domain
    ext = tldextract.extract(url)
    features["hyphen_in_domain"] = int("-" in (ext.domain or ""))
    if features["hyphen_in_domain"]:
        reasons.append("Hyphen in domain")
        score += 1

    # url shortener
    features["is_shortener"] = int(domain in URL_SHORTENERS)
    if features["is_shortener"]:
        reasons.append("URL shortener used")
        score += 2

    # HTTPS
    features["is_https"] = int(parsed.scheme == "https")
    if parsed.scheme != "https":
        reasons.append("Not HTTPS")
        score += 1

    # suspicious keywords in path
    path = (parsed.path or "").lower()
    features["susp_keyword"] = 0
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in path:
            features["susp_keyword"] = 1
            reasons.append(f"Suspicious keyword in path: {kw}")
            score += 1
            break

    # fetch page and look for password input
    status, body = fetch_page(url)
    features["has_password_field"] = 0
    features["external_links_count"] = 0
    if status and body:
        if re.search(r'<input[^>]+type=["\']?password', body, re.I):
            features["has_password_field"] = 1
            reasons.append("Page contains password input")
            score += 2
        links = re.findall(r'href=["\'](.*?)["\']', body, re.I)
        external = 0
        for link in links[:200]:
            try:
                if link.startswith("http"):
                    p = urlparse(link)
                    if p.hostname and p.hostname != parsed.hostname:
                        external += 1
                if external > 10: break
            except: continue
        features["external_links_count"] = external
        if external > 10:
            reasons.append(f"Many external links ({external})")
            score += 1

    # SSL check
    features["ssl_valid"] = 0
    if parsed.scheme == "https" and parsed.hostname:
        valid_cert, issuer, not_after = check_ssl_certificate(parsed.hostname)
        features["ssl_valid"] = int(valid_cert)
        if not valid_cert:
            reasons.append("SSL certificate not valid / connection failed")
            score += 1

    # WHOIS domain age
    domain_age = whois_domain_age(domain)
    features["domain_age_days"] = domain_age if domain_age is not None else -1
    if domain_age is None:
        reasons.append("WHOIS age unknown")
    else:
        # newly registered domains (<90 days) are suspicious
        if domain_age < 90:
            reasons.append(f"Domain age low: {domain_age} days")
            score += 1

    features["score"] = score
    return {"score": score, "reasons": reasons, "features": features}