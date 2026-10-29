import hashlib
import ipaddress
import socket
from urllib.parse import urlparse
import dns.resolver

def key_digest(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()

def parse_public_ip(value: str) -> str:
    ip = ipaddress.ip_address(value.strip())
    if not ip.is_global:
        raise ValueError("Only public, globally routable IPs are supported.")
    return str(ip)

def validate_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain or len(domain) > 253 or "/" in domain or "://" in domain:
        raise ValueError("Enter a domain name, not a URL or path.")
    if domain == "localhost" or "." not in domain:
        raise ValueError("Enter a public domain name.")
    labels = domain.split(".")
    if any(not x or len(x) > 63 or x.startswith("-") or x.endswith("-")
           or not all(c.isalnum() or c == "-" for c in x) for x in labels):
        raise ValueError("Invalid domain format.")
    return domain

def resolve_domain(domain: str) -> dict:
    domain = validate_domain(domain)
    result = {}
    for kind in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            result[kind] = [str(r).strip('"') for r in dns.resolver.resolve(domain, kind, lifetime=4)][:10]
        except Exception:
            result[kind] = []
    return result

def validate_authorized_https_url(value: str, allowlist: set[str]) -> str:
    raw = value.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Provide an HTTPS URL on your authorized domain allowlist.")
    host = parsed.hostname.lower().rstrip(".")
    domain = validate_domain(host)
    if not any(domain == allowed or domain.endswith("." + allowed) for allowed in allowlist):
        raise ValueError("Domain is not in AUTHORIZED_TEST_DOMAINS.")
    infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    ips = {info[4][0] for info in infos}
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise ValueError("Domain resolves to a private or non-public address; blocked.")
    return raw
