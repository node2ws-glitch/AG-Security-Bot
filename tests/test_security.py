import pytest
from security import parse_public_ip, validate_domain, key_digest

def test_public_ip():
    assert parse_public_ip("8.8.8.8") == "8.8.8.8"

@pytest.mark.parametrize("ip", ["127.0.0.1", "192.168.1.2", "10.0.0.1"])
def test_private_ips_rejected(ip):
    with pytest.raises(ValueError):
        parse_public_ip(ip)

def test_domain_normalized():
    assert validate_domain("Example.COM.") == "example.com"

def test_bad_domain_rejected():
    with pytest.raises(ValueError):
        validate_domain("https://example.com/path")

def test_key_digest():
    assert key_digest("abc") != key_digest("def")
