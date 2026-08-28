import pytest
from app.services.tools.handlers.url_canonicalizer import _canonicalize_url, _is_shortener
from app.services.tools.handlers.ip_classifier import is_blocked_ip
import ipaddress

def test_url_canonicalizer_tracking_params():
    raw = "https://example.com/login?utm_source=fb&utm_medium=cpc&session=123"
    canon = _canonicalize_url(raw)
    assert canon == "https://example.com/login?session=123"

def test_url_canonicalizer_ports_and_slashes():
    raw = "http://EXAMPLE.com:80/path/?gclid=123#frag"
    canon = _canonicalize_url(raw)
    assert canon == "http://example.com/path"

def test_is_shortener():
    assert _is_shortener("bit.ly") is True
    assert _is_shortener("example.com") is False

def test_ip_classifier_blocked():
    assert is_blocked_ip(ipaddress.ip_address("10.5.5.5")) is True
    assert is_blocked_ip(ipaddress.ip_address("192.168.1.1")) is True
    assert is_blocked_ip(ipaddress.ip_address("127.0.0.1")) is True
    assert is_blocked_ip(ipaddress.ip_address("8.8.8.8")) is False

