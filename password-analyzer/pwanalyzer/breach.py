"""Check a password against Have I Been Pwned using k-anonymity.

Only the first 5 chars of the SHA-1 hash are sent. The full password
(and full hash) never leave your machine.
"""
import hashlib
import urllib.request
import urllib.error

API_URL = "https://api.pwnedpasswords.com/range/{}"


def sha1_hex(password):
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def parse_range_response(body, suffix):
    for line in body.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return int(parts[1])
    return 0


def times_pwned(password, timeout=5):
    """Returns how many times the password showed up in breaches,
    or None if the lookup failed."""
    digest = sha1_hex(password)
    prefix, suffix = digest[:5], digest[5:]
    req = urllib.request.Request(
        API_URL.format(prefix),
        headers={"User-Agent": "pwanalyzer", "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None
    return parse_range_response(body, suffix)
