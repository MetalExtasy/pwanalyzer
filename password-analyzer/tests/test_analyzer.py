from pwanalyzer import analyze
from pwanalyzer import patterns
from pwanalyzer.analyzer import charset_size, format_duration
from pwanalyzer.breach import parse_range_response, sha1_hex


def test_common_password_is_very_weak():
    r = analyze("password")
    assert r.score == 0
    assert any("well-known" in f for f in r.findings)


def test_leetspeak_is_detected():
    r = analyze("P@ssw0rd2024!")
    assert r.score <= 2
    assert any("common word" in f for f in r.findings)


def test_short_password_capped():
    r = analyze("Xk9#q")
    assert r.score <= 1


def test_random_long_password_is_strong():
    r = analyze("vT8#qL2!mZr9@wXe")
    assert r.score >= 3


def test_passphrase_is_strong():
    r = analyze("correct-horse-battery-staple-violin")
    assert r.score >= 3


def test_sequences():
    found = patterns.find_sequences("xxabcdxx987")
    tokens = {m.token for m in found}
    assert "abcd" in tokens
    assert "987" in tokens


def test_keyboard_walk():
    found = patterns.find_keyboard_walks("zzqwertyzz")
    assert any(m.token == "qwerty" for m in found)


def test_repeats():
    found = patterns.find_repeats("aaaaXYXYXY")
    tokens = {m.token for m in found}
    assert "aaaa" in tokens
    assert "XYXYXY" in tokens


def test_years():
    found = patterns.find_years("ansel1998")
    assert found and found[0].token == "1998"


def test_charset_size():
    assert charset_size("abc") == 26
    assert charset_size("aB3") == 62
    assert charset_size("aB3!") == 62 + 32


def test_format_duration():
    assert format_duration(0.5) == "instant"
    assert format_duration(90) == "1 minute"
    assert format_duration(86400 * 3) == "3 days"


def test_hibp_parsing():
    digest = sha1_hex("password")
    suffix = digest[5:]
    body = f"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{suffix}:9545824\r\n"
    assert parse_range_response(body, suffix) == 9545824
    assert parse_range_response(body, "NOPE") == 0
