import math
import string
from dataclasses import dataclass, field
from pathlib import Path

from . import patterns

DATA_FILE = Path(__file__).parent / "common_passwords.txt"

# guesses per second for different attack scenarios
ATTACK_SCENARIOS = {
    "Online, rate limited (100/hour)": 100 / 3600,
    "Online, no rate limit (10/sec)": 10,
    "Offline, slow hash like bcrypt (10k/sec)": 1e4,
    "Offline, fast hash like MD5 (10B/sec)": 1e10,
}

LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]

_common_cache = None


def load_common_passwords():
    global _common_cache
    if _common_cache is None:
        lines = DATA_FILE.read_text(encoding="utf-8").splitlines()
        words = [w.strip().lower() for w in lines if w.strip() and not w.startswith("#")]
        # keep rank order, first occurrence wins
        _common_cache = {}
        for rank, w in enumerate(words, start=1):
            _common_cache.setdefault(w, rank)
    return _common_cache


@dataclass
class Result:
    length: int
    charset_size: int
    raw_entropy: float
    effective_entropy: float
    score: int
    label: str
    crack_times: dict
    findings: list = field(default_factory=list)
    suggestions: list = field(default_factory=list)

    def to_dict(self):
        return {
            "length": self.length,
            "charset_size": self.charset_size,
            "raw_entropy": round(self.raw_entropy, 2),
            "effective_entropy": round(self.effective_entropy, 2),
            "score": self.score,
            "label": self.label,
            "crack_times": self.crack_times,
            "findings": self.findings,
            "suggestions": self.suggestions,
        }


def charset_size(pw):
    size = 0
    if any(c in string.ascii_lowercase for c in pw):
        size += 26
    if any(c in string.ascii_uppercase for c in pw):
        size += 26
    if any(c in string.digits for c in pw):
        size += 10
    if any(c in string.punctuation for c in pw):
        size += len(string.punctuation)
    if any(c in string.whitespace for c in pw):
        size += 1
    if any(ord(c) > 127 for c in pw):
        size += 100  # rough guess for unicode
    return size


def _cost(match, pool, wordlist_size):
    """Rough number of bits an attacker needs to guess this piece."""
    if match.kind == "word":
        bits = math.log2(wordlist_size)
        if match.token != match.token.lower():
            bits += 1  # capitalization variant
        if patterns.unleet(match.token) != match.token.lower():
            bits += 1  # leet substitution variant
        return bits
    if match.kind == "year":
        return math.log2(100)
    if match.kind == "sequence":
        return math.log2(26) + math.log2(match.length) + 1
    if match.kind == "keyboard":
        return math.log2(4 * 10) + math.log2(match.length)
    if match.kind == "repeat":
        unit = len(set(match.token))
        return unit * math.log2(max(pool, 2)) + math.log2(match.length)
    return match.length * math.log2(max(pool, 2))


def _pick_matches(matches, bits_per_char):
    """Greedy: take the matches that save the most bits, no overlaps."""
    matches = sorted(matches, key=lambda m: m.length * bits_per_char - m.cost, reverse=True)
    taken = []
    used = set()
    for m in matches:
        span = set(range(m.start, m.end))
        if span & used:
            continue
        if m.length * bits_per_char <= m.cost:
            continue
        taken.append(m)
        used |= span
    return sorted(taken, key=lambda m: m.start), used


def format_duration(seconds):
    if seconds < 1:
        return "instant"
    units = [
        ("century", 3153600000), ("year", 31536000), ("month", 2592000),
        ("day", 86400), ("hour", 3600), ("minute", 60), ("second", 1),
    ]
    if seconds >= 100 * 3153600000:
        return "centuries+"
    for name, size in units:
        if seconds >= size:
            n = int(seconds // size)
            plural = "centuries" if name == "century" and n != 1 else name + ("s" if n != 1 else "")
            return f"{n} {plural}"
    return "instant"


def _score(entropy, length):
    if entropy < 28:
        s = 0
    elif entropy < 36:
        s = 1
    elif entropy < 60:
        s = 2
    elif entropy < 80:
        s = 3
    else:
        s = 4
    if length < 8:
        s = min(s, 1)
    return s


def analyze(password, common=None):
    if common is None:
        common = load_common_passwords()

    pool = charset_size(password)
    length = len(password)
    bpc = math.log2(pool) if pool > 1 else 0
    raw = length * bpc

    findings = []
    suggestions = []

    rank = common.get(password.lower())
    if rank:
        effective = math.log2(rank + 1)
        findings.append(f"This is a well-known password (#{rank} on the common list).")
        suggestions.append("Never use this password anywhere. It's one of the first things attackers try.")
    else:
        found = []
        found += patterns.find_words(password, common)
        found += patterns.find_sequences(password)
        found += patterns.find_repeats(password)
        found += patterns.find_keyboard_walks(password)
        found += patterns.find_years(password)

        for m in found:
            m.cost = _cost(m, pool, len(common))

        picked, covered = _pick_matches(found, bpc)
        uncovered = length - len(covered)
        effective = uncovered * bpc + sum(m.cost for m in picked)

        for m in picked:
            if m.kind == "word":
                findings.append(f"Contains a common word or password: '{m.token}'")
            elif m.kind == "sequence":
                findings.append(f"Contains a sequence: '{m.token}'")
            elif m.kind == "keyboard":
                findings.append(f"Contains a keyboard pattern: '{m.token}'")
            elif m.kind == "repeat":
                findings.append(f"Contains repeated characters: '{m.token}'")
            elif m.kind == "year":
                findings.append(f"Contains what looks like a year: '{m.token}'")

        kinds = {m.kind for m in picked}
        if "word" in kinds:
            suggestions.append("Swapping letters for symbols (a -> @) doesn't fool cracking tools. Avoid real words or use several random ones.")
        if "year" in kinds:
            suggestions.append("Years (birthdays, graduation, etc.) are easy to guess. Leave them out.")
        if kinds & {"sequence", "keyboard", "repeat"}:
            suggestions.append("Avoid predictable patterns like 1234, qwerty or aaaa.")

    if length < 12:
        suggestions.append("Use at least 12 characters. Length matters more than complexity.")
    if pool <= 26:
        suggestions.append("Mix in uppercase, digits or symbols, or make it a lot longer.")

    effective = max(0.0, min(effective, raw))
    score = _score(effective, length)

    if score >= 3 and not suggestions:
        suggestions.append("Looks good. Store it in a password manager and don't reuse it.")

    guesses = 2 ** effective / 2  # on average you find it halfway through
    crack_times = {name: format_duration(guesses / rate) for name, rate in ATTACK_SCENARIOS.items()}

    return Result(
        length=length,
        charset_size=pool,
        raw_entropy=raw,
        effective_entropy=effective,
        score=score,
        label=LABELS[score],
        crack_times=crack_times,
        findings=findings,
        suggestions=suggestions,
    )
