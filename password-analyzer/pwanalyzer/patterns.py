import re
from dataclasses import dataclass

LEET_MAP = {
    "4": "a", "@": "a", "3": "e", "1": "i", "!": "i",
    "0": "o", "5": "s", "$": "s", "7": "t", "+": "t",
}

KEYBOARD_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]

YEAR_RE = re.compile(r"(19[4-9]\d|20[0-3]\d)")
REPEAT_CHAR_RE = re.compile(r"(.)\1{2,}")
REPEAT_CHUNK_RE = re.compile(r"(.{2,}?)\1+")


@dataclass
class Match:
    kind: str
    start: int
    end: int  # exclusive
    token: str
    cost: float = 0.0  # estimated bits needed to guess this piece

    @property
    def length(self):
        return self.end - self.start


def unleet(text):
    return "".join(LEET_MAP.get(c, c) for c in text.lower())


def find_sequences(pw, min_len=3):
    """abc, 789, zyx etc. Only within letters or within digits."""
    matches = []
    i = 0
    while i < len(pw) - 1:
        a, b = pw[i], pw[i + 1]
        same_class = (a.isdigit() and b.isdigit()) or (a.isalpha() and b.isalpha())
        step = ord(b.lower()) - ord(a.lower())
        if not same_class or step not in (1, -1):
            i += 1
            continue
        j = i + 1
        while j < len(pw) - 1:
            c, d = pw[j], pw[j + 1]
            ok = (c.isdigit() and d.isdigit()) or (c.isalpha() and d.isalpha())
            if ok and ord(d.lower()) - ord(c.lower()) == step:
                j += 1
            else:
                break
        if j - i + 1 >= min_len:
            matches.append(Match("sequence", i, j + 1, pw[i:j + 1]))
        i = j
    return matches


def find_repeats(pw):
    matches = []
    for m in REPEAT_CHAR_RE.finditer(pw):
        matches.append(Match("repeat", m.start(), m.end(), m.group(0)))
    for m in REPEAT_CHUNK_RE.finditer(pw):
        # skip single-char repeats, already caught above
        if len(set(m.group(0))) > 1:
            matches.append(Match("repeat", m.start(), m.end(), m.group(0)))
    return matches


def find_keyboard_walks(pw, min_len=4):
    lowered = pw.lower()
    matches = []
    for row in KEYBOARD_ROWS:
        for line in (row, row[::-1]):
            for size in range(len(line), min_len - 1, -1):
                for k in range(len(line) - size + 1):
                    chunk = line[k:k + size]
                    idx = lowered.find(chunk)
                    while idx != -1:
                        matches.append(Match("keyboard", idx, idx + size, pw[idx:idx + size]))
                        idx = lowered.find(chunk, idx + 1)
    return matches


def find_years(pw):
    return [Match("year", m.start(), m.end(), m.group(0)) for m in YEAR_RE.finditer(pw)]


def find_words(pw, wordlist, min_len=4):
    """Look for known words / common passwords hidden inside the password,
    including leetspeak versions (p@ssw0rd -> password)."""
    matches = []
    normalized = unleet(pw)
    n = len(pw)
    for i in range(n):
        for j in range(n, i + min_len - 1, -1):
            piece = normalized[i:j]
            if piece in wordlist:
                matches.append(Match("word", i, j, pw[i:j]))
                break  # longest match from this start is enough
    return matches
