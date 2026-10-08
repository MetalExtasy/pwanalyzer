# pwanalyzer

A command-line password strength analyzer. Instead of just checking "has an uppercase letter and a number", it looks for the patterns real cracking tools exploit and estimates how long a password would actually survive.

## Features

- **Entropy calculation**: raw entropy based on length and character set, plus an *effective* entropy that accounts for detected patterns
- **Pattern detection**: common passwords, dictionary words (including leetspeak like `p@ssw0rd`), sequences (`abc`, `987`), keyboard walks (`qwerty`, `asdf`), repeated characters/chunks, and years
- **Crack time estimates** across four attack scenarios, from rate-limited online attacks to offline GPU cracking of fast hashes
- **Breach check** against Have I Been Pwned using k-anonymity (only the first 5 characters of the SHA-1 hash leave your machine)
- **Batch mode** to audit a file of passwords, with masked output
- JSON output for scripting
- No third-party dependencies

## Install

```bash
git clone https://github.com/MetalExtasy/pwanalyzer.git
cd pwanalyzer
pip install -e .
```

## Usage

```bash
pwcheck                      # prompts for password (keeps it out of shell history)
pwcheck "MyP@ssw0rd"         # pass it directly
pwcheck --hibp               # also check breach databases
pwcheck "hunter2" --json     # machine-readable output
pwcheck --file list.txt      # audit many passwords
```

You can also run it without installing: `python -m pwanalyzer`.

### Example

```
$ pwcheck Ansel1998

Strength: [############--------] Fair
Length: 9   Charset: 62   Entropy: 36.4 bits (max 53.6)

Estimated time to crack:
  Online, rate limited (100/hour)               centuries+
  Online, no rate limit (10/sec)                1 century
  Offline, slow hash like bcrypt (10k/sec)      1 month
  Offline, fast hash like MD5 (10B/sec)         4 seconds

Issues found:
  - Contains what looks like a year: '1998'

Suggestions:
  - Years (birthdays, graduation, etc.) are easy to guess. Leave them out.
  - Use at least 12 characters. Length matters more than complexity.
```

## How the scoring works

1. **Raw entropy** = `length × log2(charset size)`. This is the best case, assuming every character is random.
2. The password is scanned for patterns. Each match gets a "cost": roughly how many bits an attacker needs to guess that chunk. For example, a word from a 200-entry list costs about 7.6 bits no matter how long it is, and a year costs about 6.6 bits.
3. Overlapping matches are resolved greedily by picking the ones that save the most bits.
4. **Effective entropy** = cost of matched chunks + full entropy for the remaining characters.
5. Score (0–4) is based on effective entropy, capped at 1 for anything under 8 characters.

Crack time assumes the attacker finds the password halfway through the search space on average (`2^entropy / 2` guesses).

## Limitations

- The bundled wordlist is small. For real audits, replace `pwanalyzer/common_passwords.txt` with a larger list such as SecLists' `10k-most-common.txt`.
- Entropy estimates are approximations. Tools like `zxcvbn` use much larger dictionaries and more detailed models.
- Never type real passwords into tools you don't trust, including this one. Read the code first.

## Tests

```bash
pip install pytest
pytest
```

## License

MIT
