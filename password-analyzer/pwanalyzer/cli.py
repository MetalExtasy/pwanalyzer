import argparse
import getpass
import json
import sys

from .analyzer import analyze
from .breach import times_pwned

COLORS = {0: "\033[91m", 1: "\033[91m", 2: "\033[93m", 3: "\033[92m", 4: "\033[92m"}
RESET = "\033[0m"
BOLD = "\033[1m"


def bar(score, width=20):
    filled = int((score + 1) / 5 * width)
    return "#" * filled + "-" * (width - filled)


def mask(pw):
    if len(pw) <= 2:
        return "*" * len(pw)
    return pw[0] + "*" * (len(pw) - 2) + pw[-1]


def print_report(result, pwned=None, color=True):
    c = COLORS[result.score] if color else ""
    r = RESET if color else ""
    b = BOLD if color else ""

    print()
    print(f"{b}Strength:{r} {c}[{bar(result.score)}] {result.label}{r}")
    print(f"Length: {result.length}   Charset: {result.charset_size}   "
          f"Entropy: {result.effective_entropy:.1f} bits (max {result.raw_entropy:.1f})")

    if pwned is not None:
        if pwned > 0:
            print(f"{COLORS[0] if color else ''}Found in {pwned:,} data breaches!{r}")
        else:
            print("Not found in any known breach.")

    print(f"\n{b}Estimated time to crack:{r}")
    for scenario, t in result.crack_times.items():
        print(f"  {scenario:<45} {t}")

    if result.findings:
        print(f"\n{b}Issues found:{r}")
        for f in result.findings:
            print(f"  - {f}")

    if result.suggestions:
        print(f"\n{b}Suggestions:{r}")
        for s in result.suggestions:
            print(f"  - {s}")
    print()


def run_batch(path, check_breach, as_json):
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            pw = line.rstrip("\n")
            if not pw:
                continue
            res = analyze(pw)
            row = {"password": mask(pw), "score": res.score, "label": res.label,
                   "entropy": round(res.effective_entropy, 1)}
            if check_breach:
                row["pwned"] = times_pwned(pw)
            out.append(row)

    if as_json:
        print(json.dumps(out, indent=2))
        return

    print(f"{'password':<20} {'score':<6} {'label':<12} {'entropy':<8}" + (" pwned" if check_breach else ""))
    for row in out:
        line = f"{row['password']:<20} {row['score']:<6} {row['label']:<12} {row['entropy']:<8}"
        if check_breach:
            line += f" {row['pwned']}"
        print(line)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="pwcheck",
        description="Analyze password strength: entropy, patterns, crack time and breach exposure.",
    )
    parser.add_argument("password", nargs="?",
                        help="password to check (if omitted you'll be prompted, which keeps it out of shell history)")
    parser.add_argument("--hibp", action="store_true",
                        help="check Have I Been Pwned (k-anonymity, only 5 hash chars are sent)")
    parser.add_argument("--json", action="store_true", help="output JSON")
    parser.add_argument("--file", help="analyze every line in a file")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    if args.file:
        run_batch(args.file, args.hibp, args.json)
        return 0

    pw = args.password
    if pw is None:
        try:
            pw = getpass.getpass("Password: ")
        except (KeyboardInterrupt, EOFError):
            print()
            return 1
    if not pw:
        print("No password given.", file=sys.stderr)
        return 1

    result = analyze(pw)
    pwned = times_pwned(pw) if args.hibp else None
    if args.hibp and pwned is None and not args.json:
        print("(couldn't reach the HIBP API, skipping breach check)", file=sys.stderr)

    if args.json:
        data = result.to_dict()
        data["pwned"] = pwned
        print(json.dumps(data, indent=2))
    else:
        print_report(result, pwned, color=not args.no_color and sys.stdout.isatty())
    return 0


if __name__ == "__main__":
    sys.exit(main())
