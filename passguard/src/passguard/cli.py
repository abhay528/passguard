"""Command-line interface for PassGuard.

Examples
--------
    # Analyze a password interactively (input is hidden)
    passguard analyze

    # Analyze a password passed on the command line
    passguard analyze --password "correct horse battery staple"

    # Also check against Have I Been Pwned and output JSON
    passguard analyze -p "hunter2" --breach --json

    # Generate a strong password
    passguard generate --length 20

    # Register a password for a user, rejecting reuse
    passguard register --user alice --db history.db
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from .analyzer import PasswordAnalyzer, Strength
from .database import PasswordHistory
from .generator import generate_passphrase, generate_password

_COLORS = {
    Strength.VERY_WEAK: "\033[91m",   # red
    Strength.WEAK: "\033[91m",        # red
    Strength.FAIR: "\033[93m",        # yellow
    Strength.STRONG: "\033[92m",      # green
    Strength.VERY_STRONG: "\033[92m", # green
}
_RESET = "\033[0m"


def _bar(score: int, width: int = 20) -> str:
    filled = round(score / 100 * width)
    return "\u2588" * filled + "\u2591" * (width - filled)


def _read_password(provided: str | None) -> str:
    if provided is not None:
        return provided
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass("Enter password: ")


def _print_report(result, *, use_color: bool) -> None:
    color = _COLORS[result.strength] if use_color else ""
    reset = _RESET if use_color else ""
    print()
    print(f"  Strength : {color}{result.strength.label} ({result.score}/100){reset}")
    print(f"  Meter    : {color}{_bar(result.score)}{reset}")
    print(f"  Length   : {result.length}")
    print(f"  Entropy  : {result.entropy_bits:.1f} bits (pool {result.pool_size})")
    print(f"  Crack    : ~{result.crack_time} (offline GPU estimate)")
    if result.breach_count is not None:
        state = f"seen {result.breach_count:,}x" if result.breach_count else "not found"
        print(f"  Breaches : {state}")
    if result.warnings:
        print("\n  Issues:")
        for warning in result.warnings:
            print(f"    - {warning}")
    if result.suggestions:
        print("\n  Stronger alternatives:")
        for suggestion in result.suggestions:
            print(f"    * {suggestion}")
    print()


def _cmd_analyze(args: argparse.Namespace) -> int:
    password = _read_password(args.password)
    analyzer = PasswordAnalyzer(min_length=args.min_length, check_breaches=args.breach)
    result = analyzer.analyze(password)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_report(result, use_color=not args.no_color and sys.stdout.isatty())
    # Non-zero exit code for weak passwords helps scripting / CI checks.
    return 0 if result.strength >= Strength.STRONG else 1


def _cmd_generate(args: argparse.Namespace) -> int:
    if args.passphrase:
        for _ in range(args.count):
            print(generate_passphrase(args.words))
    else:
        for _ in range(args.count):
            print(
                generate_password(
                    args.length,
                    use_symbols=not args.no_symbols,
                )
            )
    return 0


def _cmd_register(args: argparse.Namespace) -> int:
    password = _read_password(args.password)
    analyzer = PasswordAnalyzer(min_length=args.min_length, check_breaches=args.breach)
    result = analyzer.analyze(password)
    if result.strength < Strength.FAIR:
        print(f"Rejected: password is too weak ({result.strength.label}).")
        _print_report(result, use_color=sys.stdout.isatty())
        return 1
    with PasswordHistory(args.db) as history:
        if history.register_if_new(args.user, password):
            count = history.history_count(args.user)
            print(f"Accepted and stored for '{args.user}' (history size: {count}).")
            return 0
        print("Rejected: this password was used before. Choose a new one.")
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="passguard",
        description="Evaluate and improve password strength.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a password's strength.")
    analyze.add_argument("-p", "--password", help="Password (omit to be prompted).")
    analyze.add_argument("--min-length", type=int, default=12)
    analyze.add_argument("--breach", action="store_true", help="Check HIBP breaches.")
    analyze.add_argument("--json", action="store_true", help="Output JSON.")
    analyze.add_argument("--no-color", action="store_true")
    analyze.set_defaults(func=_cmd_analyze)

    generate = sub.add_parser("generate", help="Generate strong passwords.")
    generate.add_argument("-l", "--length", type=int, default=16)
    generate.add_argument("-c", "--count", type=int, default=1)
    generate.add_argument("--no-symbols", action="store_true")
    generate.add_argument("--passphrase", action="store_true", help="Word-based.")
    generate.add_argument("--words", type=int, default=4)
    generate.set_defaults(func=_cmd_generate)

    register = sub.add_parser(
        "register", help="Store a password for a user, rejecting reuse."
    )
    register.add_argument("-u", "--user", required=True)
    register.add_argument("-p", "--password", help="Password (omit to be prompted).")
    register.add_argument("--db", default="password_history.db")
    register.add_argument("--min-length", type=int, default=12)
    register.add_argument("--breach", action="store_true")
    register.set_defaults(func=_cmd_register)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
