# PassGuard — Password Strength Analyzer

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-pytest-informational)

PassGuard is a command-line and web tool that evaluates how strong a password is,
explains *why*, suggests stronger alternatives, and can remember password history
to prevent reuse — all without ever storing a plaintext password.

It was built as a learning project to explore **password security and basic
cryptography concepts**: entropy, brute-force search space, salting, key
derivation functions (PBKDF2), and the k-anonymity model used by the
"Have I Been Pwned" API.

---

## Features

- **Length & complexity checks** — character classes (lower, upper, digits,
  symbols) and minimum-length policy.
- **Entropy-based scoring** — estimates the brute-force search space in bits
  and converts it into an offline crack-time estimate.
- **Pattern detection** — penalises sequences (`abc`, `123`), repeats (`aaa`),
  keyboard walks (`qwerty`) and embedded years.
- **Uniqueness checks** — flags common/breached passwords using a bundled
  word list, and *optionally* the online Have I Been Pwned range API (only the
  first 5 characters of the SHA-1 hash ever leave your machine).
- **Stronger suggestions** — generates cryptographically secure random
  passwords and memorable passphrases (using Python's `secrets` module).
- **Reuse prevention (optional DB)** — stores salted **PBKDF2-HMAC-SHA256**
  hashes in SQLite so a user cannot re-use an old password.
- **CLI + optional Flask web UI** with a live strength meter.
- **Fully unit-tested** with `pytest` and a GitHub Actions CI workflow.

---

## Project structure

```
passguard/
├── src/passguard/
│   ├── analyzer.py      # Core scoring engine
│   ├── entropy.py       # Entropy & crack-time math
│   ├── common.py        # Common-password & pattern detection
│   ├── breach.py        # Have I Been Pwned (k-anonymity) client
│   ├── generator.py     # Secure password / passphrase generation
│   ├── database.py       # Salted-hash password history (SQLite)
│   ├── cli.py           # Command-line interface
│   ├── web.py           # Optional Flask web UI
│   └── data/common_passwords.txt
├── tests/               # pytest test suite
├── .github/workflows/   # CI
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## Installation

```bash
git clone https://github.com/your-username/passguard.git
cd passguard
python -m pip install -e ".[dev]"     # installs the `passguard` command
```

The core library has **no third-party dependencies** (standard library only).
Flask is only needed for the optional web UI (`pip install -e ".[web]"`).

---

## Usage

### Analyze a password

```bash
# Prompt securely (input hidden)
passguard analyze

# Or pass it directly
passguard analyze --password "correct horse battery staple"

# Also check breaches and print JSON
passguard analyze -p "hunter2" --breach --json
```

Example output:

```
  Strength : Very Strong (92/100)
  Meter    : ██████████████████░░
  Length   : 20
  Entropy  : 131.0 bits (pool 94)
  Crack    : ~4.35e+21 centuries (offline GPU estimate)
```

### Generate a strong password

```bash
passguard generate --length 20          # random
passguard generate --passphrase --words 5  # memorable passphrase
```

### Prevent password reuse (SQLite)

```bash
passguard register --user alice --db history.db
# Re-registering the same password later is rejected.
```

### Run the web UI

```bash
pip install -e ".[web]"
python -m passguard.web        # http://127.0.0.1:5000
```

### Use it as a library

```python
from passguard import PasswordAnalyzer

result = PasswordAnalyzer(min_length=12).analyze("Tr0ub4dour&3")
print(result.strength.label, result.score)
print(result.warnings)
print(result.suggestions)
```

---

## How the scoring works

1. **Search-space entropy** is computed as `length × log2(pool_size)`, where
   `pool_size` is the combined size of every character class present.
2. That entropy is mapped onto a 0–80 base score; up to 20 bonus points are
   awarded for character-class diversity.
3. Predictable patterns (sequences, repeats, keyboard walks, years) and
   too-short passwords subtract points.
4. Any password that is a known common password or found in a breach is forced
   to a score of **0**, because it can be guessed instantly regardless of shape.
5. The final score maps to one of five buckets: Very Weak → Very Strong.

### Security notes

- Passwords are **never** stored in plaintext. The history database keeps a
  random 16-byte salt and a 200,000-round PBKDF2-HMAC-SHA256 digest per entry.
- Breach checks use k-anonymity: only the first 5 hex characters of the
  SHA-1 hash are sent to the API, so the password can't be reconstructed.
- Crack-time estimates assume an offline attacker at 10 billion guesses/sec.

---

## Testing

```bash
pytest -q
```

---

## License

Released under the [MIT License](LICENSE).
