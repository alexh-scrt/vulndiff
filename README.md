# vulndiff

**Catch AI-introduced vulnerabilities before they reach production.**

vulndiff is a diff-aware security scanner built for teams using AI coding assistants like GitHub Copilot or Cursor. Instead of scanning your entire codebase, it analyzes only the lines you've added — giving you fast, focused security feedback precisely where new code was introduced. It covers OWASP Top 10, injection flaws, hardcoded secrets, insecure auth patterns, and more.

---

## Quick Start

**Install:**

```bash
pip install vulndiff
```

**Scan your staged changes before committing:**

```bash
vulndiff --staged
```

**Scan the most recent commit:**

```bash
vulndiff --head
```

**Scan a branch range (CI):**

```bash
vulndiff --from-ref main --to-ref HEAD
```

If findings are detected, vulndiff exits with code `1` so it can block CI pipelines or pre-commit hooks automatically.

---

## Features

- **Diff-aware scanning** — Only analyzes lines *added* in the diff, eliminating noise from pre-existing code and delivering precise, line-level findings.
- **Comprehensive OWASP rule set** — Covers SQL/command/LDAP injection, hardcoded secrets, insecure authentication patterns, path traversal, and unsafe deserialization.
- **Multiple output formats** — Rich colorized terminal output, structured JSON for CI pipelines, and SARIF for GitHub Advanced Security and VS Code integration.
- **Flexible input modes** — Works with staged changes, the latest commit, or arbitrary git ref ranges — covering pre-commit hooks through full CI pipelines.
- **Zero heavy dependencies** — Only requires Python 3.9+ and `rich`. Fast to install, runs anywhere.

---

## Usage Examples

### Pre-commit hook (recommended)

Add vulndiff to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/example/vulndiff
    rev: v0.1.0
    hooks:
      - id: vulndiff
```

Optionally set a minimum severity and output format:

```yaml
      - id: vulndiff
        args: ["--severity", "medium", "--format", "json"]
```

Install the hook:

```bash
pre-commit install
```

---

### CI pipeline (GitHub Actions)

```yaml
name: Security Scan

on: [pull_request]

jobs:
  vulndiff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install vulndiff
        run: pip install vulndiff

      - name: Scan diff
        run: vulndiff --from-ref ${{ github.event.pull_request.base.sha }} --to-ref HEAD --format sarif --output results.sarif

      - name: Upload SARIF to GitHub Advanced Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

### CLI reference

```bash
# Scan staged changes with default rich output
vulndiff --staged

# Only report HIGH and CRITICAL findings
vulndiff --staged --severity high

# Output structured JSON
vulndiff --head --format json

# Output SARIF for VS Code / GitHub Advanced Security
vulndiff --from-ref main --to-ref HEAD --format sarif --output results.sarif

# List all available rules
vulndiff --list-rules
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0`  | No findings at or above the severity threshold |
| `1`  | One or more findings detected |
| `2`  | Error (not a git repo, invalid arguments, etc.) |

---

### Example terminal output

```
 vulndiff scan — 3 findings in 2 files

  CRITICAL  app/db.py:47
  Rule      SQL-001 · SQL Injection
  Match     cursor.execute(f"SELECT * FROM users WHERE id={uid}")
  Fix       Use parameterized queries or an ORM instead of string interpolation.

  HIGH      app/auth.py:12
  Rule      AUTH-003 · Hardcoded Secret
  Match     SECRET_KEY = "hardcoded-secret-do-not-use"
  Fix       Load secrets from environment variables or a secrets manager.

  MEDIUM    app/files.py:23
  Rule      PATH-001 · Path Traversal
  Match     open(os.path.join(base_dir, user_input))
  Fix       Validate and sanitize user-controlled path components.
```

---

## Project Structure

```
vulndiff/
├── pyproject.toml          # Project metadata, dependencies, CLI entry point
├── .pre-commit-hooks.yaml  # Pre-commit framework hook definition
├── README.md
│
├── vulndiff/
│   ├── __init__.py         # Package init and version constant
│   ├── cli.py              # Argparse CLI entry point
│   ├── git_diff.py         # Git diff extraction (staged, HEAD, ref range)
│   ├── scanner.py          # Rule engine — matches patterns against diff hunks
│   ├── rules.py            # Vulnerability rule definitions (OWASP Top 10, etc.)
│   ├── reporter.py         # Output formatters: rich, JSON, SARIF
│   └── models.py           # Shared dataclasses: Rule, DiffHunk, Finding, ScanResult
│
└── tests/
    ├── __init__.py
    ├── test_models.py      # Data model construction and serialization tests
    ├── test_rules.py       # Rule pattern compilation and payload matching
    ├── test_git_diff.py    # Diff parsing — multi-file, multi-hunk, edge cases
    ├── test_scanner.py     # Scanner engine with known-vulnerable snippets
    ├── test_reporter.py    # JSON and SARIF output correctness
    └── test_cli.py         # Argument parsing, exit codes, format dispatching
```

---

## Configuration

vulndiff is configured via CLI flags. There is no config file required.

| Flag | Default | Description |
|------|---------|-------------|
| `--staged` | — | Scan staged changes (`git diff --cached`) |
| `--head` | — | Scan the most recent commit (`HEAD~1..HEAD`) |
| `--from-ref <ref>` | — | Start ref for a custom range |
| `--to-ref <ref>` | `HEAD` | End ref for a custom range |
| `--severity <level>` | `low` | Minimum severity to report: `low`, `medium`, `high`, `critical` |
| `--format <fmt>` | `rich` | Output format: `rich`, `json`, `sarif` |
| `--output <file>` | stdout | Write output to a file instead of stdout |
| `--list-rules` | — | Print all available rules and exit |
| `--no-exit-code` | — | Always exit `0` (useful for informational scans) |

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest

# With coverage
pytest --cov=vulndiff --cov-report=term-missing
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

*Built with [Jitter](https://github.com/jitter-ai) — an AI agent that ships code daily.*
