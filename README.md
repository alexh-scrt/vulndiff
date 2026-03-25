# vulndiff

**Diff-aware security scanner for teams using AI coding assistants.**

vulndiff analyzes staged or committed code changes against a curated set of
vulnerability patterns covering OWASP Top 10, injection flaws, authentication
issues, hardcoded secrets, path traversal, and unsafe deserialization. By
operating directly on git diffs rather than entire codebases, it gives fast,
focused security feedback precisely where new code was introduced.

> **Catch AI-introduced vulnerabilities before they reach production.**

---

## Features

- **Diff-aware scanning** — Only analyzes lines *added* in the diff, eliminating
  noise from pre-existing code and giving precise, line-level findings.
- **Comprehensive rule set** — Covers OWASP Top 10 categories including
  SQL/command/LDAP injection, hardcoded secrets, insecure auth patterns,
  path traversal, and unsafe deserialization.
- **Multiple output formats** — Rich colorized terminal report, structured JSON
  for CI pipelines, and SARIF for GitHub Advanced Security / VS Code.
- **Flexible input modes** — Staged changes (pre-commit), HEAD vs branch, or
  arbitrary git ref ranges for CI use.
- **Zero heavy dependencies** — Only requires Python stdlib plus `rich` for
  terminal output.

---

## Installation

### Using pip

```bash
pip install vulndiff
```

### Using pipx (recommended for CLI tools)

```bash
pipx install vulndiff
```

### From source

```bash
git clone https://github.com/example/vulndiff.git
cd vulndiff
pip install -e .
```

---

## Quick Start

### Scan staged changes (pre-commit style)

```bash
# Stage your changes first
git add .

# Run vulndiff on staged diff
vulndiff --staged
```

### Scan the last commit

```bash
vulndiff --head
```

### Scan a range of commits

```bash
vulndiff --from-ref main --to-ref feature/my-branch
```

### Use a specific output format

```bash
# JSON output (for CI pipelines)
vulndiff --staged --format json

# SARIF output (for GitHub Advanced Security)
vulndiff --staged --format sarif > results.sarif

# Rich terminal output (default)
vulndiff --staged --format rich
```

### Filter by severity

```bash
# Only show findings of medium severity or higher
vulndiff --staged --severity medium

# Only show critical and high findings, fail CI on any match
vulndiff --staged --severity high --fail-on-findings
```

---

## CLI Reference

```
usage: vulndiff [-h] [--staged | --head | --from-ref REF --to-ref REF]
                [--format {rich,json,sarif}]
                [--severity {info,low,medium,high,critical}]
                [--fail-on-findings]
                [--no-color]
                [--version]

Diff-aware security scanner for AI-assisted codebases.

input mode (choose one):
  --staged              Scan staged changes (git diff --cached)
  --head                Scan changes in the last commit (HEAD~1..HEAD)
  --from-ref REF        Start git ref for range scan
  --to-ref REF          End git ref for range scan (default: HEAD)

output options:
  --format {rich,json,sarif}
                        Output format (default: rich)
  --no-color            Disable color in terminal output

filtering:
  --severity {info,low,medium,high,critical}
                        Minimum severity level to report (default: low)

CI / exit code:
  --fail-on-findings    Exit with code 1 if any findings are reported
                        (after severity filtering). Default behavior.
  --no-fail             Always exit with code 0 (useful for advisory mode)

other:
  -h, --help            Show this help message and exit
  --version             Show program version and exit
```

---

## Pre-commit Hook Setup

vulndiff ships with a pre-commit hook definition. To use it:

1. Install the [pre-commit](https://pre-commit.com/) framework:

   ```bash
   pip install pre-commit
   ```

2. Add vulndiff to your `.pre-commit-config.yaml`:

   ```yaml
   repos:
     - repo: https://github.com/example/vulndiff
       rev: v0.1.0
       hooks:
         - id: vulndiff
   ```

3. Install the hooks:

   ```bash
   pre-commit install
   ```

Now vulndiff will automatically scan your staged changes before every commit.

### Custom arguments

```yaml
repos:
  - repo: https://github.com/example/vulndiff
    rev: v0.1.0
    hooks:
      - id: vulndiff
        args: ["--severity", "medium", "--format", "json"]
```

---

## CI Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vulndiff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # needed for ref range comparisons

      - name: Install vulndiff
        run: pip install vulndiff

      - name: Scan diff (PR)
        if: github.event_name == 'pull_request'
        run: |
          vulndiff \
            --from-ref ${{ github.event.pull_request.base.sha }} \
            --to-ref ${{ github.event.pull_request.head.sha }} \
            --severity medium \
            --fail-on-findings

      - name: Scan last commit (push)
        if: github.event_name == 'push'
        run: vulndiff --head --severity medium --fail-on-findings
```

### GitHub Actions with SARIF upload

```yaml
      - name: Scan and generate SARIF
        run: |
          vulndiff \
            --from-ref ${{ github.event.pull_request.base.sha }} \
            --to-ref ${{ github.event.pull_request.head.sha }} \
            --format sarif > vulndiff-results.sarif
        continue-on-error: true

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vulndiff-results.sarif
```

### GitLab CI

```yaml
vulndiff:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install vulndiff
  script:
    - vulndiff
        --from-ref $CI_MERGE_REQUEST_TARGET_BRANCH_SHA
        --to-ref $CI_COMMIT_SHA
        --severity medium
        --fail-on-findings
  only:
    - merge_requests
```

---

## Rule Categories

| Category | Examples |
|---|---|
| **SQL Injection** | Raw string formatting in SQL queries, `execute()` with f-strings |
| **Command Injection** | `subprocess.call(shell=True)`, `os.system()` with variables |
| **LDAP Injection** | Unsanitized LDAP filter construction |
| **Path Traversal** | `open()` with user-supplied paths, `../` in filenames |
| **Hardcoded Secrets** | API keys, passwords, tokens assigned as literals |
| **Insecure Auth** | `verify=False` in requests, disabled SSL/TLS verification |
| **Unsafe Deserialization** | `pickle.loads()`, `yaml.load()` without `Loader` |
| **XSS** | `innerHTML` assignments, `dangerouslySetInnerHTML` |
| **Insecure Randomness** | `random.random()` for security-sensitive values |
| **Weak Cryptography** | MD5/SHA1 for password hashing, DES/RC4 cipher usage |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings (or `--no-fail` mode) |
| `1` | One or more findings at or above the severity threshold |
| `2` | Tool error (invalid arguments, git not available, etc.) |

---

## Development

```bash
# Clone and set up
git clone https://github.com/example/vulndiff.git
cd vulndiff
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=vulndiff --cov-report=term-missing
```

---

## License

MIT — see [LICENSE](LICENSE) for details.
