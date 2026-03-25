"""Test package for vulndiff.

This package contains all unit and integration tests for the vulndiff
security scanner.  Tests are organized by module:

- ``test_models.py``    — Tests for core data models (Rule, DiffHunk, Finding, ScanResult).
- ``test_rules.py``     — Tests for vulnerability rule definitions and pattern matching.
- ``test_git_diff.py``  — Tests for git diff extraction and parsing logic.
- ``test_scanner.py``   — Tests for the scanner engine.
- ``test_reporter.py``  — Tests for JSON, SARIF, and rich terminal output formatters.
- ``test_cli.py``       — Tests for the CLI entry point and argument parsing.

All tests use pytest conventions and can be run with::

    pytest

or with coverage::

    pytest --cov=vulndiff --cov-report=term-missing
"""
