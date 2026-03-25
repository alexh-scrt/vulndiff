"""Core data models for vulndiff.

This module defines all shared dataclasses used across the vulndiff package:

- :class:`Rule` — A vulnerability detection rule with regex pattern and metadata.
- :class:`DiffHunk` — A chunk of added lines from a git diff with file context.
- :class:`Finding` — A specific vulnerability match found during scanning.
- :class:`ScanResult` — The aggregated result of a complete scan run.

All models use Python dataclasses for lightweight, type-safe data containers
without external dependencies.

Example usage::

    from vulndiff.models import DiffHunk, Finding, Rule, ScanResult, Severity

    hunk = DiffHunk(
        file_path="app/views.py",
        start_line=42,
        added_lines=[(42, "cursor.execute(f'SELECT * FROM users WHERE id={uid}'))"),],
    )
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple


class Severity(str, Enum):
    """Enumeration of vulnerability severity levels.

    Levels are ordered from lowest to highest impact:
    INFO < LOW < MEDIUM < HIGH < CRITICAL.

    The class inherits from ``str`` so that severity values serialize
    naturally to JSON as plain strings.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    # Ordering support so severities can be compared with < > <= >=
    _order = ["info", "low", "medium", "high", "critical"]

    def __lt__(self, other: "Severity") -> bool:
        """Return True if this severity is less than *other*."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() < other._rank()

    def __le__(self, other: "Severity") -> bool:
        """Return True if this severity is less than or equal to *other*."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() <= other._rank()

    def __gt__(self, other: "Severity") -> bool:
        """Return True if this severity is greater than *other*."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() > other._rank()

    def __ge__(self, other: "Severity") -> bool:
        """Return True if this severity is greater than or equal to *other*."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() >= other._rank()

    def _rank(self) -> int:
        """Return a numeric rank for comparison purposes."""
        order = ["info", "low", "medium", "high", "critical"]
        return order.index(self.value)


class Category(str, Enum):
    """OWASP-aligned vulnerability category labels.

    These map to the OWASP Top 10 and common CWE categories referenced
    in the rule set and reported in SARIF output.
    """

    SQL_INJECTION = "sql-injection"
    COMMAND_INJECTION = "command-injection"
    LDAP_INJECTION = "ldap-injection"
    CODE_INJECTION = "code-injection"
    PATH_TRAVERSAL = "path-traversal"
    HARDCODED_SECRET = "hardcoded-secret"
    INSECURE_AUTH = "insecure-auth"
    UNSAFE_DESERIALIZATION = "unsafe-deserialization"
    XSS = "xss"
    INSECURE_RANDOMNESS = "insecure-randomness"
    WEAK_CRYPTOGRAPHY = "weak-cryptography"
    INSECURE_CONFIGURATION = "insecure-configuration"
    SENSITIVE_DATA_EXPOSURE = "sensitive-data-exposure"
    OTHER = "other"


@dataclass
class Rule:
    """A vulnerability detection rule.

    Each rule encapsulates a compiled regex pattern together with human-readable
    metadata used for reporting and SARIF output.

    Attributes:
        rule_id:     Unique identifier string, e.g. ``"VD001"``.
        name:        Short human-readable name, e.g. ``"SQL Injection via f-string"``.
        description: Longer explanation of the vulnerability and why it is dangerous.
        category:    :class:`Category` enum value grouping this rule under an OWASP
                     or CWE category.
        severity:    :class:`Severity` enum value indicating the default impact level.
        pattern:     Compiled :class:`re.Pattern` used to match added diff lines.
        recommendation: Actionable remediation advice shown in reports.
        cwe_id:      Optional CWE identifier string, e.g. ``"CWE-89"``.
        owasp_id:    Optional OWASP Top 10 identifier, e.g. ``"A03:2021"``.
        references:  List of URLs to external documentation or advisories.
        tags:        Arbitrary string tags for additional filtering.
    """

    rule_id: str
    name: str
    description: str
    category: Category
    severity: Severity
    pattern: re.Pattern  # type: ignore[type-arg]
    recommendation: str
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate field types after dataclass construction.

        Raises:
            TypeError: If *pattern* is not a compiled :class:`re.Pattern`.
            ValueError: If *rule_id* or *name* is an empty string.
        """
        if not isinstance(self.pattern, re.Pattern):
            raise TypeError(
                f"Rule '{self.rule_id}': pattern must be a compiled re.Pattern, "
                f"got {type(self.pattern).__name__}"
            )
        if not self.rule_id.strip():
            raise ValueError("Rule rule_id must not be empty.")
        if not self.name.strip():
            raise ValueError("Rule name must not be empty.")

    def matches(self, line: str) -> Optional[re.Match]:  # type: ignore[type-arg]
        """Test whether *line* matches this rule's pattern.

        Args:
            line: A single line of source code to test.

        Returns:
            A :class:`re.Match` object if the pattern matches, else ``None``.
        """
        return self.pattern.search(line)


@dataclass
class DiffHunk:
    """A contiguous block of added lines extracted from a git diff.

    A ``DiffHunk`` represents a single ``@@`` section of a unified diff for
    one file, containing only the lines that were *added* (lines starting
    with ``+`` in the raw diff).

    Attributes:
        file_path:   Repository-relative path of the file being changed,
                     e.g. ``"src/app/views.py"``.
        start_line:  1-based line number in the *new* file where this hunk begins.
        added_lines: Ordered list of ``(line_number, line_content)`` tuples for
                     every added line in this hunk.  ``line_content`` does **not**
                     include the leading ``+`` character from the raw diff.
        hunk_header: The raw ``@@ -a,b +c,d @@`` header string, preserved for
                     diagnostic purposes.  May be an empty string if unavailable.
    """

    file_path: str
    start_line: int
    added_lines: List[Tuple[int, str]] = field(default_factory=list)
    hunk_header: str = ""

    def __post_init__(self) -> None:
        """Validate field values after dataclass construction.

        Raises:
            ValueError: If *file_path* is empty or *start_line* is less than 1.
        """
        if not self.file_path.strip():
            raise ValueError("DiffHunk file_path must not be empty.")
        if self.start_line < 1:
            raise ValueError(
                f"DiffHunk start_line must be >= 1, got {self.start_line}."
            )

    @property
    def line_count(self) -> int:
        """Return the number of added lines in this hunk."""
        return len(self.added_lines)

    def is_empty(self) -> bool:
        """Return True if this hunk contains no added lines."""
        return len(self.added_lines) == 0


@dataclass
class Finding:
    """A single vulnerability match produced by the scanner.

    A ``Finding`` ties a :class:`Rule` match to its exact location within
    the diff, carrying everything needed for both human-readable and
    machine-parseable reports.

    Attributes:
        rule:        The :class:`Rule` that triggered this finding.
        file_path:   Repository-relative path of the affected file.
        line_number: 1-based line number in the *new* file where the match occurs.
        line_content: The raw source line that triggered the finding (without
                      leading ``+``).
        match_text:  The specific substring matched by the rule pattern.
        severity:    Effective severity for this finding.  Defaults to the
                     rule's own severity but may be overridden.
        snippet:     Optional multi-line code snippet showing context around
                     the finding for richer terminal output.
    """

    rule: Rule
    file_path: str
    line_number: int
    line_content: str
    match_text: str
    severity: Severity = field(init=False)
    snippet: Optional[str] = None

    def __post_init__(self) -> None:
        """Set derived fields and validate after dataclass construction.

        The ``severity`` attribute is copied from the associated rule so that
        it can be compared or overridden independently.

        Raises:
            ValueError: If *file_path* is empty or *line_number* is less than 1.
        """
        # Inherit severity from rule
        self.severity = self.rule.severity

        if not self.file_path.strip():
            raise ValueError("Finding file_path must not be empty.")
        if self.line_number < 1:
            raise ValueError(
                f"Finding line_number must be >= 1, got {self.line_number}."
            )

    @property
    def rule_id(self) -> str:
        """Shortcut to the associated rule's identifier."""
        return self.rule.rule_id

    @property
    def category(self) -> Category:
        """Shortcut to the associated rule's category."""
        return self.rule.category

    def to_dict(self) -> dict:  # type: ignore[type-arg]
        """Serialize this finding to a plain dictionary suitable for JSON output.

        Returns:
            A dictionary with string keys and JSON-serializable values.
        """
        return {
            "rule_id": self.rule.rule_id,
            "rule_name": self.rule.name,
            "category": self.rule.category.value,
            "severity": self.severity.value,
            "file": self.file_path,
            "line": self.line_number,
            "line_content": self.line_content,
            "match_text": self.match_text,
            "description": self.rule.description,
            "recommendation": self.rule.recommendation,
            "cwe_id": self.rule.cwe_id,
            "owasp_id": self.rule.owasp_id,
            "references": self.rule.references,
        }


@dataclass
class ScanResult:
    """Aggregated result of a complete vulndiff scan run.

    ``ScanResult`` is the top-level container returned by the scanner after
    processing all diff hunks.  It carries the list of :class:`Finding` objects
    together with summary statistics and the parameters used for the scan.

    Attributes:
        findings:        All findings produced by the scan, ordered by file path
                         and line number.
        scanned_files:   Deduplicated list of file paths that appeared in the diff.
        scanned_hunks:   Total number of :class:`DiffHunk` objects processed.
        scanned_lines:   Total number of added lines examined.
        rules_applied:   Total number of rules evaluated (may differ from the
                         number of rules in the rule set if filtering was applied).
        input_mode:      Description of the git input mode used, e.g.
                         ``"staged"``, ``"head"``, or ``"ref-range"``.
        from_ref:        Git ref used as the start of the comparison range,
                         or ``None`` for staged/head modes.
        to_ref:          Git ref used as the end of the comparison range,
                         or ``None`` for staged/head modes.
        severity_filter: Minimum :class:`Severity` level that was reported.
    """

    findings: List[Finding] = field(default_factory=list)
    scanned_files: List[str] = field(default_factory=list)
    scanned_hunks: int = 0
    scanned_lines: int = 0
    rules_applied: int = 0
    input_mode: str = "unknown"
    from_ref: Optional[str] = None
    to_ref: Optional[str] = None
    severity_filter: Severity = Severity.LOW

    # ------------------------------------------------------------------ #
    # Convenience properties                                               #
    # ------------------------------------------------------------------ #

    @property
    def finding_count(self) -> int:
        """Return the total number of findings."""
        return len(self.findings)

    @property
    def has_findings(self) -> bool:
        """Return True if at least one finding was produced."""
        return len(self.findings) > 0

    def findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Return all findings with exactly the given *severity*.

        Args:
            severity: The :class:`Severity` level to filter on.

        Returns:
            A list of :class:`Finding` objects matching *severity*.
        """
        return [f for f in self.findings if f.severity == severity]

    def findings_at_or_above(self, severity: Severity) -> List[Finding]:
        """Return all findings whose severity is >= *severity*.

        Args:
            severity: Minimum :class:`Severity` level (inclusive).

        Returns:
            A list of :class:`Finding` objects at or above *severity*.
        """
        return [f for f in self.findings if f.severity >= severity]

    def findings_by_file(self, file_path: str) -> List[Finding]:
        """Return all findings for the given *file_path*.

        Args:
            file_path: Repository-relative path to filter on.

        Returns:
            A list of :class:`Finding` objects for that file.
        """
        return [f for f in self.findings if f.file_path == file_path]

    def severity_summary(self) -> dict:  # type: ignore[type-arg]
        """Return a dictionary mapping each severity level to its finding count.

        Returns:
            Dict with keys ``"critical"``, ``"high"``, ``"medium"``,
            ``"low"``, ``"info"`` and integer counts as values.
        """
        summary = {s.value: 0 for s in Severity}
        for finding in self.findings:
            summary[finding.severity.value] += 1
        return summary

    def to_dict(self) -> dict:  # type: ignore[type-arg]
        """Serialize this scan result to a plain dictionary for JSON output.

        Returns:
            A dictionary with string keys and JSON-serializable values,
            including a serialized list of all findings.
        """
        return {
            "summary": {
                "total_findings": self.finding_count,
                "scanned_files": len(self.scanned_files),
                "scanned_hunks": self.scanned_hunks,
                "scanned_lines": self.scanned_lines,
                "rules_applied": self.rules_applied,
                "severity_counts": self.severity_summary(),
            },
            "scan_info": {
                "input_mode": self.input_mode,
                "from_ref": self.from_ref,
                "to_ref": self.to_ref,
                "severity_filter": self.severity_filter.value,
            },
            "findings": [f.to_dict() for f in self.findings],
        }
