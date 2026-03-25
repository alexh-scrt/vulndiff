"""Scanner engine for vulndiff.

This module provides the :func:`scan` function that runs all (or a filtered
subset of) vulnerability rules against a list of :class:`~vulndiff.models.DiffHunk`
objects and returns a :class:`~vulndiff.models.ScanResult`.

The scanner only examines lines that were *added* in the diff — never context
or deleted lines — so findings are always precise and actionable.

Example usage::

    from vulndiff.git_diff import get_staged_hunks
    from vulndiff.rules import get_all_rules
    from vulndiff.scanner import scan
    from vulndiff.models import Severity

    hunks = get_staged_hunks()
    rules = get_all_rules()
    result = scan(hunks, rules, severity_filter=Severity.MEDIUM)
    print(result.finding_count)
"""

from __future__ import annotations

from typing import List, Optional

from vulndiff.models import DiffHunk, Finding, Rule, ScanResult, Severity


def scan(
    hunks: List[DiffHunk],
    rules: List[Rule],
    severity_filter: Severity = Severity.LOW,
    input_mode: str = "unknown",
    from_ref: Optional[str] = None,
    to_ref: Optional[str] = None,
) -> ScanResult:
    """Run all *rules* against every added line in *hunks*.

    For each added line in each hunk, every rule's compiled regex pattern is
    tested.  When a match is found a :class:`~vulndiff.models.Finding` is
    created.  Findings whose severity is below *severity_filter* are excluded
    from the returned :class:`~vulndiff.models.ScanResult`.

    Duplicate findings (same rule, file, and line number) are deduplicated so
    that a single line cannot produce more than one finding per rule.

    Args:
        hunks:           List of :class:`~vulndiff.models.DiffHunk` objects
                         produced by the diff-extraction layer.
        rules:           List of :class:`~vulndiff.models.Rule` objects to
                         evaluate against the diff.
        severity_filter: Minimum :class:`~vulndiff.models.Severity` level
                         (inclusive) to include in the result.  Findings below
                         this threshold are silently dropped.
        input_mode:      Human-readable label for the scan input mode
                         (e.g. ``"staged"``, ``"head"``, ``"ref-range"``).
        from_ref:        Start git ref for ref-range scans (or ``None``).
        to_ref:          End git ref for ref-range scans (or ``None``).

    Returns:
        A :class:`~vulndiff.models.ScanResult` containing all findings that
        meet the *severity_filter* threshold, along with scan statistics.
    """
    findings: List[Finding] = []
    # Track (rule_id, file_path, line_number) to avoid duplicates
    seen: set = set()

    scanned_lines = 0
    scanned_files_set: set = set()

    for hunk in hunks:
        scanned_files_set.add(hunk.file_path)
        for line_number, line_content in hunk.added_lines:
            scanned_lines += 1
            for rule in rules:
                match = rule.matches(line_content)
                if match is None:
                    continue

                # Deduplicate: same rule + file + line
                dedup_key = (rule.rule_id, hunk.file_path, line_number)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                finding = Finding(
                    rule=rule,
                    file_path=hunk.file_path,
                    line_number=line_number,
                    line_content=line_content,
                    match_text=match.group(0),
                )

                # Apply severity filter
                if finding.severity >= severity_filter:
                    findings.append(finding)

    # Sort findings by file path then line number for deterministic output
    findings.sort(key=lambda f: (f.file_path, f.line_number, f.rule_id))

    return ScanResult(
        findings=findings,
        scanned_files=sorted(scanned_files_set),
        scanned_hunks=len(hunks),
        scanned_lines=scanned_lines,
        rules_applied=len(rules),
        input_mode=input_mode,
        from_ref=from_ref,
        to_ref=to_ref,
        severity_filter=severity_filter,
    )


def scan_text(
    text: str,
    file_path: str,
    rules: List[Rule],
    start_line: int = 1,
    severity_filter: Severity = Severity.LOW,
) -> List[Finding]:
    """Convenience function: scan raw text as if it were a single diff hunk.

    This is primarily useful for testing and for scenarios where the caller
    already has a snippet of code to check without going through the full
    git diff pipeline.

    Args:
        text:            The source text to scan.  Each line is treated as an
                         added line.
        file_path:       Repository-relative path to associate with findings.
        rules:           List of :class:`~vulndiff.models.Rule` objects.
        start_line:      1-based line number for the first line of *text*.
        severity_filter: Minimum severity to include.

    Returns:
        A list of :class:`~vulndiff.models.Finding` objects for all matches
        at or above *severity_filter*.

    Raises:
        ValueError: If *file_path* is empty or *start_line* is less than 1.
    """
    if not file_path or not file_path.strip():
        raise ValueError("file_path must not be empty.")
    if start_line < 1:
        raise ValueError(f"start_line must be >= 1, got {start_line}.")

    lines = text.splitlines()
    added_lines = [
        (start_line + i, line) for i, line in enumerate(lines)
    ]
    hunk = DiffHunk(
        file_path=file_path,
        start_line=start_line,
        added_lines=added_lines,
    )
    result = scan(
        hunks=[hunk],
        rules=rules,
        severity_filter=severity_filter,
    )
    return result.findings
