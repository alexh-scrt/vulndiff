"""Unit tests for vulndiff.models.

Covers construction, validation, ordering, and serialization of all
dataclasses: Rule, DiffHunk, Finding, and ScanResult, as well as the
Severity and Category enumerations.
"""

from __future__ import annotations

import re

import pytest

from vulndiff.models import (
    Category,
    DiffHunk,
    Finding,
    Rule,
    ScanResult,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_rule(
    rule_id: str = "VD001",
    name: str = "Test Rule",
    severity: Severity = Severity.HIGH,
    pattern: str = r"unsafe_call\(",
) -> Rule:
    """Construct a minimal valid Rule for use in tests."""
    return Rule(
        rule_id=rule_id,
        name=name,
        description="A test vulnerability rule.",
        category=Category.OTHER,
        severity=severity,
        pattern=re.compile(pattern),
        recommendation="Replace with safe_call().",
    )


def make_finding(
    rule: Rule | None = None,
    file_path: str = "app/views.py",
    line_number: int = 42,
    line_content: str = "    unsafe_call(user_input)",
    match_text: str = "unsafe_call(",
) -> Finding:
    """Construct a minimal valid Finding for use in tests."""
    if rule is None:
        rule = make_rule()
    return Finding(
        rule=rule,
        file_path=file_path,
        line_number=line_number,
        line_content=line_content,
        match_text=match_text,
    )


# ---------------------------------------------------------------------------
# Severity tests
# ---------------------------------------------------------------------------

class TestSeverity:
    """Tests for the Severity enumeration."""

    def test_values_are_strings(self) -> None:
        """Each Severity value should be a plain lowercase string."""
        assert Severity.INFO.value == "info"
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_ordering_less_than(self) -> None:
        """Lower severity levels should compare as less than higher ones."""
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

    def test_ordering_greater_than(self) -> None:
        """Higher severity levels should compare as greater than lower ones."""
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

    def test_ordering_equal(self) -> None:
        """Identical severity levels should compare as equal."""
        assert Severity.HIGH == Severity.HIGH
        assert not (Severity.HIGH < Severity.HIGH)
        assert Severity.HIGH <= Severity.HIGH
        assert Severity.HIGH >= Severity.HIGH

    def test_severity_is_str(self) -> None:
        """Severity inherits from str, so values can be used as plain strings."""
        assert isinstance(Severity.HIGH, str)
        assert Severity.HIGH == "high"

    def test_sorted_order(self) -> None:
        """Sorting a list of Severity values should produce ascending order."""
        shuffled = [Severity.CRITICAL, Severity.INFO, Severity.MEDIUM, Severity.LOW, Severity.HIGH]
        expected = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        assert sorted(shuffled) == expected


# ---------------------------------------------------------------------------
# Category tests
# ---------------------------------------------------------------------------

class TestCategory:
    """Tests for the Category enumeration."""

    def test_values_are_strings(self) -> None:
        """Category values should be hyphenated lowercase strings."""
        assert Category.SQL_INJECTION.value == "sql-injection"
        assert Category.COMMAND_INJECTION.value == "command-injection"
        assert Category.HARDCODED_SECRET.value == "hardcoded-secret"

    def test_all_categories_unique(self) -> None:
        """All category values should be unique."""
        values = [c.value for c in Category]
        assert len(values) == len(set(values))


# ---------------------------------------------------------------------------
# Rule tests
# ---------------------------------------------------------------------------

class TestRule:
    """Tests for the Rule dataclass."""

    def test_valid_construction(self) -> None:
        """A well-formed Rule should be created without raising."""
        rule = make_rule()
        assert rule.rule_id == "VD001"
        assert rule.name == "Test Rule"
        assert rule.severity == Severity.HIGH
        assert rule.category == Category.OTHER

    def test_with_optional_fields(self) -> None:
        """A Rule with optional fields populated should store them correctly."""
        rule = Rule(
            rule_id="VD002",
            name="SQL Injection",
            description="SQL injection via f-string.",
            category=Category.SQL_INJECTION,
            severity=Severity.CRITICAL,
            pattern=re.compile(r"execute\(f['\""].*\{"),
            recommendation="Use parameterised queries.",
            cwe_id="CWE-89",
            owasp_id="A03:2021",
            references=["https://owasp.org/Top10/A03_2021-Injection/"],
            tags=["sql", "injection"],
        )
        assert rule.cwe_id == "CWE-89"
        assert rule.owasp_id == "A03:2021"
        assert len(rule.references) == 1
        assert "sql" in rule.tags

    def test_pattern_must_be_compiled(self) -> None:
        """Passing a raw string as pattern should raise TypeError."""
        with pytest.raises(TypeError, match="compiled re.Pattern"):
            Rule(
                rule_id="VD003",
                name="Bad Rule",
                description=".",
                category=Category.OTHER,
                severity=Severity.LOW,
                pattern="not_compiled",  # type: ignore[arg-type]
                recommendation=".",
            )

    def test_empty_rule_id_raises(self) -> None:
        """An empty rule_id should raise ValueError."""
        with pytest.raises(ValueError, match="rule_id"):
            Rule(
                rule_id="   ",
                name="Bad Rule",
                description=".",
                category=Category.OTHER,
                severity=Severity.LOW,
                pattern=re.compile(r"x"),
                recommendation=".",
            )

    def test_empty_name_raises(self) -> None:
        """An empty name should raise ValueError."""
        with pytest.raises(ValueError, match="name"):
            Rule(
                rule_id="VD004",
                name="",
                description=".",
                category=Category.OTHER,
                severity=Severity.LOW,
                pattern=re.compile(r"x"),
                recommendation=".",
            )

    def test_matches_returns_match_object(self) -> None:
        """Rule.matches() should return a Match when the pattern is found."""
        rule = make_rule(pattern=r"unsafe_call\(")
        result = rule.matches("    unsafe_call(user_input)")
        assert result is not None
        assert result.group(0) == "unsafe_call("

    def test_matches_returns_none_on_no_match(self) -> None:
        """Rule.matches() should return None when the pattern is not found."""
        rule = make_rule(pattern=r"unsafe_call\(")
        result = rule.matches("    safe_function(user_input)")
        assert result is None

    def test_default_fields_are_empty_lists(self) -> None:
        """Default references and tags should be independent empty lists."""
        rule1 = make_rule(rule_id="VD010")
        rule2 = make_rule(rule_id="VD011")
        rule1.references.append("https://example.com")
        # rule2's list should be unaffected (no shared mutable default)
        assert rule2.references == []


# ---------------------------------------------------------------------------
# DiffHunk tests
# ---------------------------------------------------------------------------

class TestDiffHunk:
    """Tests for the DiffHunk dataclass."""

    def test_valid_construction(self) -> None:
        """A well-formed DiffHunk should be created without raising."""
        hunk = DiffHunk(
            file_path="src/app.py",
            start_line=10,
            added_lines=[(10, "x = 1"), (11, "y = 2")],
            hunk_header="@@ -8,3 +10,4 @@",
        )
        assert hunk.file_path == "src/app.py"
        assert hunk.start_line == 10
        assert hunk.line_count == 2

    def test_empty_file_path_raises(self) -> None:
        """An empty file_path should raise ValueError."""
        with pytest.raises(ValueError, match="file_path"):
            DiffHunk(file_path="  ", start_line=1)

    def test_start_line_zero_raises(self) -> None:
        """A start_line of 0 should raise ValueError."""
        with pytest.raises(ValueError, match="start_line"):
            DiffHunk(file_path="foo.py", start_line=0)

    def test_start_line_negative_raises(self) -> None:
        """A negative start_line should raise ValueError."""
        with pytest.raises(ValueError, match="start_line"):
            DiffHunk(file_path="foo.py", start_line=-5)

    def test_line_count_property(self) -> None:
        """line_count should equal the number of added_lines tuples."""
        hunk = DiffHunk(
            file_path="foo.py",
            start_line=1,
            added_lines=[(1, "a"), (2, "b"), (3, "c")],
        )
        assert hunk.line_count == 3

    def test_is_empty_true(self) -> None:
        """is_empty() should return True when added_lines is empty."""
        hunk = DiffHunk(file_path="foo.py", start_line=1)
        assert hunk.is_empty() is True

    def test_is_empty_false(self) -> None:
        """is_empty() should return False when there are added lines."""
        hunk = DiffHunk(
            file_path="foo.py",
            start_line=1,
            added_lines=[(1, "x = 1")],
        )
        assert hunk.is_empty() is False

    def test_default_hunk_header_is_empty_string(self) -> None:
        """The default hunk_header should be an empty string."""
        hunk = DiffHunk(file_path="foo.py", start_line=1)
        assert hunk.hunk_header == ""


# ---------------------------------------------------------------------------
# Finding tests
# ---------------------------------------------------------------------------

class TestFinding:
    """Tests for the Finding dataclass."""

    def test_valid_construction(self) -> None:
        """A well-formed Finding should be created without raising."""
        finding = make_finding()
        assert finding.file_path == "app/views.py"
        assert finding.line_number == 42
        assert finding.match_text == "unsafe_call("

    def test_severity_inherited_from_rule(self) -> None:
        """Finding.severity should be copied from the associated Rule."""
        rule = make_rule(severity=Severity.CRITICAL)
        finding = make_finding(rule=rule)
        assert finding.severity == Severity.CRITICAL

    def test_rule_id_property(self) -> None:
        """Finding.rule_id should delegate to the associated rule's rule_id."""
        rule = make_rule(rule_id="VD099")
        finding = make_finding(rule=rule)
        assert finding.rule_id == "VD099"

    def test_category_property(self) -> None:
        """Finding.category should delegate to the associated rule's category."""
        rule = Rule(
            rule_id="VD050",
            name="Cmd Injection",
            description=".",
            category=Category.COMMAND_INJECTION,
            severity=Severity.HIGH,
            pattern=re.compile(r"os\.system"),
            recommendation=".",
        )
        finding = make_finding(rule=rule)
        assert finding.category == Category.COMMAND_INJECTION

    def test_empty_file_path_raises(self) -> None:
        """An empty file_path should raise ValueError."""
        with pytest.raises(ValueError, match="file_path"):
            Finding(
                rule=make_rule(),
                file_path="",
                line_number=1,
                line_content="x",
                match_text="x",
            )

    def test_line_number_zero_raises(self) -> None:
        """A line_number of 0 should raise ValueError."""
        with pytest.raises(ValueError, match="line_number"):
            Finding(
                rule=make_rule(),
                file_path="foo.py",
                line_number=0,
                line_content="x",
                match_text="x",
            )

    def test_to_dict_keys(self) -> None:
        """to_dict() should return a dict with the expected keys."""
        finding = make_finding()
        d = finding.to_dict()
        expected_keys = {
            "rule_id", "rule_name", "category", "severity",
            "file", "line", "line_content", "match_text",
            "description", "recommendation", "cwe_id", "owasp_id", "references",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_values(self) -> None:
        """to_dict() values should reflect the finding and its rule."""
        rule = make_rule(rule_id="VD001", severity=Severity.HIGH)
        finding = make_finding(rule=rule, file_path="main.py", line_number=7)
        d = finding.to_dict()
        assert d["rule_id"] == "VD001"
        assert d["severity"] == "high"
        assert d["file"] == "main.py"
        assert d["line"] == 7

    def test_snippet_defaults_to_none(self) -> None:
        """snippet should default to None when not provided."""
        finding = make_finding()
        assert finding.snippet is None

    def test_snippet_can_be_set(self) -> None:
        """snippet should store the provided value."""
        finding = make_finding()
        finding.snippet = "line 41\n> line 42\nline 43"
        assert finding.snippet is not None
        assert "line 42" in finding.snippet


# ---------------------------------------------------------------------------
# ScanResult tests
# ---------------------------------------------------------------------------

class TestScanResult:
    """Tests for the ScanResult dataclass."""

    def test_default_construction(self) -> None:
        """A ScanResult with no arguments should have sensible defaults."""
        result = ScanResult()
        assert result.finding_count == 0
        assert result.has_findings is False
        assert result.scanned_hunks == 0
        assert result.scanned_lines == 0
        assert result.severity_filter == Severity.LOW

    def test_has_findings_true(self) -> None:
        """has_findings should return True when findings are present."""
        result = ScanResult(findings=[make_finding()])
        assert result.has_findings is True

    def test_finding_count(self) -> None:
        """finding_count should equal the length of the findings list."""
        result = ScanResult(findings=[make_finding(), make_finding()])
        assert result.finding_count == 2

    def test_findings_by_severity(self) -> None:
        """findings_by_severity() should return only matching-severity findings."""
        high_rule = make_rule(rule_id="VD001", severity=Severity.HIGH)
        low_rule = make_rule(rule_id="VD002", severity=Severity.LOW)
        high_finding = make_finding(rule=high_rule)
        low_finding = make_finding(rule=low_rule)
        result = ScanResult(findings=[high_finding, low_finding])

        assert result.findings_by_severity(Severity.HIGH) == [high_finding]
        assert result.findings_by_severity(Severity.LOW) == [low_finding]
        assert result.findings_by_severity(Severity.CRITICAL) == []

    def test_findings_at_or_above(self) -> None:
        """findings_at_or_above() should include all findings >= the given severity."""
        info_rule = make_rule(rule_id="VD001", severity=Severity.INFO)
        medium_rule = make_rule(rule_id="VD002", severity=Severity.MEDIUM)
        critical_rule = make_rule(rule_id="VD003", severity=Severity.CRITICAL)
        result = ScanResult(
            findings=[
                make_finding(rule=info_rule),
                make_finding(rule=medium_rule),
                make_finding(rule=critical_rule),
            ]
        )
        at_or_above_medium = result.findings_at_or_above(Severity.MEDIUM)
        assert len(at_or_above_medium) == 2
        severities = {f.severity for f in at_or_above_medium}
        assert Severity.INFO not in severities

    def test_findings_by_file(self) -> None:
        """findings_by_file() should return only findings for that file."""
        f1 = make_finding(file_path="foo.py")
        f2 = make_finding(file_path="bar.py")
        f3 = make_finding(file_path="foo.py")
        result = ScanResult(findings=[f1, f2, f3])
        assert result.findings_by_file("foo.py") == [f1, f3]
        assert result.findings_by_file("bar.py") == [f2]
        assert result.findings_by_file("baz.py") == []

    def test_severity_summary_all_zero(self) -> None:
        """severity_summary() should return zero counts when there are no findings."""
        result = ScanResult()
        summary = result.severity_summary()
        assert all(v == 0 for v in summary.values())
        assert set(summary.keys()) == {"info", "low", "medium", "high", "critical"}

    def test_severity_summary_counts(self) -> None:
        """severity_summary() should correctly tally findings per severity."""
        high_rule = make_rule(rule_id="VD001", severity=Severity.HIGH)
        low_rule = make_rule(rule_id="VD002", severity=Severity.LOW)
        result = ScanResult(
            findings=[
                make_finding(rule=high_rule),
                make_finding(rule=high_rule),
                make_finding(rule=low_rule),
            ]
        )
        summary = result.severity_summary()
        assert summary["high"] == 2
        assert summary["low"] == 1
        assert summary["critical"] == 0

    def test_to_dict_structure(self) -> None:
        """to_dict() should contain summary, scan_info, and findings keys."""
        result = ScanResult(
            findings=[make_finding()],
            scanned_files=["foo.py"],
            scanned_hunks=1,
            scanned_lines=10,
            rules_applied=5,
            input_mode="staged",
            severity_filter=Severity.MEDIUM,
        )
        d = result.to_dict()
        assert "summary" in d
        assert "scan_info" in d
        assert "findings" in d

    def test_to_dict_summary_values(self) -> None:
        """to_dict() summary block should reflect actual scan statistics."""
        result = ScanResult(
            findings=[make_finding()],
            scanned_files=["a.py", "b.py"],
            scanned_hunks=3,
            scanned_lines=20,
            rules_applied=15,
        )
        summary = result.to_dict()["summary"]
        assert summary["total_findings"] == 1
        assert summary["scanned_files"] == 2
        assert summary["scanned_hunks"] == 3
        assert summary["scanned_lines"] == 20
        assert summary["rules_applied"] == 15

    def test_to_dict_scan_info(self) -> None:
        """to_dict() scan_info block should reflect input mode and refs."""
        result = ScanResult(
            input_mode="ref-range",
            from_ref="main",
            to_ref="feature/x",
            severity_filter=Severity.HIGH,
        )
        info = result.to_dict()["scan_info"]
        assert info["input_mode"] == "ref-range"
        assert info["from_ref"] == "main"
        assert info["to_ref"] == "feature/x"
        assert info["severity_filter"] == "high"

    def test_to_dict_findings_are_serialized(self) -> None:
        """to_dict() findings list should contain dicts, not Finding objects."""
        result = ScanResult(findings=[make_finding()])
        findings_list = result.to_dict()["findings"]
        assert len(findings_list) == 1
        assert isinstance(findings_list[0], dict)
        assert "rule_id" in findings_list[0]

    def test_default_findings_lists_are_independent(self) -> None:
        """Default mutable fields should not be shared between instances."""
        r1 = ScanResult()
        r2 = ScanResult()
        r1.findings.append(make_finding())
        assert r2.finding_count == 0
