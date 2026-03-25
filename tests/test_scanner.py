"""Unit tests for vulndiff.scanner.

Verifies that the scanner correctly:
- Produces findings for known-vulnerable code snippets.
- Deduplicates findings for the same rule/file/line.
- Applies severity filtering.
- Returns accurate scan statistics.
- Works across multiple hunks and files.
"""

from __future__ import annotations

import re
from typing import List

import pytest

from vulndiff.models import Category, DiffHunk, Finding, Rule, ScanResult, Severity
from vulndiff.scanner import scan, scan_text
from vulndiff.rules import get_all_rules, get_rule_by_id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_rule(
    rule_id: str = "VD999",
    name: str = "Test Rule",
    severity: Severity = Severity.HIGH,
    pattern: str = r"unsafe_call\(",
    category: Category = Category.OTHER,
) -> Rule:
    """Construct a minimal Rule for testing."""
    return Rule(
        rule_id=rule_id,
        name=name,
        description="Test description.",
        category=category,
        severity=severity,
        pattern=re.compile(pattern),
        recommendation="Use safe_call() instead.",
    )


def make_hunk(
    file_path: str = "app/views.py",
    start_line: int = 1,
    lines: List[str] = None,
) -> DiffHunk:
    """Construct a DiffHunk from a list of added line strings."""
    if lines is None:
        lines = []
    added_lines = [(start_line + i, line) for i, line in enumerate(lines)]
    return DiffHunk(
        file_path=file_path,
        start_line=start_line,
        added_lines=added_lines,
    )


# ---------------------------------------------------------------------------
# Basic scan functionality
# ---------------------------------------------------------------------------


class TestScanBasic:
    """Basic scan correctness tests."""

    def test_empty_hunks_returns_no_findings(self) -> None:
        """No hunks should produce an empty ScanResult."""
        result = scan(hunks=[], rules=get_all_rules())
        assert result.finding_count == 0
        assert result.has_findings is False

    def test_empty_rules_returns_no_findings(self) -> None:
        """No rules should produce an empty ScanResult."""
        hunk = make_hunk(lines=["pickle.loads(data)"])
        result = scan(hunks=[hunk], rules=[])
        assert result.finding_count == 0

    def test_matching_rule_produces_finding(self) -> None:
        """A hunk containing a vulnerable line should produce a finding."""
        rule = make_rule(pattern=r"unsafe_call\(")
        hunk = make_hunk(lines=["    result = unsafe_call(user_input)"])
        result = scan(hunks=[hunk], rules=[rule])
        assert result.finding_count == 1

    def test_non_matching_rule_produces_no_finding(self) -> None:
        """A hunk without a vulnerable pattern should produce no findings."""
        rule = make_rule(pattern=r"unsafe_call\(")
        hunk = make_hunk(lines=["    result = safe_call(user_input)"])
        result = scan(hunks=[hunk], rules=[rule])
        assert result.finding_count == 0

    def test_finding_has_correct_file_path(self) -> None:
        """The finding's file_path should match the hunk's file_path."""
        rule = make_rule(pattern=r"DANGER")
        hunk = make_hunk(file_path="src/auth.py", lines=["DANGER here"])
        result = scan(hunks=[hunk], rules=[rule])
        assert result.findings[0].file_path == "src/auth.py"

    def test_finding_has_correct_line_number(self) -> None:
        """The finding's line_number should match the hunk's line numbering."""
        rule = make_rule(pattern=r"DANGER")
        hunk = make_hunk(start_line=42, lines=["no match", "DANGER here"])
        result = scan(hunks=[hunk], rules=[rule])
        assert result.findings[0].line_number == 43  # second line

    def test_finding_has_correct_line_content(self) -> None:
        """The finding's line_content should be the raw added line."""
        rule = make_rule(pattern=r"DANGER")
        hunk = make_hunk(lines=["  DANGER line content  "])
        result = scan(hunks=[hunk], rules=[rule])
        assert result.findings[0].line_content == "  DANGER line content  "

    def test_finding_has_correct_match_text(self) -> None:
        """The finding's match_text should be the regex-matched substring."""
        rule = make_rule(pattern=r"unsafe_call\(")
        hunk = make_hunk(lines=["    unsafe_call(user_input)"])
        result = scan(hunks=[hunk], rules=[rule])
        assert result.findings[0].match_text == "unsafe_call("

    def test_finding_severity_inherited_from_rule(self) -> None:
        """The finding's severity should be inherited from the rule."""
        rule = make_rule(severity=Severity.CRITICAL, pattern=r"BAD")
        hunk = make_hunk(lines=["BAD code"])
        result = scan(hunks=[hunk], rules=[rule])
        assert result.findings[0].severity == Severity.CRITICAL

    def test_finding_rule_reference_correct(self) -> None:
        """The finding should reference the correct Rule object."""
        rule = make_rule(rule_id="VD999", pattern=r"BAD")
        hunk = make_hunk(lines=["BAD"])
        result = scan(hunks=[hunk], rules=[rule])
        assert result.findings[0].rule is rule

    def test_returns_scan_result_instance(self) -> None:
        """scan() must return a ScanResult instance."""
        result = scan(hunks=[], rules=[])
        assert isinstance(result, ScanResult)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


class TestScanDeduplication:
    """Tests for finding deduplication logic."""

    def test_same_line_same_rule_produces_one_finding(self) -> None:
        """The same rule matching the same line should produce one finding."""
        rule = make_rule(pattern=r"DANGER")
        # Provide the same added_line twice (simulates a corrupt hunk)
        hunk = DiffHunk(
            file_path="foo.py",
            start_line=1,
            added_lines=[(1, "DANGER"), (1, "DANGER")],
        )
        result = scan(hunks=[hunk], rules=[rule])
        assert result.finding_count == 1

    def test_same_pattern_different_lines_produces_multiple_findings(self) -> None:
        """The same rule matching different lines should produce multiple findings."""
        rule = make_rule(pattern=r"DANGER")
        hunk = make_hunk(lines=["DANGER one", "DANGER two", "DANGER three"])
        result = scan(hunks=[hunk], rules=[rule])
        assert result.finding_count == 3

    def test_two_rules_matching_same_line_produce_two_findings(self) -> None:
        """Two distinct rules matching the same line each produce a finding."""
        rule1 = make_rule(rule_id="VD901", pattern=r"DANGER")
        rule2 = make_rule(rule_id="VD902", pattern=r"DANGER")
        hunk = make_hunk(lines=["DANGER"])
        result = scan(hunks=[hunk], rules=[rule1, rule2])
        assert result.finding_count == 2


# ---------------------------------------------------------------------------
# Severity filtering
# ---------------------------------------------------------------------------


class TestScanSeverityFilter:
    """Tests for severity threshold filtering."""

    def test_filter_excludes_below_threshold(self) -> None:
        """Findings below the severity_filter should be excluded."""
        low_rule = make_rule(rule_id="VD901", severity=Severity.LOW, pattern=r"LOWBAD")
        high_rule = make_rule(rule_id="VD902", severity=Severity.HIGH, pattern=r"HIGHBAD")
        hunk = make_hunk(lines=["LOWBAD stuff", "HIGHBAD stuff"])
        result = scan(
            hunks=[hunk],
            rules=[low_rule, high_rule],
            severity_filter=Severity.HIGH,
        )
        assert result.finding_count == 1
        assert result.findings[0].rule.rule_id == "VD902"

    def test_filter_includes_at_threshold(self) -> None:
        """Findings at exactly the threshold severity should be included."""
        rule = make_rule(severity=Severity.MEDIUM, pattern=r"MEDBAD")
        hunk = make_hunk(lines=["MEDBAD stuff"])
        result = scan(hunks=[hunk], rules=[rule], severity_filter=Severity.MEDIUM)
        assert result.finding_count == 1

    def test_filter_info_includes_all(self) -> None:
        """INFO threshold should include findings of all severity levels."""
        rules = [
            make_rule(rule_id=f"VD9{i:02d}", severity=sev, pattern=f"MATCH{i}")
            for i, sev in enumerate(Severity)
        ]
        lines = [f"MATCH{i} code" for i in range(len(rules))]
        hunk = make_hunk(lines=lines)
        result = scan(hunks=[hunk], rules=rules, severity_filter=Severity.INFO)
        assert result.finding_count == len(rules)

    def test_filter_critical_excludes_all_lower(self) -> None:
        """CRITICAL threshold should exclude HIGH, MEDIUM, LOW, INFO findings."""
        rules = [
            make_rule(rule_id="VD901", severity=Severity.INFO, pattern=r"INFO_MATCH"),
            make_rule(rule_id="VD902", severity=Severity.LOW, pattern=r"LOW_MATCH"),
            make_rule(rule_id="VD903", severity=Severity.MEDIUM, pattern=r"MED_MATCH"),
            make_rule(rule_id="VD904", severity=Severity.HIGH, pattern=r"HIGH_MATCH"),
            make_rule(rule_id="VD905", severity=Severity.CRITICAL, pattern=r"CRIT_MATCH"),
        ]
        lines = [
            "INFO_MATCH", "LOW_MATCH", "MED_MATCH", "HIGH_MATCH", "CRIT_MATCH"
        ]
        hunk = make_hunk(lines=lines)
        result = scan(hunks=[hunk], rules=rules, severity_filter=Severity.CRITICAL)
        assert result.finding_count == 1
        assert result.findings[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Scan statistics
# ---------------------------------------------------------------------------


class TestScanStatistics:
    """Tests for scan result statistics."""

    def test_scanned_lines_count(self) -> None:
        """scanned_lines should equal the total number of added lines."""
        hunk1 = make_hunk(file_path="a.py", lines=["line1", "line2"])
        hunk2 = make_hunk(file_path="b.py", lines=["line3"])
        result = scan(hunks=[hunk1, hunk2], rules=[])
        assert result.scanned_lines == 3

    def test_scanned_hunks_count(self) -> None:
        """scanned_hunks should equal the number of hunks processed."""
        hunks = [make_hunk(file_path=f"file{i}.py", lines=["x"]) for i in range(5)]
        result = scan(hunks=hunks, rules=[])
        assert result.scanned_hunks == 5

    def test_scanned_files_deduplicated(self) -> None:
        """scanned_files should be a deduplicated list."""
        hunk1 = make_hunk(file_path="same.py", start_line=1, lines=["a"])
        hunk2 = make_hunk(file_path="same.py", start_line=10, lines=["b"])
        result = scan(hunks=[hunk1, hunk2], rules=[])
        assert result.scanned_files == ["same.py"]

    def test_scanned_files_sorted(self) -> None:
        """scanned_files should be sorted."""
        hunk_z = make_hunk(file_path="z.py", lines=["x"])
        hunk_a = make_hunk(file_path="a.py", lines=["x"])
        result = scan(hunks=[hunk_z, hunk_a], rules=[])
        assert result.scanned_files == sorted(result.scanned_files)

    def test_rules_applied_count(self) -> None:
        """rules_applied should equal the number of rules passed."""
        rules = [make_rule(rule_id=f"VD9{i:02d}") for i in range(7)]
        result = scan(hunks=[], rules=rules)
        assert result.rules_applied == 7

    def test_input_mode_stored(self) -> None:
        """input_mode should be stored in the ScanResult."""
        result = scan(hunks=[], rules=[], input_mode="staged")
        assert result.input_mode == "staged"

    def test_from_ref_stored(self) -> None:
        """from_ref should be stored in the ScanResult."""
        result = scan(hunks=[], rules=[], from_ref="main")
        assert result.from_ref == "main"

    def test_to_ref_stored(self) -> None:
        """to_ref should be stored in the ScanResult."""
        result = scan(hunks=[], rules=[], to_ref="feature/x")
        assert result.to_ref == "feature/x"

    def test_severity_filter_stored(self) -> None:
        """severity_filter should be stored in the ScanResult."""
        result = scan(hunks=[], rules=[], severity_filter=Severity.HIGH)
        assert result.severity_filter == Severity.HIGH

    def test_empty_hunk_contributes_zero_lines(self) -> None:
        """An empty hunk should contribute 0 to scanned_lines."""
        hunk = DiffHunk(file_path="empty.py", start_line=1, added_lines=[])
        result = scan(hunks=[hunk], rules=[])
        assert result.scanned_lines == 0

    def test_empty_hunk_still_counted_in_hunks(self) -> None:
        """An empty hunk itself is counted in scanned_hunks."""
        hunk = DiffHunk(file_path="empty.py", start_line=1, added_lines=[])
        result = scan(hunks=[hunk], rules=[])
        assert result.scanned_hunks == 1

    def test_scanned_files_includes_file_from_empty_hunk(self) -> None:
        """A file from an empty hunk should still appear in scanned_files."""
        hunk = DiffHunk(file_path="empty.py", start_line=1, added_lines=[])
        result = scan(hunks=[hunk], rules=[])
        assert "empty.py" in result.scanned_files

    def test_severity_summary_reflects_findings(self) -> None:
        """severity_summary() should tally findings correctly."""
        crit_rule = make_rule(rule_id="VD901", severity=Severity.CRITICAL, pattern=r"CRIT")
        high_rule = make_rule(rule_id="VD902", severity=Severity.HIGH, pattern=r"HIGH")
        hunk = make_hunk(lines=["CRIT code", "HIGH code", "CRIT again"])
        result = scan(hunks=[hunk], rules=[crit_rule, high_rule])
        summary = result.severity_summary()
        assert summary["critical"] == 2
        assert summary["high"] == 1
        assert summary["medium"] == 0


# ---------------------------------------------------------------------------
# Findings ordering
# ---------------------------------------------------------------------------


class TestFindingsOrdering:
    """Tests for the deterministic ordering of findings."""

    def test_findings_sorted_by_file_then_line(self) -> None:
        """Findings should be ordered by file path, then line number."""
        rule = make_rule(pattern=r"MATCH")
        hunk_b = make_hunk(file_path="b.py", start_line=5, lines=["MATCH"])
        hunk_a = make_hunk(file_path="a.py", start_line=10, lines=["MATCH"])
        result = scan(hunks=[hunk_b, hunk_a], rules=[rule])
        paths = [f.file_path for f in result.findings]
        assert paths == ["a.py", "b.py"]

    def test_findings_same_file_sorted_by_line(self) -> None:
        """Within the same file, findings should be sorted by line number."""
        rule = make_rule(pattern=r"MATCH")
        hunk = DiffHunk(
            file_path="file.py",
            start_line=1,
            added_lines=[(30, "MATCH"), (5, "MATCH"), (15, "MATCH")],
        )
        result = scan(hunks=[hunk], rules=[rule])
        line_nums = [f.line_number for f in result.findings]
        assert line_nums == sorted(line_nums)

    def test_findings_sorted_by_rule_id_for_same_file_line(self) -> None:
        """When file and line are the same, findings should be sorted by rule_id."""
        rule_b = make_rule(rule_id="VD902", pattern=r"MATCH")
        rule_a = make_rule(rule_id="VD901", pattern=r"MATCH")
        hunk = make_hunk(file_path="x.py", start_line=1, lines=["MATCH"])
        result = scan(hunks=[hunk], rules=[rule_b, rule_a])
        rule_ids = [f.rule_id for f in result.findings]
        assert rule_ids == sorted(rule_ids)


# ---------------------------------------------------------------------------
# Multi-hunk and multi-file scans
# ---------------------------------------------------------------------------


class TestMultiHunkMultiFile:
    """Tests for scanning multiple hunks and files."""

    def test_multiple_hunks_same_file(self) -> None:
        """Multiple hunks in the same file should all be scanned."""
        rule = make_rule(pattern=r"BAD")
        hunk1 = make_hunk(file_path="x.py", start_line=1, lines=["BAD code"])
        hunk2 = make_hunk(file_path="x.py", start_line=20, lines=["BAD again"])
        result = scan(hunks=[hunk1, hunk2], rules=[rule])
        assert result.finding_count == 2

    def test_multiple_files_each_scanned(self) -> None:
        """Hunks from different files should both be scanned."""
        rule = make_rule(pattern=r"BAD")
        hunk1 = make_hunk(file_path="a.py", lines=["BAD in a"])
        hunk2 = make_hunk(file_path="b.py", lines=["BAD in b"])
        result = scan(hunks=[hunk1, hunk2], rules=[rule])
        file_paths = {f.file_path for f in result.findings}
        assert "a.py" in file_paths
        assert "b.py" in file_paths

    def test_empty_hunk_not_counted_in_lines(self) -> None:
        """An empty hunk contributes 0 to scanned_lines."""
        hunk = DiffHunk(file_path="empty.py", start_line=1, added_lines=[])
        result = scan(hunks=[hunk], rules=[])
        assert result.scanned_lines == 0
        assert result.scanned_hunks == 1  # hunk itself is counted

    def test_mixed_empty_and_non_empty_hunks(self) -> None:
        """Mix of empty and non-empty hunks: only non-empty lines contribute."""
        rule = make_rule(pattern=r"BAD")
        empty_hunk = DiffHunk(file_path="empty.py", start_line=1, added_lines=[])
        full_hunk = make_hunk(file_path="full.py", lines=["BAD code", "more code"])
        result = scan(hunks=[empty_hunk, full_hunk], rules=[rule])
        assert result.scanned_lines == 2
        assert result.scanned_hunks == 2
        assert result.finding_count == 1

    def test_no_cross_file_deduplication(self) -> None:
        """The same pattern on the same line number in two files = two findings."""
        rule = make_rule(pattern=r"BAD")
        hunk_a = make_hunk(file_path="a.py", start_line=10, lines=["BAD"])
        hunk_b = make_hunk(file_path="b.py", start_line=10, lines=["BAD"])
        result = scan(hunks=[hunk_a, hunk_b], rules=[rule])
        assert result.finding_count == 2


# ---------------------------------------------------------------------------
# Integration: real rules against vulnerable snippets
# ---------------------------------------------------------------------------


class TestScanWithRealRules:
    """Integration tests using the full rule set against real code snippets."""

    def test_sql_injection_fstring_detected(self) -> None:
        """VD001 should trigger on an f-string SQL query."""
        rule = get_rule_by_id("VD001")
        hunk = make_hunk(
            file_path="db.py",
            lines=["    cursor.execute(f'SELECT * FROM users WHERE id={uid}')"],
        )
        result = scan(hunks=[hunk], rules=[rule])
        assert result.finding_count == 1
        assert result.findings[0].rule_id == "VD001"

    def test_pickle_loads_detected(self) -> None:
        """VD060 should trigger on pickle.loads()."""
        rule = get_rule_by_id("VD060")
        hunk = make_hunk(
            file_path="utils.py",
            lines=["    obj = pickle.loads(data)"],
        )
        result = scan(hunks=[hunk], rules=[rule])
        assert result.finding_count == 1

    def test_subprocess_shell_true_detected(self) -> None:
        """VD011 should trigger on subprocess.run with shell=True."""
        rule = get_rule_by_id("VD011")
        hunk = make_hunk(
            file_path="runner.py",
            lines=["    subprocess.run(cmd, shell=True)"],
        )
        result = scan(hunks=[hunk], rules=[rule])
        assert result.finding_count == 1

    def test_hardcoded_aws_key_detected(self) -> None:
        """VD041 should trigger on an AWS Access Key ID pattern."""
        rule = get_rule_by_id("VD041")
        hunk = make_hunk(
            file_path="config.py",
            lines=["    AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"],
        )
        result = scan(hunks=[hunk], rules=[rule])
        assert result.finding_count == 1

    def test_verify_false_detected(self) -> None:
        """VD050 should trigger on requests.get with verify=False."""
        rule = get_rule_by_id("VD050")
        hunk = make_hunk(
            file_path="client.py",
            lines=["    resp = requests.get(url, verify=False)"],
        )
        result = scan(hunks=[hunk], rules=[rule])
        assert result.finding_count == 1

    def test_full_rule_set_clean_code(self) -> None:
        """A hunk with safe code should not crash the scanner with the full rule set."""
        rules = get_all_rules()
        hunk = make_hunk(
            file_path="safe.py",
            lines=[
                "    x = 1 + 2",
                "    print('hello world')",
                "    result = my_function(arg1, arg2)",
            ],
        )
        result = scan(hunks=[hunk], rules=rules)
        # Verify the scanner runs without errors and returns a ScanResult
        assert isinstance(result, ScanResult)

    def test_multiple_vulnerabilities_in_one_hunk(self) -> None:
        """A hunk with multiple vulnerable lines should produce multiple findings."""
        rules = [
            get_rule_by_id("VD060"),  # pickle
            get_rule_by_id("VD011"),  # subprocess shell=True
        ]
        hunk = make_hunk(
            file_path="bad.py",
            lines=[
                "    obj = pickle.loads(data)",
                "    subprocess.run(cmd, shell=True)",
            ],
        )
        result = scan(hunks=[hunk], rules=rules)
        assert result.finding_count == 2
        rule_ids = {f.rule_id for f in result.findings}
        assert "VD060" in rule_ids
        assert "VD011" in rule_ids

    def test_yaml_load_without_loader_detected(self) -> None:
        """VD061 should trigger on yaml.load() without a safe loader."""
        rule = get_rule_by_id("VD061")
        hunk = make_hunk(
            file_path="config_loader.py",
            lines=["    data = yaml.load(stream)"],
        )
        result = scan(hunks=[hunk], rules=[rule])
        assert result.finding_count == 1

    def test_eval_variable_detected(self) -> None:
        """VD013 should trigger on eval() with a variable argument."""
        rule = get_rule_by_id("VD013")
        hunk = make_hunk(
            file_path="dynamic.py",
            lines=["    result = eval(user_code)"],
        )
        result = scan(hunks=[hunk], rules=[rule])
        assert result.finding_count == 1

    def test_debug_true_detected(self) -> None:
        """VD054 should trigger on DEBUG = True."""
        rule = get_rule_by_id("VD054")
        hunk = make_hunk(
            file_path="settings.py",
            lines=["DEBUG = True"],
        )
        result = scan(hunks=[hunk], rules=[rule])
        assert result.finding_count == 1

    def test_hashlib_md5_detected(self) -> None:
        """VD090 should trigger on hashlib.md5() usage."""
        rule = get_rule_by_id("VD090")
        hunk = make_hunk(
            file_path="crypto_utils.py",
            lines=["    digest = hashlib.md5(data).hexdigest()"],
        )
        result = scan(hunks=[hunk], rules=[rule])
        assert result.finding_count == 1

    def test_private_key_header_detected(self) -> None:
        """VD043 should trigger on a PEM private key header."""
        rule = get_rule_by_id("VD043")
        hunk = make_hunk(
            file_path="certs.py",
            lines=["    key = '-----BEGIN RSA PRIVATE KEY-----'"],
        )
        result = scan(hunks=[hunk], rules=[rule])
        assert result.finding_count == 1

    def test_finding_file_path_stored_correctly(self) -> None:
        """Finding file_path should match the hunk's file_path exactly."""
        rule = get_rule_by_id("VD060")
        hunk = make_hunk(
            file_path="deeply/nested/module.py",
            lines=["    obj = pickle.loads(data)"],
        )
        result = scan(hunks=[hunk], rules=[rule])
        assert result.findings[0].file_path == "deeply/nested/module.py"

    def test_finding_line_number_accurate(self) -> None:
        """Finding line_number should reflect the actual position in the new file."""
        rule = get_rule_by_id("VD060")
        hunk = make_hunk(
            file_path="utils.py",
            start_line=100,
            lines=["safe line", "also safe", "    obj = pickle.loads(data)"],
        )
        result = scan(hunks=[hunk], rules=[rule])
        assert result.findings[0].line_number == 102


# ---------------------------------------------------------------------------
# scan_text convenience function
# ---------------------------------------------------------------------------


class TestScanText:
    """Tests for the scan_text() convenience function."""

    def test_returns_list_of_findings(self) -> None:
        """scan_text() should return a list of Finding objects."""
        rule = make_rule(pattern=r"BAD")
        findings = scan_text("    BAD code", "foo.py", rules=[rule])
        assert isinstance(findings, list)
        assert len(findings) == 1
        assert isinstance(findings[0], Finding)

    def test_empty_text_returns_empty(self) -> None:
        """Empty text should produce no findings."""
        rule = make_rule(pattern=r"BAD")
        findings = scan_text("", "foo.py", rules=[rule])
        assert findings == []

    def test_no_match_returns_empty(self) -> None:
        """Text without a match should return an empty list."""
        rule = make_rule(pattern=r"BAD")
        findings = scan_text("    safe_code()", "foo.py", rules=[rule])
        assert findings == []

    def test_start_line_used_for_line_numbers(self) -> None:
        """start_line should offset the reported line numbers."""
        rule = make_rule(pattern=r"BAD")
        findings = scan_text("    BAD code", "foo.py", rules=[rule], start_line=50)
        assert findings[0].line_number == 50

    def test_multiline_text_correct_line_numbers(self) -> None:
        """Multi-line text should produce correct sequential line numbers."""
        rule = make_rule(pattern=r"BAD")
        text = "ok line\nBAD line\nalso ok"
        findings = scan_text(text, "foo.py", rules=[rule], start_line=10)
        assert len(findings) == 1
        assert findings[0].line_number == 11  # second line -> 10 + 1

    def test_empty_file_path_raises(self) -> None:
        """An empty file_path should raise ValueError."""
        rule = make_rule(pattern=r"BAD")
        with pytest.raises(ValueError, match="file_path"):
            scan_text("BAD", "", rules=[rule])

    def test_start_line_zero_raises(self) -> None:
        """A start_line of 0 should raise ValueError."""
        rule = make_rule(pattern=r"BAD")
        with pytest.raises(ValueError, match="start_line"):
            scan_text("BAD", "foo.py", rules=[rule], start_line=0)

    def test_start_line_negative_raises(self) -> None:
        """A negative start_line should raise ValueError."""
        rule = make_rule(pattern=r"BAD")
        with pytest.raises(ValueError, match="start_line"):
            scan_text("BAD", "foo.py", rules=[rule], start_line=-5)

    def test_severity_filter_applied(self) -> None:
        """scan_text() should apply the severity_filter."""
        low_rule = make_rule(rule_id="VD901", severity=Severity.LOW, pattern=r"LOWBAD")
        findings = scan_text(
            "LOWBAD", "foo.py", rules=[low_rule], severity_filter=Severity.HIGH
        )
        assert findings == []

    def test_multiple_matching_lines(self) -> None:
        """scan_text() should find all matching lines in multi-line text."""
        rule = make_rule(pattern=r"BAD")
        text = "BAD line 1\nok line\nBAD line 3"
        findings = scan_text(text, "foo.py", rules=[rule], start_line=1)
        assert len(findings) == 2
        line_numbers = [f.line_number for f in findings]
        assert 1 in line_numbers
        assert 3 in line_numbers

    def test_whitespace_only_file_path_raises(self) -> None:
        """A whitespace-only file_path should raise ValueError."""
        rule = make_rule(pattern=r"BAD")
        with pytest.raises(ValueError, match="file_path"):
            scan_text("BAD", "   ", rules=[rule])

    def test_no_rules_returns_empty(self) -> None:
        """With no rules, scan_text() should return an empty list."""
        findings = scan_text("pickle.loads(data)", "foo.py", rules=[])
        assert findings == []

    def test_finding_has_correct_match_text(self) -> None:
        """scan_text() findings should have the correct match_text substring."""
        rule = make_rule(pattern=r"unsafe_call\(")
        findings = scan_text("    unsafe_call(x)", "foo.py", rules=[rule])
        assert len(findings) == 1
        assert findings[0].match_text == "unsafe_call("

    def test_finding_line_content_preserved(self) -> None:
        """scan_text() findings should preserve the original line content."""
        rule = make_rule(pattern=r"BAD")
        findings = scan_text("  BAD code here  ", "foo.py", rules=[rule])
        assert findings[0].line_content == "  BAD code here  "

    def test_real_rule_via_scan_text(self) -> None:
        """scan_text() should work with a real rule from the rule set."""
        rule = get_rule_by_id("VD060")
        findings = scan_text(
            "    obj = pickle.loads(data)",
            "utils.py",
            rules=[rule],
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "VD060"
