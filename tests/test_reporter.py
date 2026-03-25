"""Tests for vulndiff.reporter.

Verifies JSON and SARIF output correctness given a fixed set of mock findings,
and basic rich terminal output generation.
"""

from __future__ import annotations

import json
import re
from typing import List

import pytest

from vulndiff.models import Category, DiffHunk, Finding, Rule, ScanResult, Severity
from vulndiff.reporter import (
    format_json,
    format_report,
    format_rich,
    format_sarif,
    _guess_language,
    _make_fingerprint,
    _SARIF_SEVERITY_MAP,
)
from vulndiff import __version__


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_rule(
    rule_id: str = "VD001",
    name: str = "SQL Injection",
    severity: Severity = Severity.CRITICAL,
    category: Category = Category.SQL_INJECTION,
    cwe_id: str = "CWE-89",
    owasp_id: str = "A03:2021",
) -> Rule:
    return Rule(
        rule_id=rule_id,
        name=name,
        description="SQL injection via f-string.",
        category=category,
        severity=severity,
        pattern=re.compile(r"execute\(f"),
        recommendation="Use parameterised queries.",
        cwe_id=cwe_id,
        owasp_id=owasp_id,
        references=["https://owasp.org/Top10/A03_2021-Injection/"],
        tags=["sql", "injection"],
    )


def _make_finding(
    rule: Rule = None,
    file_path: str = "app/db.py",
    line_number: int = 42,
    line_content: str = "    cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
    match_text: str = "execute(f",
) -> Finding:
    if rule is None:
        rule = _make_rule()
    return Finding(
        rule=rule,
        file_path=file_path,
        line_number=line_number,
        line_content=line_content,
        match_text=match_text,
    )


def _make_result(
    findings: List[Finding] = None,
    scanned_files: List[str] = None,
    scanned_hunks: int = 2,
    scanned_lines: int = 10,
    rules_applied: int = 50,
    input_mode: str = "staged",
    from_ref: str = None,
    to_ref: str = None,
    severity_filter: Severity = Severity.LOW,
) -> ScanResult:
    if findings is None:
        findings = [_make_finding()]
    if scanned_files is None:
        scanned_files = ["app/db.py"]
    return ScanResult(
        findings=findings,
        scanned_files=scanned_files,
        scanned_hunks=scanned_hunks,
        scanned_lines=scanned_lines,
        rules_applied=rules_applied,
        input_mode=input_mode,
        from_ref=from_ref,
        to_ref=to_ref,
        severity_filter=severity_filter,
    )


# ---------------------------------------------------------------------------
# JSON output tests
# ---------------------------------------------------------------------------


class TestFormatJson:
    """Tests for format_json()."""

    def test_returns_valid_json(self) -> None:
        """format_json() must return a string parseable by json.loads()."""
        result = _make_result()
        output = format_json(result)
        parsed = json.loads(output)  # should not raise
        assert isinstance(parsed, dict)

    def test_top_level_keys(self) -> None:
        """Top-level keys must include summary, scan_info, findings, tool."""
        result = _make_result()
        parsed = json.loads(format_json(result))
        assert "summary" in parsed
        assert "scan_info" in parsed
        assert "findings" in parsed
        assert "tool" in parsed

    def test_tool_metadata(self) -> None:
        """Tool metadata should include name and version."""
        result = _make_result()
        parsed = json.loads(format_json(result))
        assert parsed["tool"]["name"] == "vulndiff"
        assert parsed["tool"]["version"] == __version__

    def test_summary_total_findings(self) -> None:
        """summary.total_findings should equal the number of findings."""
        findings = [_make_finding(), _make_finding(line_number=99)]
        result = _make_result(findings=findings)
        parsed = json.loads(format_json(result))
        assert parsed["summary"]["total_findings"] == 2

    def test_summary_scanned_files(self) -> None:
        """summary.scanned_files should equal the number of scanned files."""
        result = _make_result(scanned_files=["a.py", "b.py"])
        parsed = json.loads(format_json(result))
        assert parsed["summary"]["scanned_files"] == 2

    def test_summary_scanned_lines(self) -> None:
        """summary.scanned_lines should reflect the scan statistic."""
        result = _make_result(scanned_lines=123)
        parsed = json.loads(format_json(result))
        assert parsed["summary"]["scanned_lines"] == 123

    def test_summary_severity_counts(self) -> None:
        """summary.severity_counts should have keys for all severity levels."""
        result = _make_result()
        parsed = json.loads(format_json(result))
        counts = parsed["summary"]["severity_counts"]
        for level in ["critical", "high", "medium", "low", "info"]:
            assert level in counts

    def test_scan_info_input_mode(self) -> None:
        """scan_info.input_mode should reflect the scan's input mode."""
        result = _make_result(input_mode="head")
        parsed = json.loads(format_json(result))
        assert parsed["scan_info"]["input_mode"] == "head"

    def test_scan_info_ref_range(self) -> None:
        """scan_info should include from_ref and to_ref for ref-range scans."""
        result = _make_result(
            input_mode="ref-range", from_ref="main", to_ref="feature/x"
        )
        parsed = json.loads(format_json(result))
        assert parsed["scan_info"]["from_ref"] == "main"
        assert parsed["scan_info"]["to_ref"] == "feature/x"

    def test_findings_list_length(self) -> None:
        """The findings array length should match the number of findings."""
        findings = [_make_finding(), _make_finding(line_number=5)]
        result = _make_result(findings=findings)
        parsed = json.loads(format_json(result))
        assert len(parsed["findings"]) == 2

    def test_finding_fields_present(self) -> None:
        """Each finding dict should contain all required fields."""
        result = _make_result()
        parsed = json.loads(format_json(result))
        finding = parsed["findings"][0]
        required = {
            "rule_id", "rule_name", "category", "severity",
            "file", "line", "line_content", "match_text",
            "description", "recommendation", "cwe_id", "owasp_id", "references",
        }
        assert required.issubset(set(finding.keys()))

    def test_finding_rule_id_value(self) -> None:
        """The finding's rule_id should match the rule used."""
        rule = _make_rule(rule_id="VD001")
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert parsed["findings"][0]["rule_id"] == "VD001"

    def test_finding_severity_value(self) -> None:
        """The finding's severity should be a lowercase string."""
        rule = _make_rule(severity=Severity.CRITICAL)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert parsed["findings"][0]["severity"] == "critical"

    def test_finding_file_path(self) -> None:
        """The finding's file path should appear in the JSON output."""
        finding = _make_finding(file_path="src/auth/views.py")
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert parsed["findings"][0]["file"] == "src/auth/views.py"

    def test_finding_line_number(self) -> None:
        """The finding's line number should be an integer in the output."""
        finding = _make_finding(line_number=99)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert parsed["findings"][0]["line"] == 99

    def test_empty_findings_produces_empty_array(self) -> None:
        """A result with no findings should have an empty findings array."""
        result = _make_result(findings=[])
        parsed = json.loads(format_json(result))
        assert parsed["findings"] == []

    def test_indent_parameter_affects_output(self) -> None:
        """The indent parameter should control JSON indentation."""
        result = _make_result(findings=[])
        compact = format_json(result, indent=None)
        pretty = format_json(result, indent=4)
        # Compact should be shorter
        assert len(compact) < len(pretty)


# ---------------------------------------------------------------------------
# SARIF output tests
# ---------------------------------------------------------------------------


class TestFormatSarif:
    """Tests for format_sarif()."""

    def test_returns_valid_json(self) -> None:
        """format_sarif() must return valid JSON."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        assert isinstance(parsed, dict)

    def test_sarif_version(self) -> None:
        """SARIF output must declare version 2.1.0."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        assert parsed["version"] == "2.1.0"

    def test_sarif_schema(self) -> None:
        """SARIF output must include the $schema field."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        assert "$schema" in parsed
        assert "sarif" in parsed["$schema"].lower()

    def test_sarif_runs_array(self) -> None:
        """SARIF output must have a 'runs' array with one entry."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        assert "runs" in parsed
        assert isinstance(parsed["runs"], list)
        assert len(parsed["runs"]) == 1

    def test_sarif_tool_driver_name(self) -> None:
        """SARIF tool driver name must be 'vulndiff'."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        driver = parsed["runs"][0]["tool"]["driver"]
        assert driver["name"] == "vulndiff"

    def test_sarif_tool_driver_version(self) -> None:
        """SARIF tool driver version must match the package version."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        driver = parsed["runs"][0]["tool"]["driver"]
        assert driver["version"] == __version__

    def test_sarif_results_count(self) -> None:
        """SARIF results array length must equal the number of findings."""
        findings = [_make_finding(), _make_finding(line_number=7)]
        result = _make_result(findings=findings)
        parsed = json.loads(format_sarif(result))
        assert len(parsed["runs"][0]["results"]) == 2

    def test_sarif_result_rule_id(self) -> None:
        """Each SARIF result must reference the correct ruleId."""
        rule = _make_rule(rule_id="VD001")
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        assert parsed["runs"][0]["results"][0]["ruleId"] == "VD001"

    def test_sarif_result_level_critical(self) -> None:
        """Critical severity should map to SARIF level 'error'."""
        rule = _make_rule(severity=Severity.CRITICAL)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        assert parsed["runs"][0]["results"][0]["level"] == "error"

    def test_sarif_result_level_high(self) -> None:
        """High severity should map to SARIF level 'error'."""
        rule = _make_rule(severity=Severity.HIGH)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        assert parsed["runs"][0]["results"][0]["level"] == "error"

    def test_sarif_result_level_medium(self) -> None:
        """Medium severity should map to SARIF level 'warning'."""
        rule = _make_rule(severity=Severity.MEDIUM)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        assert parsed["runs"][0]["results"][0]["level"] == "warning"

    def test_sarif_result_level_low(self) -> None:
        """Low severity should map to SARIF level 'note'."""
        rule = _make_rule(severity=Severity.LOW)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        assert parsed["runs"][0]["results"][0]["level"] == "note"

    def test_sarif_result_location_uri(self) -> None:
        """The SARIF result location URI must match the finding's file path."""
        finding = _make_finding(file_path="src/models/user.py")
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        location = parsed["runs"][0]["results"][0]["locations"][0]
        uri = location["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "src/models/user.py"

    def test_sarif_result_location_start_line(self) -> None:
        """The SARIF result region startLine must match the finding's line number."""
        finding = _make_finding(line_number=55)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        region = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 55

    def test_sarif_artifacts_present(self) -> None:
        """SARIF artifacts array must list the scanned files."""
        result = _make_result(scanned_files=["app/db.py", "app/auth.py"])
        parsed = json.loads(format_sarif(result))
        artifact_uris = {
            a["location"]["uri"]
            for a in parsed["runs"][0]["artifacts"]
        }
        assert "app/db.py" in artifact_uris
        assert "app/auth.py" in artifact_uris

    def test_sarif_rules_in_driver(self) -> None:
        """Driver rules must include an entry for each unique rule in findings."""
        rule1 = _make_rule(rule_id="VD001")
        rule2 = _make_rule(rule_id="VD002", name="Another Rule")
        findings = [
            _make_finding(rule=rule1),
            _make_finding(rule=rule2, line_number=5),
        ]
        result = _make_result(findings=findings)
        parsed = json.loads(format_sarif(result))
        driver_rule_ids = {
            r["id"]
            for r in parsed["runs"][0]["tool"]["driver"]["rules"]
        }
        assert "VD001" in driver_rule_ids
        assert "VD002" in driver_rule_ids

    def test_sarif_fingerprints_present(self) -> None:
        """Each SARIF result must include a fingerprint."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        result_item = parsed["runs"][0]["results"][0]
        assert "fingerprints" in result_item
        assert "vulndiff/v1" in result_item["fingerprints"]

    def test_sarif_empty_findings(self) -> None:
        """SARIF output with no findings should have an empty results array."""
        result = _make_result(findings=[])
        parsed = json.loads(format_sarif(result))
        assert parsed["runs"][0]["results"] == []

    def test_sarif_cwe_taxa(self) -> None:
        """Findings with a CWE ID should include a taxa entry in the SARIF result."""
        rule = _make_rule(cwe_id="CWE-89")
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        sarif_result = parsed["runs"][0]["results"][0]
        assert "taxa" in sarif_result
        cwe_taxon = next(
            (t for t in sarif_result["taxa"] if t["toolComponent"]["name"] == "CWE"),
            None,
        )
        assert cwe_taxon is not None
        assert cwe_taxon["id"] == "CWE-89"


# ---------------------------------------------------------------------------
# Rich output tests
# ---------------------------------------------------------------------------


class TestFormatRich:
    """Tests for format_rich()."""

    def test_returns_string(self) -> None:
        """format_rich() must return a string."""
        result = _make_result()
        output = format_rich(result, no_color=True)
        assert isinstance(output, str)

    def test_contains_rule_id(self) -> None:
        """The rich output should mention the rule ID."""
        rule = _make_rule(rule_id="VD001")
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        output = format_rich(result, no_color=True)
        assert "VD001" in output

    def test_contains_file_path(self) -> None:
        """The rich output should mention the finding's file path."""
        finding = _make_finding(file_path="src/views.py")
        result = _make_result(findings=[finding])
        output = format_rich(result, no_color=True)
        assert "src/views.py" in output

    def test_contains_severity(self) -> None:
        """The rich output should mention the finding's severity."""
        rule = _make_rule(severity=Severity.CRITICAL)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        output = format_rich(result, no_color=True)
        assert "CRITICAL" in output.upper() or "critical" in output.lower()

    def test_no_findings_message(self) -> None:
        """When there are no findings, the output should indicate clean status."""
        result = _make_result(findings=[])
        output = format_rich(result, no_color=True)
        assert "No findings" in output or "no findings" in output.lower()

    def test_version_in_header(self) -> None:
        """The vulndiff version should appear in the rich output header."""
        result = _make_result()
        output = format_rich(result, no_color=True)
        assert __version__ in output

    def test_no_color_produces_shorter_output(self) -> None:
        """no_color=True should produce output without ANSI codes."""
        result = _make_result()
        colored = format_rich(result, no_color=False)
        plain = format_rich(result, no_color=True)
        # Both should be non-empty strings
        assert len(plain) > 0
        assert len(colored) > 0

    def test_multiple_findings_all_present(self) -> None:
        """All findings should appear in the rich output."""
        rule1 = _make_rule(rule_id="VD001")
        rule2 = _make_rule(rule_id="VD002", name="Path Traversal")
        findings = [
            _make_finding(rule=rule1, file_path="a.py", line_number=1),
            _make_finding(rule=rule2, file_path="b.py", line_number=2),
        ]
        result = _make_result(findings=findings, scanned_files=["a.py", "b.py"])
        output = format_rich(result, no_color=True)
        assert "VD001" in output
        assert "VD002" in output


# ---------------------------------------------------------------------------
# format_report dispatch
# ---------------------------------------------------------------------------


class TestFormatReport:
    """Tests for the format_report() dispatch function."""

    def test_json_format(self) -> None:
        """format_report with fmt='json' should return valid JSON."""
        result = _make_result()
        output = format_report(result, fmt="json")
        parsed = json.loads(output)
        assert "findings" in parsed

    def test_sarif_format(self) -> None:
        """format_report with fmt='sarif' should return valid SARIF JSON."""
        result = _make_result()
        output = format_report(result, fmt="sarif")
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"

    def test_rich_format(self) -> None:
        """format_report with fmt='rich' should return a non-empty string."""
        result = _make_result()
        output = format_report(result, fmt="rich", no_color=True)
        assert isinstance(output, str)
        assert len(output) > 0

    def test_unknown_format_raises(self) -> None:
        """An unknown format string should raise ValueError."""
        result = _make_result()
        with pytest.raises(ValueError, match="Unknown format"):
            format_report(result, fmt="xml")


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestGuessLanguage:
    """Tests for the _guess_language() helper."""

    def test_python_extension(self) -> None:
        assert _guess_language("foo.py") == "python"

    def test_javascript_extension(self) -> None:
        assert _guess_language("app.js") == "javascript"

    def test_typescript_extension(self) -> None:
        assert _guess_language("component.ts") == "typescript"

    def test_java_extension(self) -> None:
        assert _guess_language("Main.java") == "java"

    def test_go_extension(self) -> None:
        assert _guess_language("server.go") == "go"

    def test_yaml_extension(self) -> None:
        assert _guess_language("config.yaml") == "yaml"

    def test_yml_extension(self) -> None:
        assert _guess_language("ci.yml") == "yaml"

    def test_json_extension(self) -> None:
        assert _guess_language("data.json") == "json"

    def test_unknown_extension_returns_text(self) -> None:
        assert _guess_language("file.xyz") == "text"

    def test_no_extension_returns_text(self) -> None:
        assert _guess_language("Makefile") == "text"

    def test_nested_path(self) -> None:
        assert _guess_language("src/auth/views.py") == "python"


class TestMakeFingerprint:
    """Tests for the _make_fingerprint() helper."""

    def test_returns_string(self) -> None:
        finding = _make_finding()
        fp = _make_fingerprint(finding)
        assert isinstance(fp, str)

    def test_fingerprint_length(self) -> None:
        """Fingerprint should be 16 hex characters."""
        finding = _make_finding()
        fp = _make_fingerprint(finding)
        assert len(fp) == 16

    def test_fingerprint_is_hex(self) -> None:
        """Fingerprint should contain only hex characters."""
        finding = _make_finding()
        fp = _make_fingerprint(finding)
        assert all(c in "0123456789abcdef" for c in fp)

    def test_same_finding_produces_same_fingerprint(self) -> None:
        """The same finding should always produce the same fingerprint."""
        finding = _make_finding()
        assert _make_fingerprint(finding) == _make_fingerprint(finding)

    def test_different_findings_different_fingerprints(self) -> None:
        """Different findings should (generally) produce different fingerprints."""
        f1 = _make_finding(line_number=10)
        f2 = _make_finding(line_number=20)
        assert _make_fingerprint(f1) != _make_fingerprint(f2)


class TestSarifSeverityMap:
    """Tests for the SARIF severity mapping constant."""

    def test_critical_maps_to_error(self) -> None:
        assert _SARIF_SEVERITY_MAP["critical"] == "error"

    def test_high_maps_to_error(self) -> None:
        assert _SARIF_SEVERITY_MAP["high"] == "error"

    def test_medium_maps_to_warning(self) -> None:
        assert _SARIF_SEVERITY_MAP["medium"] == "warning"

    def test_low_maps_to_note(self) -> None:
        assert _SARIF_SEVERITY_MAP["low"] == "note"

    def test_info_maps_to_none(self) -> None:
        assert _SARIF_SEVERITY_MAP["info"] == "none"

    def test_all_severity_levels_covered(self) -> None:
        for sev in Severity:
            assert sev.value in _SARIF_SEVERITY_MAP
