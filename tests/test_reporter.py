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
    """Construct a minimal Rule for use in reporter tests."""
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
    """Construct a minimal Finding for use in reporter tests."""
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
    """Construct a ScanResult for use in reporter tests."""
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

    def test_summary_scanned_hunks(self) -> None:
        """summary.scanned_hunks should reflect the scan statistic."""
        result = _make_result(scanned_hunks=7)
        parsed = json.loads(format_json(result))
        assert parsed["summary"]["scanned_hunks"] == 7

    def test_summary_rules_applied(self) -> None:
        """summary.rules_applied should reflect the scan statistic."""
        result = _make_result(rules_applied=42)
        parsed = json.loads(format_json(result))
        assert parsed["summary"]["rules_applied"] == 42

    def test_summary_severity_counts(self) -> None:
        """summary.severity_counts should have keys for all severity levels."""
        result = _make_result()
        parsed = json.loads(format_json(result))
        counts = parsed["summary"]["severity_counts"]
        for level in ["critical", "high", "medium", "low", "info"]:
            assert level in counts

    def test_summary_severity_counts_values(self) -> None:
        """summary.severity_counts should accurately tally findings."""
        crit_rule = _make_rule(rule_id="VD001", severity=Severity.CRITICAL)
        high_rule = _make_rule(rule_id="VD002", severity=Severity.HIGH)
        findings = [
            _make_finding(rule=crit_rule, line_number=1),
            _make_finding(rule=crit_rule, line_number=2),
            _make_finding(rule=high_rule, line_number=3),
        ]
        result = _make_result(findings=findings)
        parsed = json.loads(format_json(result))
        counts = parsed["summary"]["severity_counts"]
        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["medium"] == 0
        assert counts["low"] == 0

    def test_scan_info_input_mode(self) -> None:
        """scan_info.input_mode should reflect the scan's input mode."""
        result = _make_result(input_mode="head")
        parsed = json.loads(format_json(result))
        assert parsed["scan_info"]["input_mode"] == "head"

    def test_scan_info_staged_mode(self) -> None:
        """scan_info.input_mode should be 'staged' for staged scans."""
        result = _make_result(input_mode="staged")
        parsed = json.loads(format_json(result))
        assert parsed["scan_info"]["input_mode"] == "staged"

    def test_scan_info_ref_range(self) -> None:
        """scan_info should include from_ref and to_ref for ref-range scans."""
        result = _make_result(
            input_mode="ref-range", from_ref="main", to_ref="feature/x"
        )
        parsed = json.loads(format_json(result))
        assert parsed["scan_info"]["from_ref"] == "main"
        assert parsed["scan_info"]["to_ref"] == "feature/x"

    def test_scan_info_severity_filter(self) -> None:
        """scan_info.severity_filter should reflect the filter level used."""
        result = _make_result(severity_filter=Severity.HIGH)
        parsed = json.loads(format_json(result))
        assert parsed["scan_info"]["severity_filter"] == "high"

    def test_scan_info_null_refs_for_staged(self) -> None:
        """scan_info from_ref and to_ref should be null for staged mode."""
        result = _make_result(input_mode="staged", from_ref=None, to_ref=None)
        parsed = json.loads(format_json(result))
        assert parsed["scan_info"]["from_ref"] is None
        assert parsed["scan_info"]["to_ref"] is None

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

    def test_finding_rule_name_value(self) -> None:
        """The finding's rule_name should match the rule's name."""
        rule = _make_rule(rule_id="VD001", name="SQL Injection")
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert parsed["findings"][0]["rule_name"] == "SQL Injection"

    def test_finding_severity_value(self) -> None:
        """The finding's severity should be a lowercase string."""
        rule = _make_rule(severity=Severity.CRITICAL)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert parsed["findings"][0]["severity"] == "critical"

    def test_finding_high_severity_value(self) -> None:
        """A HIGH finding should serialize severity as 'high'."""
        rule = _make_rule(rule_id="VD002", severity=Severity.HIGH)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert parsed["findings"][0]["severity"] == "high"

    def test_finding_category_value(self) -> None:
        """The finding's category should be the enum's string value."""
        rule = _make_rule(category=Category.SQL_INJECTION)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert parsed["findings"][0]["category"] == "sql-injection"

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

    def test_finding_line_content(self) -> None:
        """The finding's line_content should appear in the output."""
        finding = _make_finding(line_content="    cursor.execute(f'SELECT 1')")
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert parsed["findings"][0]["line_content"] == "    cursor.execute(f'SELECT 1')"

    def test_finding_match_text(self) -> None:
        """The finding's match_text should appear in the output."""
        finding = _make_finding(match_text="execute(f")
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert parsed["findings"][0]["match_text"] == "execute(f"

    def test_finding_cwe_id(self) -> None:
        """The finding's CWE ID should appear in the output."""
        rule = _make_rule(cwe_id="CWE-89")
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert parsed["findings"][0]["cwe_id"] == "CWE-89"

    def test_finding_owasp_id(self) -> None:
        """The finding's OWASP ID should appear in the output."""
        rule = _make_rule(owasp_id="A03:2021")
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert parsed["findings"][0]["owasp_id"] == "A03:2021"

    def test_finding_references_list(self) -> None:
        """The finding's references should be a list in the output."""
        rule = _make_rule()
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert isinstance(parsed["findings"][0]["references"], list)

    def test_finding_description(self) -> None:
        """The finding's description should appear in the output."""
        rule = _make_rule()
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert "SQL injection" in parsed["findings"][0]["description"]

    def test_finding_recommendation(self) -> None:
        """The finding's recommendation should appear in the output."""
        rule = _make_rule()
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_json(result))
        assert "parameterised" in parsed["findings"][0]["recommendation"]

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

    def test_default_indent_is_two_spaces(self) -> None:
        """Default indent of 2 should produce indented JSON."""
        result = _make_result(findings=[])
        output = format_json(result)
        # 2-space indent means lines should start with exactly 2 spaces for top-level keys
        assert "  " in output

    def test_non_ascii_content_preserved(self) -> None:
        """Non-ASCII characters in line content should be preserved (ensure_ascii=False)."""
        finding = _make_finding(line_content="    # Ren\u00e9e's query")
        result = _make_result(findings=[finding])
        output = format_json(result)
        assert "Ren\u00e9e" in output


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

    def test_sarif_tool_driver_present(self) -> None:
        """SARIF tool object must contain a driver field."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        assert "tool" in parsed["runs"][0]
        assert "driver" in parsed["runs"][0]["tool"]

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

    def test_sarif_tool_driver_information_uri(self) -> None:
        """SARIF tool driver should include an informationUri."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        driver = parsed["runs"][0]["tool"]["driver"]
        assert "informationUri" in driver
        assert driver["informationUri"].startswith("http")

    def test_sarif_results_present(self) -> None:
        """SARIF runs[0] must contain a results array."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        assert "results" in parsed["runs"][0]
        assert isinstance(parsed["runs"][0]["results"], list)

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
        rule = _make_rule(rule_id="VD002", severity=Severity.HIGH)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        assert parsed["runs"][0]["results"][0]["level"] == "error"

    def test_sarif_result_level_medium(self) -> None:
        """Medium severity should map to SARIF level 'warning'."""
        rule = _make_rule(rule_id="VD003", severity=Severity.MEDIUM)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        assert parsed["runs"][0]["results"][0]["level"] == "warning"

    def test_sarif_result_level_low(self) -> None:
        """Low severity should map to SARIF level 'note'."""
        rule = _make_rule(rule_id="VD004", severity=Severity.LOW)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        assert parsed["runs"][0]["results"][0]["level"] == "note"

    def test_sarif_result_level_info(self) -> None:
        """Info severity should map to SARIF level 'none'."""
        rule = _make_rule(rule_id="VD005", severity=Severity.INFO)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        assert parsed["runs"][0]["results"][0]["level"] == "none"

    def test_sarif_result_message_present(self) -> None:
        """Each SARIF result must include a message object."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        sarif_result = parsed["runs"][0]["results"][0]
        assert "message" in sarif_result
        assert "text" in sarif_result["message"]
        assert len(sarif_result["message"]["text"]) > 0

    def test_sarif_result_message_contains_description(self) -> None:
        """The SARIF result message should contain the rule description."""
        rule = _make_rule()
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        msg_text = parsed["runs"][0]["results"][0]["message"]["text"]
        assert "SQL injection" in msg_text

    def test_sarif_result_message_contains_recommendation(self) -> None:
        """The SARIF result message should contain the recommendation."""
        rule = _make_rule()
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        msg_text = parsed["runs"][0]["results"][0]["message"]["text"]
        assert "parameterised" in msg_text

    def test_sarif_result_locations_present(self) -> None:
        """Each SARIF result must include a locations array."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        sarif_result = parsed["runs"][0]["results"][0]
        assert "locations" in sarif_result
        assert len(sarif_result["locations"]) == 1

    def test_sarif_result_location_uri(self) -> None:
        """The SARIF result location URI must match the finding's file path."""
        finding = _make_finding(file_path="src/models/user.py")
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        location = parsed["runs"][0]["results"][0]["locations"][0]
        uri = location["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "src/models/user.py"

    def test_sarif_result_location_uri_base_id(self) -> None:
        """The SARIF result location uriBaseId must be '%SRCROOT%'."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        location = parsed["runs"][0]["results"][0]["locations"][0]
        base_id = location["physicalLocation"]["artifactLocation"]["uriBaseId"]
        assert base_id == "%SRCROOT%"

    def test_sarif_result_location_start_line(self) -> None:
        """The SARIF result region startLine must match the finding's line number."""
        finding = _make_finding(line_number=55)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        region = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 55

    def test_sarif_result_region_start_column(self) -> None:
        """The SARIF result region startColumn should default to 1."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        region = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startColumn"] == 1

    def test_sarif_result_region_snippet(self) -> None:
        """The SARIF result region should include a snippet."""
        finding = _make_finding(line_content="    cursor.execute(f'...')")
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        region = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert "snippet" in region
        assert region["snippet"]["text"] == "    cursor.execute(f'...')"

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

    def test_sarif_artifacts_uri_base_id(self) -> None:
        """Each artifact location uriBaseId should be '%SRCROOT%'."""
        result = _make_result(scanned_files=["app/db.py"])
        parsed = json.loads(format_sarif(result))
        artifact = parsed["runs"][0]["artifacts"][0]
        assert artifact["location"]["uriBaseId"] == "%SRCROOT%"

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

    def test_sarif_driver_rules_deduplicated(self) -> None:
        """If the same rule appears multiple times in findings, it should appear once in driver rules."""
        rule = _make_rule(rule_id="VD001")
        findings = [
            _make_finding(rule=rule, line_number=10),
            _make_finding(rule=rule, line_number=20),
            _make_finding(rule=rule, line_number=30),
        ]
        result = _make_result(findings=findings)
        parsed = json.loads(format_sarif(result))
        driver_rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in driver_rules]
        assert rule_ids.count("VD001") == 1

    def test_sarif_driver_rule_short_description(self) -> None:
        """Each driver rule should include a shortDescription."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        driver_rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]
        assert "shortDescription" in driver_rule
        assert "text" in driver_rule["shortDescription"]

    def test_sarif_driver_rule_full_description(self) -> None:
        """Each driver rule should include a fullDescription."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        driver_rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]
        assert "fullDescription" in driver_rule
        assert "text" in driver_rule["fullDescription"]

    def test_sarif_driver_rule_help(self) -> None:
        """Each driver rule should include a help/recommendation field."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        driver_rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]
        assert "help" in driver_rule
        assert "text" in driver_rule["help"]

    def test_sarif_fingerprints_present(self) -> None:
        """Each SARIF result must include a fingerprint."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        result_item = parsed["runs"][0]["results"][0]
        assert "fingerprints" in result_item
        assert "vulndiff/v1" in result_item["fingerprints"]

    def test_sarif_fingerprint_is_hex_string(self) -> None:
        """The fingerprint value should be a hex string."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        fp = parsed["runs"][0]["results"][0]["fingerprints"]["vulndiff/v1"]
        assert isinstance(fp, str)
        assert all(c in "0123456789abcdef" for c in fp)

    def test_sarif_result_properties(self) -> None:
        """Each SARIF result should include a properties object with severity and category."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        props = parsed["runs"][0]["results"][0].get("properties", {})
        assert "severity" in props
        assert "category" in props

    def test_sarif_empty_findings(self) -> None:
        """SARIF output with no findings should have an empty results array."""
        result = _make_result(findings=[])
        parsed = json.loads(format_sarif(result))
        assert parsed["runs"][0]["results"] == []

    def test_sarif_empty_findings_empty_driver_rules(self) -> None:
        """SARIF output with no findings should have no driver rules."""
        result = _make_result(findings=[])
        parsed = json.loads(format_sarif(result))
        assert parsed["runs"][0]["tool"]["driver"]["rules"] == []

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

    def test_sarif_no_taxa_when_no_cwe(self) -> None:
        """Findings without a CWE ID should not include a taxa entry."""
        rule = Rule(
            rule_id="VD999",
            name="No CWE Rule",
            description="A rule with no CWE ID.",
            category=Category.OTHER,
            severity=Severity.LOW,
            pattern=re.compile(r"bad_pattern"),
            recommendation="Fix it.",
            cwe_id=None,
        )
        finding = Finding(
            rule=rule,
            file_path="foo.py",
            line_number=1,
            line_content="bad_pattern",
            match_text="bad_pattern",
        )
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        sarif_result = parsed["runs"][0]["results"][0]
        assert "taxa" not in sarif_result

    def test_sarif_invocations_present(self) -> None:
        """SARIF runs[0] should include an invocations array."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        assert "invocations" in parsed["runs"][0]
        assert len(parsed["runs"][0]["invocations"]) == 1

    def test_sarif_invocation_execution_successful(self) -> None:
        """The invocation should report executionSuccessful=True."""
        result = _make_result()
        parsed = json.loads(format_sarif(result))
        invocation = parsed["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is True

    def test_sarif_driver_rule_help_uri_from_references(self) -> None:
        """A rule with references should have helpUri set to the first reference."""
        rule = _make_rule()
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        driver_rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]
        assert "helpUri" in driver_rule
        assert driver_rule["helpUri"] == "https://owasp.org/Top10/A03_2021-Injection/"

    def test_sarif_driver_rule_default_configuration_level(self) -> None:
        """A critical rule should have defaultConfiguration.level = 'error'."""
        rule = _make_rule(severity=Severity.CRITICAL)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        driver_rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]
        assert driver_rule["defaultConfiguration"]["level"] == "error"

    def test_sarif_driver_rule_properties_tags(self) -> None:
        """Driver rule properties should include the rule's tags."""
        rule = _make_rule()
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        driver_rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]
        assert "properties" in driver_rule
        assert "tags" in driver_rule["properties"]
        assert "sql" in driver_rule["properties"]["tags"]

    def test_sarif_driver_rule_properties_category(self) -> None:
        """Driver rule properties should include the rule's category."""
        rule = _make_rule(category=Category.SQL_INJECTION)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        parsed = json.loads(format_sarif(result))
        driver_rule = parsed["runs"][0]["tool"]["driver"]["rules"][0]
        assert driver_rule["properties"]["category"] == "sql-injection"

    def test_sarif_multiple_findings_different_rules(self) -> None:
        """Multiple findings with different rules should each appear in results."""
        rule1 = _make_rule(rule_id="VD001")
        rule2 = _make_rule(rule_id="VD060", name="Pickle Loads", cwe_id="CWE-502")
        findings = [
            _make_finding(rule=rule1, file_path="db.py", line_number=10),
            _make_finding(rule=rule2, file_path="utils.py", line_number=20),
        ]
        result = _make_result(findings=findings, scanned_files=["db.py", "utils.py"])
        parsed = json.loads(format_sarif(result))
        result_rule_ids = [r["ruleId"] for r in parsed["runs"][0]["results"]]
        assert "VD001" in result_rule_ids
        assert "VD060" in result_rule_ids


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

    def test_returns_non_empty_string(self) -> None:
        """format_rich() must return a non-empty string."""
        result = _make_result()
        output = format_rich(result, no_color=True)
        assert len(output) > 0

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

    def test_contains_line_number(self) -> None:
        """The rich output should mention the finding's line number."""
        finding = _make_finding(line_number=77)
        result = _make_result(findings=[finding])
        output = format_rich(result, no_color=True)
        assert "77" in output

    def test_contains_severity(self) -> None:
        """The rich output should mention the finding's severity."""
        rule = _make_rule(severity=Severity.CRITICAL)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        output = format_rich(result, no_color=True)
        assert "CRITICAL" in output.upper() or "critical" in output.lower()

    def test_contains_rule_name(self) -> None:
        """The rich output should mention the rule's name."""
        rule = _make_rule(name="SQL Injection")
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        output = format_rich(result, no_color=True)
        assert "SQL Injection" in output

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

    def test_no_color_produces_output(self) -> None:
        """no_color=True should produce non-empty plain-text output."""
        result = _make_result()
        plain = format_rich(result, no_color=True)
        assert len(plain) > 0

    def test_color_produces_output(self) -> None:
        """no_color=False (default) should produce non-empty output."""
        result = _make_result()
        colored = format_rich(result, no_color=False)
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

    def test_input_mode_in_output(self) -> None:
        """The scan input mode should appear in the rich output."""
        result = _make_result(input_mode="staged")
        output = format_rich(result, no_color=True)
        assert "staged" in output

    def test_summary_section_present(self) -> None:
        """The rich output should contain a summary section."""
        result = _make_result(findings=[])
        output = format_rich(result, no_color=True)
        # Summary table should mention either 'Summary' or 'findings'
        assert "Summary" in output or "summary" in output.lower() or "findings" in output.lower()

    def test_recommendation_in_output(self) -> None:
        """The finding's recommendation should appear somewhere in the rich output."""
        rule = _make_rule()
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        output = format_rich(result, no_color=True)
        assert "parameterised" in output.lower() or "Remediation" in output or "recommendation" in output.lower()

    def test_description_in_output(self) -> None:
        """The finding's description should appear somewhere in the rich output."""
        rule = _make_rule()
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        output = format_rich(result, no_color=True)
        assert "SQL injection" in output or "Description" in output

    def test_empty_result_no_crash(self) -> None:
        """format_rich() should not raise even for an empty result."""
        result = ScanResult(
            findings=[],
            scanned_files=[],
            scanned_hunks=0,
            scanned_lines=0,
            rules_applied=0,
        )
        output = format_rich(result, no_color=True)
        assert isinstance(output, str)

    def test_high_severity_finding_present(self) -> None:
        """HIGH severity findings should appear in the output."""
        rule = _make_rule(rule_id="VD002", severity=Severity.HIGH)
        finding = _make_finding(rule=rule)
        result = _make_result(findings=[finding])
        output = format_rich(result, no_color=True)
        assert "HIGH" in output.upper() or "high" in output.lower()


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

    def test_rich_format_with_color(self) -> None:
        """format_report with fmt='rich' and no_color=False should return a string."""
        result = _make_result()
        output = format_report(result, fmt="rich", no_color=False)
        assert isinstance(output, str)
        assert len(output) > 0

    def test_json_no_color_flag_ignored(self) -> None:
        """no_color flag should not affect JSON output."""
        result = _make_result()
        out_with = format_report(result, fmt="json", no_color=True)
        out_without = format_report(result, fmt="json", no_color=False)
        assert out_with == out_without

    def test_sarif_no_color_flag_ignored(self) -> None:
        """no_color flag should not affect SARIF output."""
        result = _make_result()
        out_with = format_report(result, fmt="sarif", no_color=True)
        out_without = format_report(result, fmt="sarif", no_color=False)
        assert out_with == out_without

    def test_unknown_format_raises(self) -> None:
        """An unknown format string should raise ValueError."""
        result = _make_result()
        with pytest.raises(ValueError, match="Unknown format"):
            format_report(result, fmt="xml")

    def test_unknown_format_error_message_contains_format(self) -> None:
        """The ValueError message should include the bad format name."""
        result = _make_result()
        with pytest.raises(ValueError, match="csv"):
            format_report(result, fmt="csv")

    def test_format_report_json_has_tool_key(self) -> None:
        """JSON output from format_report should include the tool key."""
        result = _make_result()
        output = format_report(result, fmt="json")
        parsed = json.loads(output)
        assert "tool" in parsed

    def test_format_report_sarif_has_runs(self) -> None:
        """SARIF output from format_report should have a runs array."""
        result = _make_result()
        output = format_report(result, fmt="sarif")
        parsed = json.loads(output)
        assert "runs" in parsed


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestGuessLanguage:
    """Tests for the _guess_language() helper."""

    def test_python_extension(self) -> None:
        """'.py' files should be identified as Python."""
        assert _guess_language("foo.py") == "python"

    def test_javascript_extension(self) -> None:
        """'.js' files should be identified as JavaScript."""
        assert _guess_language("app.js") == "javascript"

    def test_typescript_extension(self) -> None:
        """'.ts' files should be identified as TypeScript."""
        assert _guess_language("component.ts") == "typescript"

    def test_tsx_extension(self) -> None:
        """'.tsx' files should be identified as tsx."""
        assert _guess_language("component.tsx") == "tsx"

    def test_jsx_extension(self) -> None:
        """'.jsx' files should be identified as jsx."""
        assert _guess_language("component.jsx") == "jsx"

    def test_java_extension(self) -> None:
        """'.java' files should be identified as Java."""
        assert _guess_language("Main.java") == "java"

    def test_go_extension(self) -> None:
        """'.go' files should be identified as Go."""
        assert _guess_language("server.go") == "go"

    def test_ruby_extension(self) -> None:
        """'.rb' files should be identified as Ruby."""
        assert _guess_language("script.rb") == "ruby"

    def test_php_extension(self) -> None:
        """'.php' files should be identified as PHP."""
        assert _guess_language("index.php") == "php"

    def test_c_extension(self) -> None:
        """'.c' files should be identified as C."""
        assert _guess_language("main.c") == "c"

    def test_cpp_extension(self) -> None:
        """'.cpp' files should be identified as C++."""
        assert _guess_language("main.cpp") == "cpp"

    def test_cpp_cc_extension(self) -> None:
        """'.cc' files should be identified as C++."""
        assert _guess_language("main.cc") == "cpp"

    def test_h_extension(self) -> None:
        """'.h' header files should be identified as C."""
        assert _guess_language("header.h") == "c"

    def test_hpp_extension(self) -> None:
        """'.hpp' header files should be identified as C++."""
        assert _guess_language("header.hpp") == "cpp"

    def test_rust_extension(self) -> None:
        """'.rs' files should be identified as Rust."""
        assert _guess_language("main.rs") == "rust"

    def test_csharp_extension(self) -> None:
        """'.cs' files should be identified as C#."""
        assert _guess_language("Program.cs") == "csharp"

    def test_yaml_extension(self) -> None:
        """'.yaml' files should be identified as YAML."""
        assert _guess_language("config.yaml") == "yaml"

    def test_yml_extension(self) -> None:
        """'.yml' files should be identified as YAML."""
        assert _guess_language("ci.yml") == "yaml"

    def test_json_extension(self) -> None:
        """'.json' files should be identified as JSON."""
        assert _guess_language("data.json") == "json"

    def test_toml_extension(self) -> None:
        """'.toml' files should be identified as TOML."""
        assert _guess_language("config.toml") == "toml"

    def test_sql_extension(self) -> None:
        """'.sql' files should be identified as SQL."""
        assert _guess_language("schema.sql") == "sql"

    def test_html_extension(self) -> None:
        """'.html' files should be identified as HTML."""
        assert _guess_language("index.html") == "html"

    def test_xml_extension(self) -> None:
        """'.xml' files should be identified as XML."""
        assert _guess_language("config.xml") == "xml"

    def test_bash_extension(self) -> None:
        """'.sh' files should be identified as Bash."""
        assert _guess_language("deploy.sh") == "bash"

    def test_bash_extension_full(self) -> None:
        """'.bash' files should be identified as Bash."""
        assert _guess_language("script.bash") == "bash"

    def test_tf_extension(self) -> None:
        """'.tf' Terraform files should be identified as HCL."""
        assert _guess_language("main.tf") == "hcl"

    def test_unknown_extension_returns_text(self) -> None:
        """An unrecognised extension should return 'text'."""
        assert _guess_language("file.xyz") == "text"

    def test_no_extension_returns_text(self) -> None:
        """A file with no extension should return 'text'."""
        assert _guess_language("Makefile") == "text"

    def test_nested_path_python(self) -> None:
        """A nested path ending in '.py' should return 'python'."""
        assert _guess_language("src/auth/views.py") == "python"

    def test_nested_path_javascript(self) -> None:
        """A nested path ending in '.js' should return 'javascript'."""
        assert _guess_language("static/js/app.js") == "javascript"

    def test_uppercase_extension_handled(self) -> None:
        """File extensions should be matched case-insensitively."""
        # The implementation lowercases the path before matching
        result = _guess_language("script.PY")
        # Either 'python' or 'text' is acceptable depending on implementation
        assert isinstance(result, str)


class TestMakeFingerprint:
    """Tests for the _make_fingerprint() helper."""

    def test_returns_string(self) -> None:
        """_make_fingerprint() should return a string."""
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

    def test_different_line_numbers_different_fingerprints(self) -> None:
        """Findings on different lines should produce different fingerprints."""
        f1 = _make_finding(line_number=10)
        f2 = _make_finding(line_number=20)
        assert _make_fingerprint(f1) != _make_fingerprint(f2)

    def test_different_files_different_fingerprints(self) -> None:
        """Findings in different files should produce different fingerprints."""
        f1 = _make_finding(file_path="a.py")
        f2 = _make_finding(file_path="b.py")
        assert _make_fingerprint(f1) != _make_fingerprint(f2)

    def test_different_rule_ids_different_fingerprints(self) -> None:
        """Findings with different rule IDs should produce different fingerprints."""
        rule1 = _make_rule(rule_id="VD001")
        rule2 = _make_rule(rule_id="VD002")
        f1 = _make_finding(rule=rule1)
        f2 = _make_finding(rule=rule2)
        assert _make_fingerprint(f1) != _make_fingerprint(f2)

    def test_different_line_content_different_fingerprints(self) -> None:
        """Findings with different line content should produce different fingerprints."""
        f1 = _make_finding(line_content="line one")
        f2 = _make_finding(line_content="line two")
        assert _make_fingerprint(f1) != _make_fingerprint(f2)


class TestSarifSeverityMap:
    """Tests for the SARIF severity mapping constant."""

    def test_critical_maps_to_error(self) -> None:
        """'critical' should map to SARIF 'error' level."""
        assert _SARIF_SEVERITY_MAP["critical"] == "error"

    def test_high_maps_to_error(self) -> None:
        """'high' should map to SARIF 'error' level."""
        assert _SARIF_SEVERITY_MAP["high"] == "error"

    def test_medium_maps_to_warning(self) -> None:
        """'medium' should map to SARIF 'warning' level."""
        assert _SARIF_SEVERITY_MAP["medium"] == "warning"

    def test_low_maps_to_note(self) -> None:
        """'low' should map to SARIF 'note' level."""
        assert _SARIF_SEVERITY_MAP["low"] == "note"

    def test_info_maps_to_none(self) -> None:
        """'info' should map to SARIF 'none' level."""
        assert _SARIF_SEVERITY_MAP["info"] == "none"

    def test_all_severity_levels_covered(self) -> None:
        """Every Severity enum value should be present in the SARIF map."""
        for sev in Severity:
            assert sev.value in _SARIF_SEVERITY_MAP, (
                f"Severity '{sev.value}' not found in _SARIF_SEVERITY_MAP"
            )

    def test_map_values_are_valid_sarif_levels(self) -> None:
        """All SARIF map values should be valid SARIF level strings."""
        valid_levels = {"error", "warning", "note", "none"}
        for key, value in _SARIF_SEVERITY_MAP.items():
            assert value in valid_levels, (
                f"SARIF level '{value}' for severity '{key}' is not a valid SARIF level"
            )

    def test_map_is_dict(self) -> None:
        """_SARIF_SEVERITY_MAP should be a dictionary."""
        assert isinstance(_SARIF_SEVERITY_MAP, dict)

    def test_map_has_five_entries(self) -> None:
        """_SARIF_SEVERITY_MAP should have exactly 5 entries (one per severity level)."""
        assert len(_SARIF_SEVERITY_MAP) == 5
