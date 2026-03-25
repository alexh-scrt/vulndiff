"""Unit and integration tests for vulndiff.cli.

Tests cover argument parsing, input mode resolution, exit code behaviour,
and output format dispatching.  Subprocess git calls and the scanner are
mocked to keep tests fast and hermetic.
"""

from __future__ import annotations

import json
import sys
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from vulndiff.cli import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    _build_parser,
    _resolve_input_mode,
    _validate_to_ref_requires_from_ref,
    main,
)
from vulndiff.models import DiffHunk, Finding, Rule, ScanResult, Severity, Category
import re


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_rule(
    rule_id: str = "VD001",
    severity: Severity = Severity.HIGH,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        name="Test Rule",
        description="A test rule.",
        category=Category.OTHER,
        severity=severity,
        pattern=re.compile(r"BAD"),
        recommendation="Fix it.",
    )


def _make_finding(
    rule: Rule = None,
    file_path: str = "app/views.py",
    line_number: int = 10,
) -> Finding:
    if rule is None:
        rule = _make_rule()
    return Finding(
        rule=rule,
        file_path=file_path,
        line_number=line_number,
        line_content="    BAD code here",
        match_text="BAD",
    )


def _empty_scan_result() -> ScanResult:
    return ScanResult(
        findings=[],
        scanned_files=[],
        scanned_hunks=0,
        scanned_lines=0,
        rules_applied=50,
        input_mode="staged",
    )


def _scan_result_with_findings() -> ScanResult:
    finding = _make_finding()
    return ScanResult(
        findings=[finding],
        scanned_files=["app/views.py"],
        scanned_hunks=1,
        scanned_lines=5,
        rules_applied=50,
        input_mode="staged",
    )


# ---------------------------------------------------------------------------
# Argument parser tests
# ---------------------------------------------------------------------------


class TestBuildParser:
    """Tests for _build_parser()."""

    def test_returns_parser(self) -> None:
        """_build_parser() should return an ArgumentParser."""
        import argparse
        parser = _build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_default_format_is_rich(self) -> None:
        """Default --format should be 'rich'."""
        parser = _build_parser()
        args = parser.parse_args([])
        assert args.format == "rich"

    def test_default_severity_is_low(self) -> None:
        """Default --severity should be 'low'."""
        parser = _build_parser()
        args = parser.parse_args([])
        assert args.severity == "low"

    def test_default_no_color_false(self) -> None:
        """Default --no-color should be False."""
        parser = _build_parser()
        args = parser.parse_args([])
        assert args.no_color is False

    def test_default_no_fail_false(self) -> None:
        """Default --no-fail should be False."""
        parser = _build_parser()
        args = parser.parse_args([])
        assert args.no_fail is False

    def test_staged_flag(self) -> None:
        """--staged should set args.staged=True."""
        parser = _build_parser()
        args = parser.parse_args(["--staged"])
        assert args.staged is True

    def test_head_flag(self) -> None:
        """--head should set args.head=True."""
        parser = _build_parser()
        args = parser.parse_args(["--head"])
        assert args.head is True

    def test_from_ref_and_to_ref(self) -> None:
        """--from-ref and --to-ref should be parsed correctly."""
        parser = _build_parser()
        args = parser.parse_args(["--from-ref", "main", "--to-ref", "HEAD"])
        assert args.from_ref == "main"
        assert args.to_ref == "HEAD"

    def test_from_ref_default_to_ref_is_head(self) -> None:
        """--from-ref without --to-ref should default to_ref to 'HEAD'."""
        parser = _build_parser()
        args = parser.parse_args(["--from-ref", "main"])
        assert args.to_ref == "HEAD"

    def test_staged_and_head_mutually_exclusive(self) -> None:
        """--staged and --head should be mutually exclusive."""
        parser = _build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--staged", "--head"])
        assert exc_info.value.code == 2

    def test_staged_and_from_ref_mutually_exclusive(self) -> None:
        """--staged and --from-ref should be mutually exclusive."""
        parser = _build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--staged", "--from-ref", "main"])
        assert exc_info.value.code == 2

    def test_format_choices(self) -> None:
        """--format should accept rich, json, sarif."""
        parser = _build_parser()
        for fmt in ["rich", "json", "sarif"]:
            args = parser.parse_args(["--format", fmt])
            assert args.format == fmt

    def test_format_invalid_raises(self) -> None:
        """--format with an invalid value should exit with code 2."""
        parser = _build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--format", "xml"])
        assert exc_info.value.code == 2

    def test_severity_choices(self) -> None:
        """--severity should accept all Severity enum values."""
        parser = _build_parser()
        for sev in ["info", "low", "medium", "high", "critical"]:
            args = parser.parse_args(["--severity", sev])
            assert args.severity == sev

    def test_severity_invalid_raises(self) -> None:
        """--severity with an invalid value should exit with code 2."""
        parser = _build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--severity", "extreme"])
        assert exc_info.value.code == 2

    def test_no_color_flag(self) -> None:
        """--no-color should set args.no_color=True."""
        parser = _build_parser()
        args = parser.parse_args(["--no-color"])
        assert args.no_color is True

    def test_no_fail_flag(self) -> None:
        """--no-fail should set args.no_fail=True."""
        parser = _build_parser()
        args = parser.parse_args(["--no-fail"])
        assert args.no_fail is True

    def test_fail_on_findings_flag(self) -> None:
        """--fail-on-findings should set args.fail_on_findings=True."""
        parser = _build_parser()
        args = parser.parse_args(["--fail-on-findings"])
        assert args.fail_on_findings is True

    def test_fail_and_no_fail_mutually_exclusive(self) -> None:
        """--fail-on-findings and --no-fail should be mutually exclusive."""
        parser = _build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--fail-on-findings", "--no-fail"])
        assert exc_info.value.code == 2

    def test_output_file_option(self) -> None:
        """--output should store the output file path."""
        parser = _build_parser()
        args = parser.parse_args(["--output", "results.json"])
        assert args.output_file == "results.json"

    def test_list_rules_flag(self) -> None:
        """--list-rules should set args.list_rules=True."""
        parser = _build_parser()
        args = parser.parse_args(["--list-rules"])
        assert args.list_rules is True

    def test_version_flag_exits(self) -> None:
        """--version should exit with code 0."""
        parser = _build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# _resolve_input_mode tests
# ---------------------------------------------------------------------------


class TestResolveInputMode:
    """Tests for _resolve_input_mode()."""

    def test_default_is_staged(self) -> None:
        """With no flags, mode should default to 'staged'."""
        parser = _build_parser()
        args = parser.parse_args([])
        mode, from_ref, to_ref = _resolve_input_mode(args)
        assert mode == "staged"
        assert from_ref is None

    def test_staged_flag_returns_staged(self) -> None:
        """--staged should produce mode='staged'."""
        parser = _build_parser()
        args = parser.parse_args(["--staged"])
        mode, from_ref, to_ref = _resolve_input_mode(args)
        assert mode == "staged"

    def test_head_flag_returns_head(self) -> None:
        """--head should produce mode='head'."""
        parser = _build_parser()
        args = parser.parse_args(["--head"])
        mode, from_ref, to_ref = _resolve_input_mode(args)
        assert mode == "head"
        assert from_ref is None

    def test_from_ref_returns_ref_range(self) -> None:
        """--from-ref should produce mode='ref-range'."""
        parser = _build_parser()
        args = parser.parse_args(["--from-ref", "main"])
        mode, from_ref, to_ref = _resolve_input_mode(args)
        assert mode == "ref-range"
        assert from_ref == "main"

    def test_from_ref_and_to_ref(self) -> None:
        """--from-ref and --to-ref should set both refs."""
        parser = _build_parser()
        args = parser.parse_args(["--from-ref", "v1.0", "--to-ref", "v2.0"])
        mode, from_ref, to_ref = _resolve_input_mode(args)
        assert mode == "ref-range"
        assert from_ref == "v1.0"


# ---------------------------------------------------------------------------
# main() exit code tests
# ---------------------------------------------------------------------------


class TestMainExitCodes:
    """Tests for exit code behaviour in main()."""

    def test_exit_ok_when_no_findings(self) -> None:
        """main() should return EXIT_OK when there are no findings."""
        empty_result = _empty_scan_result()
        with patch("vulndiff.cli._run_scan", return_value=empty_result):
            code = main(["--staged", "--format", "json"])
        assert code == EXIT_OK

    def test_exit_findings_when_findings_present(self) -> None:
        """main() should return EXIT_FINDINGS when findings are present."""
        result_with_findings = _scan_result_with_findings()
        with patch("vulndiff.cli._run_scan", return_value=result_with_findings):
            code = main(["--staged", "--format", "json"])
        assert code == EXIT_FINDINGS

    def test_no_fail_overrides_findings(self) -> None:
        """--no-fail should cause EXIT_OK even when findings are present."""
        result_with_findings = _scan_result_with_findings()
        with patch("vulndiff.cli._run_scan", return_value=result_with_findings):
            code = main(["--staged", "--no-fail", "--format", "json"])
        assert code == EXIT_OK

    def test_exit_error_on_git_error(self) -> None:
        """A GitError should cause EXIT_ERROR."""
        from vulndiff.git_diff import GitError
        with patch("vulndiff.cli._run_scan", side_effect=GitError("git failed", 1)):
            code = main(["--staged", "--format", "json"])
        assert code == EXIT_ERROR

    def test_exit_error_on_not_a_git_repo(self) -> None:
        """A NotAGitRepositoryError should cause EXIT_ERROR."""
        from vulndiff.git_diff import NotAGitRepositoryError
        with patch(
            "vulndiff.cli._run_scan",
            side_effect=NotAGitRepositoryError("not a repo"),
        ):
            code = main(["--staged", "--format", "json"])
        assert code == EXIT_ERROR

    def test_exit_error_on_value_error(self) -> None:
        """A ValueError from the scan pipeline should cause EXIT_ERROR."""
        with patch("vulndiff.cli._run_scan", side_effect=ValueError("bad value")):
            code = main(["--staged", "--format", "json"])
        assert code == EXIT_ERROR

    def test_exit_error_on_unexpected_exception(self) -> None:
        """An unexpected exception should cause EXIT_ERROR."""
        with patch("vulndiff.cli._run_scan", side_effect=RuntimeError("boom")):
            code = main(["--staged", "--format", "json"])
        assert code == EXIT_ERROR

    def test_exit_ok_with_head_mode(self) -> None:
        """--head mode with no findings should return EXIT_OK."""
        empty_result = _empty_scan_result()
        empty_result.input_mode = "head"
        with patch("vulndiff.cli._run_scan", return_value=empty_result):
            code = main(["--head", "--format", "json"])
        assert code == EXIT_OK

    def test_exit_ok_with_ref_range(self) -> None:
        """--from-ref / --to-ref with no findings should return EXIT_OK."""
        empty_result = _empty_scan_result()
        empty_result.input_mode = "ref-range"
        with patch("vulndiff.cli._run_scan", return_value=empty_result):
            code = main(["--from-ref", "main", "--to-ref", "HEAD", "--format", "json"])
        assert code == EXIT_OK


# ---------------------------------------------------------------------------
# main() output format tests
# ---------------------------------------------------------------------------


class TestMainOutputFormats:
    """Tests for output format dispatching in main()."""

    def test_json_output_written_to_stdout(self, capsys: pytest.CaptureFixture) -> None:
        """--format json should write valid JSON to stdout."""
        empty_result = _empty_scan_result()
        with patch("vulndiff.cli._run_scan", return_value=empty_result):
            main(["--staged", "--format", "json"])
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert "findings" in parsed

    def test_sarif_output_written_to_stdout(self, capsys: pytest.CaptureFixture) -> None:
        """--format sarif should write valid SARIF JSON to stdout."""
        empty_result = _empty_scan_result()
        with patch("vulndiff.cli._run_scan", return_value=empty_result):
            main(["--staged", "--format", "sarif"])
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["version"] == "2.1.0"

    def test_rich_output_contains_vulndiff(self, capsys: pytest.CaptureFixture) -> None:
        """--format rich should write a string mentioning 'vulndiff' to stdout."""
        empty_result = _empty_scan_result()
        with patch("vulndiff.cli._run_scan", return_value=empty_result):
            main(["--staged", "--format", "rich", "--no-color"])
        captured = capsys.readouterr()
        assert "vulndiff" in captured.out.lower() or "vulndiff" in captured.out

    def test_output_file_written(self, tmp_path) -> None:
        """--output FILE should write the report to the given file."""
        empty_result = _empty_scan_result()
        output_path = tmp_path / "report.json"
        with patch("vulndiff.cli._run_scan", return_value=empty_result):
            code = main([
                "--staged",
                "--format", "json",
                "--output", str(output_path),
            ])
        assert code == EXIT_OK
        assert output_path.exists()
        parsed = json.loads(output_path.read_text(encoding="utf-8"))
        assert "findings" in parsed

    def test_output_file_error_returns_exit_error(self, tmp_path) -> None:
        """If the output file cannot be written, EXIT_ERROR should be returned."""
        empty_result = _empty_scan_result()
        # Use a path inside a non-existent directory
        bad_path = str(tmp_path / "nonexistent_dir" / "report.json")
        with patch("vulndiff.cli._run_scan", return_value=empty_result):
            code = main([
                "--staged",
                "--format", "json",
                "--output", bad_path,
            ])
        assert code == EXIT_ERROR


# ---------------------------------------------------------------------------
# main() severity filtering tests
# ---------------------------------------------------------------------------


class TestMainSeverityFiltering:
    """Tests that severity filter is passed through to the scan pipeline."""

    def test_severity_passed_to_run_scan(self) -> None:
        """The --severity flag value should be forwarded to _run_scan."""
        empty_result = _empty_scan_result()
        with patch("vulndiff.cli._run_scan", return_value=empty_result) as mock_scan:
            main(["--staged", "--severity", "high", "--format", "json"])
            call_kwargs = mock_scan.call_args[1]
            assert call_kwargs["severity_filter"] == Severity.HIGH

    def test_default_severity_low_passed(self) -> None:
        """Default severity (low) should be forwarded to _run_scan."""
        empty_result = _empty_scan_result()
        with patch("vulndiff.cli._run_scan", return_value=empty_result) as mock_scan:
            main(["--staged", "--format", "json"])
            call_kwargs = mock_scan.call_args[1]
            assert call_kwargs["severity_filter"] == Severity.LOW

    def test_rules_above_flag_forwarded(self) -> None:
        """--rules-above should set rules_above=True in _run_scan call."""
        empty_result = _empty_scan_result()
        with patch("vulndiff.cli._run_scan", return_value=empty_result) as mock_scan:
            main(["--staged", "--rules-above", "--format", "json"])
            call_kwargs = mock_scan.call_args[1]
            assert call_kwargs["rules_above"] is True


# ---------------------------------------------------------------------------
# Validate to_ref requires from_ref
# ---------------------------------------------------------------------------


class TestValidateToRefRequiresFromRef:
    """Tests for the --to-ref / --from-ref cross-validation."""

    def test_to_ref_without_from_ref_raises(self) -> None:
        """--to-ref without --from-ref (and not --head) should exit with code 2."""
        parser = _build_parser()
        args = parser.parse_args(["--to-ref", "feature/x"])
        with pytest.raises(SystemExit) as exc_info:
            _validate_to_ref_requires_from_ref(args, parser)
        assert exc_info.value.code == 2

    def test_to_ref_with_from_ref_ok(self) -> None:
        """--to-ref with --from-ref should not raise."""
        parser = _build_parser()
        args = parser.parse_args(["--from-ref", "main", "--to-ref", "feature/x"])
        # Should not raise
        _validate_to_ref_requires_from_ref(args, parser)

    def test_default_to_ref_without_from_ref_ok(self) -> None:
        """Default --to-ref (HEAD) without --from-ref should not raise."""
        parser = _build_parser()
        args = parser.parse_args(["--staged"])
        # default to_ref is HEAD — no error expected
        _validate_to_ref_requires_from_ref(args, parser)


# ---------------------------------------------------------------------------
# list-rules tests
# ---------------------------------------------------------------------------


class TestListRules:
    """Tests for --list-rules."""

    def test_list_rules_exits_zero(self) -> None:
        """--list-rules should exit with code 0."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--list-rules"])
        assert exc_info.value.code == EXIT_OK

    def test_list_rules_output_contains_rule_ids(self, capsys: pytest.CaptureFixture) -> None:
        """--list-rules output should mention at least one rule ID."""
        with pytest.raises(SystemExit):
            main(["--list-rules"])
        captured = capsys.readouterr()
        # VD001 is the first SQL injection rule
        assert "VD001" in captured.out


# ---------------------------------------------------------------------------
# _run_scan unit tests
# ---------------------------------------------------------------------------


class TestRunScan:
    """Unit tests for the _run_scan() internal function."""

    def test_run_scan_staged_calls_get_hunks(self) -> None:
        """_run_scan with staged mode should call get_hunks with mode='staged'."""
        from vulndiff.cli import _run_scan

        with patch("vulndiff.cli.get_hunks", return_value=[]) as mock_get_hunks:
            with patch("vulndiff.cli.scan", return_value=_empty_scan_result()):
                _run_scan(
                    mode="staged",
                    from_ref=None,
                    to_ref="HEAD",
                    severity_filter=Severity.LOW,
                    rules_above=False,
                )
            mock_get_hunks.assert_called_once()
            call_kwargs = mock_get_hunks.call_args[1]
            assert call_kwargs["mode"] == "staged"

    def test_run_scan_rules_above_loads_filtered_rules(self) -> None:
        """rules_above=True should call get_rules_at_or_above_severity."""
        from vulndiff.cli import _run_scan

        with patch("vulndiff.cli.get_hunks", return_value=[]):
            with patch("vulndiff.cli.scan", return_value=_empty_scan_result()):
                with patch(
                    "vulndiff.cli.get_rules_at_or_above_severity",
                    return_value=[],
                ) as mock_filter:
                    _run_scan(
                        mode="staged",
                        from_ref=None,
                        to_ref="HEAD",
                        severity_filter=Severity.HIGH,
                        rules_above=True,
                    )
                    mock_filter.assert_called_once_with(Severity.HIGH)

    def test_run_scan_all_rules_when_not_above(self) -> None:
        """rules_above=False should call get_all_rules."""
        from vulndiff.cli import _run_scan

        with patch("vulndiff.cli.get_hunks", return_value=[]):
            with patch("vulndiff.cli.scan", return_value=_empty_scan_result()):
                with patch(
                    "vulndiff.cli.get_all_rules", return_value=[]
                ) as mock_all:
                    _run_scan(
                        mode="staged",
                        from_ref=None,
                        to_ref="HEAD",
                        severity_filter=Severity.LOW,
                        rules_above=False,
                    )
                    mock_all.assert_called_once()

    def test_run_scan_returns_scan_result(self) -> None:
        """_run_scan should return a ScanResult."""
        from vulndiff.cli import _run_scan
        from vulndiff.models import ScanResult

        with patch("vulndiff.cli.get_hunks", return_value=[]):
            result = _run_scan(
                mode="staged",
                from_ref=None,
                to_ref="HEAD",
                severity_filter=Severity.LOW,
                rules_above=False,
            )
        assert isinstance(result, ScanResult)
