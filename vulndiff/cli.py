"""Command-line interface entry point for vulndiff.

This module wires together all vulndiff components — diff extraction,
scanning, and reporting — behind an argparse-based CLI.  It is the module
referenced by the ``vulndiff`` console-scripts entry point defined in
``pyproject.toml``.

Supported input modes:

- ``--staged``   — scan staged changes (pre-commit hook usage).
- ``--head``     — scan the most recent commit (HEAD~1..HEAD).
- ``--from-ref`` / ``--to-ref`` — scan an arbitrary git ref range (CI usage).

Supported output formats:

- ``rich``  — colourised terminal output (default).
- ``json``  — machine-parseable JSON.
- ``sarif`` — SARIF 2.1.0 for GitHub Advanced Security / VS Code.

Exit codes:

- ``0`` — no findings at or above the severity threshold (or ``--no-fail`` mode).
- ``1`` — one or more findings at or above the severity threshold.
- ``2`` — tool error (invalid arguments, git not available, etc.).

Example usage::

    # Pre-commit hook (default: staged, rich output, fail on findings)
    vulndiff --staged

    # CI pipeline with JSON output and medium-severity threshold
    vulndiff --from-ref main --to-ref HEAD --severity medium --format json

    # Advisory mode: never fail the build
    vulndiff --head --no-fail
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from vulndiff import __version__
from vulndiff.git_diff import (
    GitError,
    NotAGitRepositoryError,
    get_hunks,
)
from vulndiff.models import DiffHunk, Severity
from vulndiff.reporter import format_report, print_rich
from vulndiff.rules import get_all_rules, get_rules_at_or_above_severity
from vulndiff.scanner import scan


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


# ---------------------------------------------------------------------------
# Argument parser construction
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Construct and return the vulndiff argument parser.

    Returns:
        A configured :class:`argparse.ArgumentParser` instance.
    """
    parser = argparse.ArgumentParser(
        prog="vulndiff",
        description=(
            "vulndiff — diff-aware security scanner for AI-assisted codebases.\n"
            "\n"
            "Analyzes staged or committed code changes against a curated set of\n"
            "vulnerability patterns covering OWASP Top 10, injection flaws,\n"
            "authentication issues, hardcoded secrets, and more."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes:\n"
            "  0  No findings (or --no-fail mode)\n"
            "  1  One or more findings at or above the severity threshold\n"
            "  2  Tool error (invalid arguments, git not available, etc.)\n"
            "\n"
            "Examples:\n"
            "  vulndiff --staged\n"
            "  vulndiff --head --severity high\n"
            "  vulndiff --from-ref main --to-ref HEAD --format json\n"
            "  vulndiff --staged --format sarif > results.sarif\n"
        ),
    )

    # ---- Version ----------------------------------------------------------
    parser.add_argument(
        "--version",
        action="version",
        version=f"vulndiff {__version__}",
    )

    # ---- Input mode (mutually exclusive group) ----------------------------
    input_group = parser.add_argument_group(
        "input mode",
        "Select which git changes to scan (default: --staged).",
    )
    mode_exclusive = input_group.add_mutually_exclusive_group()

    mode_exclusive.add_argument(
        "--staged",
        action="store_true",
        default=False,
        help="Scan staged changes (git diff --cached). Default mode.",
    )
    mode_exclusive.add_argument(
        "--head",
        action="store_true",
        default=False,
        help="Scan changes in the last commit (HEAD~1..HEAD).",
    )
    mode_exclusive.add_argument(
        "--from-ref",
        metavar="REF",
        dest="from_ref",
        default=None,
        help=(
            "Start git ref for a range scan (branch, tag, or commit SHA). "
            "Must be combined with --to-ref."
        ),
    )

    input_group.add_argument(
        "--to-ref",
        metavar="REF",
        dest="to_ref",
        default="HEAD",
        help="End git ref for a range scan (default: HEAD).",
    )

    # ---- Output options ---------------------------------------------------
    output_group = parser.add_argument_group("output")

    output_group.add_argument(
        "--format",
        choices=["rich", "json", "sarif"],
        default="rich",
        metavar="FORMAT",
        help="Output format: rich (default), json, or sarif.",
    )
    output_group.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        dest="no_color",
        help="Disable ANSI colour codes in rich terminal output.",
    )
    output_group.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        dest="output_file",
        default=None,
        help=(
            "Write output to FILE instead of stdout. "
            "Useful for saving SARIF or JSON reports."
        ),
    )

    # ---- Filtering --------------------------------------------------------
    filter_group = parser.add_argument_group("filtering")

    filter_group.add_argument(
        "--severity",
        choices=[s.value for s in Severity],
        default=Severity.LOW.value,
        metavar="LEVEL",
        help=(
            "Minimum severity level to report. "
            "Choices: info, low (default), medium, high, critical."
        ),
    )

    # ---- CI / exit code behaviour ----------------------------------------
    exit_group = parser.add_argument_group("CI / exit code")

    exit_exclusive = exit_group.add_mutually_exclusive_group()
    exit_exclusive.add_argument(
        "--fail-on-findings",
        action="store_true",
        default=False,
        dest="fail_on_findings",
        help=(
            "Exit with code 1 if any findings are reported at or above the "
            "severity threshold. This is the default behaviour."
        ),
    )
    exit_exclusive.add_argument(
        "--no-fail",
        action="store_true",
        default=False,
        dest="no_fail",
        help=(
            "Always exit with code 0 even when findings are present. "
            "Useful for advisory / informational runs."
        ),
    )

    # ---- Advanced ---------------------------------------------------------
    advanced_group = parser.add_argument_group("advanced")

    advanced_group.add_argument(
        "--rules-above",
        action="store_true",
        default=False,
        dest="rules_above",
        help=(
            "Only load rules whose severity is at or above the --severity "
            "threshold. Slightly faster but may miss lower-severity patterns "
            "that co-occur with high-severity issues."
        ),
    )
    advanced_group.add_argument(
        "--list-rules",
        action="store_true",
        default=False,
        dest="list_rules",
        help="Print all available rules and exit.",
    )

    return parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_input_mode(
    args: argparse.Namespace,
) -> tuple[str, Optional[str], str]:
    """Derive the canonical (mode, from_ref, to_ref) triple from parsed args.

    If no mode flag is supplied, ``--staged`` is used as the default.

    Args:
        args: Parsed :class:`argparse.Namespace` from the argument parser.

    Returns:
        A ``(mode, from_ref, to_ref)`` tuple where *mode* is one of
        ``"staged"``, ``"head"``, or ``"ref-range"``.

    Raises:
        SystemExit: (via :func:`argparse.ArgumentParser.error`) if
            ``--from-ref`` is supplied without ``--to-ref`` being meaningful
            or if conflicting flags are detected.
    """
    if args.head:
        return "head", None, "HEAD"
    if args.from_ref is not None:
        return "ref-range", args.from_ref, args.to_ref
    # Default: staged
    return "staged", None, None


def _list_rules_and_exit(severity_filter: Severity) -> None:
    """Print a table of all available rules to stdout and exit with code 0.

    Args:
        severity_filter: If provided, only rules at or above this severity
                         are shown.  Passing :attr:`Severity.INFO` shows all.
    """
    from rich.console import Console
    from rich.table import Table
    from rich import box as rich_box
    from vulndiff.rules import get_all_rules

    console = Console()
    all_rules = get_all_rules()

    table = Table(
        title=f"vulndiff rules ({len(all_rules)} total)",
        box=rich_box.ROUNDED,
        show_header=True,
        header_style="bold bright_blue",
        show_lines=False,
    )
    table.add_column("ID", style="bold cyan", min_width=7)
    table.add_column("Severity", min_width=8)
    table.add_column("Category", min_width=22)
    table.add_column("Name", min_width=40)

    _sev_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }

    for rule in sorted(all_rules, key=lambda r: r.rule_id):
        sev = rule.severity.value
        table.add_row(
            rule.rule_id,
            f"[{_sev_styles.get(sev, 'white')}]{sev}[/]",
            rule.category.value,
            rule.name,
        )

    console.print(table)
    sys.exit(EXIT_OK)


def _validate_to_ref_requires_from_ref(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> None:
    """Emit an error if --to-ref is used without --from-ref.

    The ``--to-ref`` flag only makes sense when ``--from-ref`` is also
    supplied.  This validation is performed after parsing because argparse
    cannot natively express this dependency.

    Args:
        args:   Parsed namespace.
        parser: The argument parser (used to call ``parser.error()``).
    """
    # --to-ref has a default of "HEAD" so we check whether the user explicitly
    # provided it alongside an incompatible mode.  We only warn/error when
    # to-ref differs from default AND from-ref is absent.
    if args.to_ref != "HEAD" and args.from_ref is None and not args.head:
        parser.error(
            "--to-ref requires --from-ref to also be specified."
        )


# ---------------------------------------------------------------------------
# Core scan pipeline
# ---------------------------------------------------------------------------


def _run_scan(
    mode: str,
    from_ref: Optional[str],
    to_ref: str,
    severity_filter: Severity,
    rules_above: bool,
) -> "ScanResult":  # noqa: F821
    """Execute the full scan pipeline and return a ScanResult.

    Args:
        mode:            One of ``"staged"``, ``"head"``, ``"ref-range"``.
        from_ref:        Start ref (for ref-range mode).
        to_ref:          End ref (for ref-range mode).
        severity_filter: Minimum severity to report.
        rules_above:     When ``True``, only load rules at or above *severity_filter*.

    Returns:
        A :class:`~vulndiff.models.ScanResult` from the scanner.

    Raises:
        GitError:                If git fails or is not available.
        NotAGitRepositoryError:  If the current directory is not a git repo.
    """
    # 1. Extract diff hunks
    hunks: List[DiffHunk] = get_hunks(
        mode=mode,
        from_ref=from_ref,
        to_ref=to_ref if mode == "ref-range" else "HEAD",
    )

    # 2. Load rules
    if rules_above:
        rules = get_rules_at_or_above_severity(severity_filter)
    else:
        rules = get_all_rules()

    # 3. Scan
    to_ref_label: Optional[str] = to_ref if mode == "ref-range" else None

    result = scan(
        hunks=hunks,
        rules=rules,
        severity_filter=severity_filter,
        input_mode=mode,
        from_ref=from_ref,
        to_ref=to_ref_label,
    )
    return result


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    """Primary entry point for the vulndiff CLI.

    This function is registered as the ``vulndiff`` console-scripts entry
    point in ``pyproject.toml``.  It can also be called programmatically
    by passing a list of argument strings via *argv*.

    Args:
        argv: Argument list to parse.  When ``None``, :data:`sys.argv` is
              used (standard argparse behaviour).

    Returns:
        An integer exit code:

        - ``0`` — success / no findings.
        - ``1`` — findings at or above the severity threshold.
        - ``2`` — tool error.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    # ---- --list-rules shortcut --------------------------------------------
    if args.list_rules:
        severity_filter = Severity(args.severity)
        _list_rules_and_exit(severity_filter)
        # _list_rules_and_exit calls sys.exit(); this line is never reached.
        return EXIT_OK  # pragma: no cover

    # ---- Validate cross-argument constraints ------------------------------
    _validate_to_ref_requires_from_ref(args, parser)

    # ---- Resolve input mode -----------------------------------------------
    mode, from_ref, to_ref_resolved = _resolve_input_mode(args)
    # For ref-range the to_ref comes from --to-ref argument
    if mode == "ref-range":
        to_ref_resolved = args.to_ref

    severity_filter = Severity(args.severity)

    # ---- Run scan ---------------------------------------------------------
    try:
        result = _run_scan(
            mode=mode,
            from_ref=from_ref,
            to_ref=to_ref_resolved or "HEAD",
            severity_filter=severity_filter,
            rules_above=args.rules_above,
        )
    except NotAGitRepositoryError as exc:
        _print_error(
            f"Not a git repository: {exc}",
            no_color=args.no_color,
        )
        return EXIT_ERROR
    except GitError as exc:
        _print_error(
            f"Git error: {exc}",
            no_color=args.no_color,
        )
        return EXIT_ERROR
    except ValueError as exc:
        _print_error(
            f"Invalid argument: {exc}",
            no_color=args.no_color,
        )
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001
        _print_error(
            f"Unexpected error: {exc}",
            no_color=args.no_color,
        )
        return EXIT_ERROR

    # ---- Format and emit output -------------------------------------------
    fmt = args.format
    no_color = args.no_color

    try:
        if fmt == "rich" and args.output_file is None:
            # Stream directly to console for best fidelity
            print_rich(result, no_color=no_color, file=sys.stdout)
        else:
            report_text = format_report(result, fmt=fmt, no_color=no_color)
            if args.output_file is not None:
                try:
                    with open(args.output_file, "w", encoding="utf-8") as fh:
                        fh.write(report_text)
                except OSError as exc:
                    _print_error(
                        f"Could not write to output file {args.output_file!r}: {exc}",
                        no_color=no_color,
                    )
                    return EXIT_ERROR
            else:
                sys.stdout.write(report_text)
                if not report_text.endswith("\n"):
                    sys.stdout.write("\n")
    except ValueError as exc:
        _print_error(f"Formatting error: {exc}", no_color=no_color)
        return EXIT_ERROR

    # ---- Determine exit code ----------------------------------------------
    if args.no_fail:
        return EXIT_OK

    if result.has_findings:
        return EXIT_FINDINGS

    return EXIT_OK


def _print_error(message: str, no_color: bool = False) -> None:
    """Print an error message to stderr.

    Args:
        message:  The error message to display.
        no_color: When ``True``, ANSI colour codes are omitted.
    """
    try:
        from rich.console import Console

        err_console = Console(stderr=True, no_color=no_color)
        err_console.print(f"[bold red]Error:[/bold red] {message}")
    except Exception:  # noqa: BLE001
        # Fallback if rich is not available or has an internal error
        print(f"Error: {message}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Script entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
