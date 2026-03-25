"""Report formatters for vulndiff scan results.

This module provides three output formats for :class:`~vulndiff.models.ScanResult`
objects:

- **rich** — A colourised, human-readable terminal report using the ``rich``
  library.  Suitable for interactive use and pre-commit hook output.
- **json** — Structured JSON output that mirrors :meth:`ScanResult.to_dict`.
  Suitable for CI pipelines and machine consumption.
- **sarif** — Static Analysis Results Interchange Format (SARIF) 2.1.0 output
  for integration with GitHub Advanced Security, VS Code, and other SARIF-aware
  tooling.

Public API::

    from vulndiff.reporter import format_rich, format_json, format_sarif, print_rich
    from vulndiff.models import ScanResult

    result: ScanResult = ...  # from scanner.scan()

    # Print to terminal
    print_rich(result)

    # Get JSON string
    json_str = format_json(result)

    # Get SARIF string
    sarif_str = format_sarif(result)
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule as RichRule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich import box

from vulndiff.models import Finding, Severity, ScanResult
from vulndiff import __version__


# ---------------------------------------------------------------------------
# Severity colour mapping for rich output
# ---------------------------------------------------------------------------

_SEVERITY_STYLES: Dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

_SEVERITY_ICONS: Dict[str, str] = {
    "critical": "\u2716",  # ✖
    "high": "\u25cf",      # ●
    "medium": "\u25b2",    # ▲
    "low": "\u25cb",       # ○
    "info": "\u2139",      # ℹ
}


# ---------------------------------------------------------------------------
# SARIF constants
# ---------------------------------------------------------------------------

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
_SARIF_SEVERITY_MAP: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


# ---------------------------------------------------------------------------
# Rich / terminal report
# ---------------------------------------------------------------------------


def format_rich(
    result: ScanResult,
    no_color: bool = False,
) -> str:
    """Render a scan result as a rich-formatted string.

    The string contains ANSI escape codes suitable for display in a terminal.
    To strip colours (e.g. for piping), pass ``no_color=True``.

    Args:
        result:   The :class:`~vulndiff.models.ScanResult` to format.
        no_color: When ``True``, ANSI colour codes are omitted.

    Returns:
        A multi-line string containing the formatted report.
    """
    console = Console(
        record=True,
        no_color=no_color,
        highlight=False,
    )
    _render_to_console(result, console)
    return console.export_text(styles=not no_color)


def print_rich(
    result: ScanResult,
    no_color: bool = False,
    file: Any = None,
) -> None:
    """Print a rich-formatted scan report directly to the terminal.

    Args:
        result:   The :class:`~vulndiff.models.ScanResult` to display.
        no_color: When ``True``, ANSI colour codes are omitted.
        file:     Output stream.  Defaults to ``sys.stdout`` when ``None``.
    """
    if file is None:
        file = sys.stdout
    console = Console(
        no_color=no_color,
        highlight=False,
        file=file,
    )
    _render_to_console(result, console)


def _render_to_console(result: ScanResult, console: Console) -> None:
    """Write the full scan report to *console*.

    Args:
        result:  The :class:`~vulndiff.models.ScanResult` to render.
        console: The :class:`rich.console.Console` to write to.
    """
    # ---- Header -----------------------------------------------------------
    console.print()
    console.print(
        RichRule(
            Text(f" vulndiff v{__version__} ", style="bold white"),
            style="bright_blue",
        )
    )
    console.print()

    # ---- Scan info --------------------------------------------------------
    _print_scan_info(result, console)

    if not result.has_findings:
        console.print()
        console.print(
            "  [bold green]\u2714 No findings.[/bold green]  "
            "The diff looks clean at the configured severity threshold."
        )
        console.print()
        _print_summary_table(result, console)
        return

    # ---- Findings ---------------------------------------------------------
    console.print()
    for finding in result.findings:
        _print_finding(finding, console)

    # ---- Summary ----------------------------------------------------------
    console.print()
    _print_summary_table(result, console)
    console.print()


def _print_scan_info(result: ScanResult, console: Console) -> None:
    """Print the scan parameters (mode, refs, severity filter)."""
    parts = [f"  [dim]mode:[/dim] [bold]{result.input_mode}[/bold]"]
    if result.from_ref:
        parts.append(f"  [dim]from:[/dim] [bold]{result.from_ref}[/bold]")
    if result.to_ref:
        parts.append(f"  [dim]to:[/dim] [bold]{result.to_ref}[/bold]")
    parts.append(
        f"  [dim]severity filter:[/dim] [bold]{result.severity_filter.value}[/bold]"
    )
    parts.append(
        f"  [dim]rules:[/dim] [bold]{result.rules_applied}[/bold]"
    )
    console.print("  ".join(parts))


def _print_finding(finding: Finding, console: Console) -> None:
    """Print a single finding as a rich panel."""
    sev = finding.severity.value
    style = _SEVERITY_STYLES.get(sev, "white")
    icon = _SEVERITY_ICONS.get(sev, "•")

    # Title line: icon + rule name + severity badge
    title = Text()
    title.append(f"{icon} ", style=style)
    title.append(f"[{sev.upper()}] ", style=style)
    title.append(finding.rule.name, style="bold")
    title.append(f"  ({finding.rule.rule_id})", style="dim")

    # Location
    location_text = Text()
    location_text.append("  File: ", style="dim")
    location_text.append(finding.file_path, style="bold cyan")
    location_text.append(f"  line {finding.line_number}", style="cyan")

    # Matched line (syntax-highlighted where possible)
    lang = _guess_language(finding.file_path)
    snippet_text = _make_snippet(finding, lang)

    # Description + recommendation
    desc_text = Text()
    desc_text.append("  Description: ", style="dim")
    desc_text.append(finding.rule.description.strip())

    rec_text = Text()
    rec_text.append("  Remediation:  ", style="dim")
    rec_text.append(finding.rule.recommendation.strip(), style="green")

    # Optional metadata
    meta_parts: List[str] = []
    if finding.rule.cwe_id:
        meta_parts.append(f"CWE: {finding.rule.cwe_id}")
    if finding.rule.owasp_id:
        meta_parts.append(f"OWASP: {finding.rule.owasp_id}")
    meta_line = "  [dim]" + "   ".join(meta_parts) + "[/dim]" if meta_parts else ""

    # Assemble panel content
    content = Text.assemble(
        location_text,
        "\n",
    )

    panel_border = style
    console.print(
        Panel(
            _build_finding_renderables(location_text, snippet_text, desc_text, rec_text, meta_line),
            title=title,
            title_align="left",
            border_style=panel_border,
            padding=(0, 1),
        )
    )


def _build_finding_renderables(
    location_text: Text,
    snippet_text: Any,
    desc_text: Text,
    rec_text: Text,
    meta_line: str,
) -> Any:
    """Assemble a renderable group for a finding panel."""
    from rich.console import Group

    items: list = [
        location_text,
        snippet_text,
        Text(""),
        desc_text,
        rec_text,
    ]
    if meta_line:
        items.append(Text(""))
        items.append(Text.from_markup(meta_line))
    return Group(*items)


def _make_snippet(finding: Finding, lang: str) -> Any:
    """Return a rich Syntax object for the matched line."""
    line_content = finding.line_content
    # Show a simple code block with the matched line
    code = f"  {finding.line_number:>6} | {line_content}"
    try:
        return Syntax(
            code,
            lang,
            theme="monokai",
            line_numbers=False,
            word_wrap=True,
        )
    except Exception:
        return Text(code, style="bold white on dark_red")


def _guess_language(file_path: str) -> str:
    """Guess the programming language from a file extension.

    Args:
        file_path: Repository-relative file path.

    Returns:
        A language identifier string understood by ``rich.syntax.Syntax``.
    """
    ext_map: Dict[str, str] = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".tsx": "tsx",
        ".jsx": "jsx",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".php": "php",
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".cs": "csharp",
        ".rs": "rust",
        ".sh": "bash",
        ".bash": "bash",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".toml": "toml",
        ".tf": "hcl",
        ".html": "html",
        ".xml": "xml",
        ".sql": "sql",
    }
    lower = file_path.lower()
    for ext, lang in ext_map.items():
        if lower.endswith(ext):
            return lang
    return "text"


def _print_summary_table(result: ScanResult, console: Console) -> None:
    """Print a summary table of finding counts by severity."""
    summary = result.severity_summary()
    total = result.finding_count

    table = Table(
        title="Scan Summary",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold bright_blue",
        title_style="bold",
        padding=(0, 1),
    )
    table.add_column("Severity", style="bold", min_width=10)
    table.add_column("Count", justify="right", min_width=6)

    for sev_value in ["critical", "high", "medium", "low", "info"]:
        count = summary.get(sev_value, 0)
        style = _SEVERITY_STYLES.get(sev_value, "white") if count > 0 else "dim"
        icon = _SEVERITY_ICONS.get(sev_value, "")
        table.add_row(
            Text(f"{icon}  {sev_value.capitalize()}", style=style),
            Text(str(count), style=style if count > 0 else "dim"),
        )

    table.add_section()
    total_style = "bold red" if total > 0 else "bold green"
    table.add_row(
        Text("Total", style="bold"),
        Text(str(total), style=total_style),
    )

    # Stats row
    stats_table = Table(
        box=box.SIMPLE,
        show_header=False,
        padding=(0, 2),
    )
    stats_table.add_column("Key", style="dim")
    stats_table.add_column("Value", style="bold")
    stats_table.add_row("Files scanned", str(len(result.scanned_files)))
    stats_table.add_row("Hunks scanned", str(result.scanned_hunks))
    stats_table.add_row("Lines scanned", str(result.scanned_lines))
    stats_table.add_row("Rules applied", str(result.rules_applied))

    from rich.columns import Columns
    console.print(Columns([table, stats_table], equal=False, expand=False))


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


def format_json(result: ScanResult, indent: int = 2) -> str:
    """Serialize a scan result to a JSON string.

    The output schema mirrors :meth:`~vulndiff.models.ScanResult.to_dict`:
    a top-level object with ``summary``, ``scan_info``, and ``findings`` keys.

    Args:
        result: The :class:`~vulndiff.models.ScanResult` to serialise.
        indent: JSON indentation level.  Defaults to ``2``.

    Returns:
        A pretty-printed JSON string.
    """
    data = result.to_dict()
    # Add tool metadata
    data["tool"] = {
        "name": "vulndiff",
        "version": __version__,
    }
    return json.dumps(data, indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# SARIF output
# ---------------------------------------------------------------------------


def format_sarif(result: ScanResult) -> str:
    """Serialize a scan result to a SARIF 2.1.0 JSON string.

    The produced SARIF document conforms to the SARIF 2.1.0 specification
    and can be uploaded to GitHub Advanced Security via the
    ``github/codeql-action/upload-sarif`` action.

    Args:
        result: The :class:`~vulndiff.models.ScanResult` to serialise.

    Returns:
        A JSON string in SARIF 2.1.0 format.
    """
    sarif: Dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": _build_sarif_tool(result),
                "results": _build_sarif_results(result),
                "artifacts": _build_sarif_artifacts(result),
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [],
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _build_sarif_tool(result: ScanResult) -> Dict[str, Any]:
    """Build the SARIF ``tool`` object."""
    # Collect all unique rules referenced by findings (or all rules applied)
    rules_seen: Dict[str, Any] = {}
    for finding in result.findings:
        rule = finding.rule
        if rule.rule_id not in rules_seen:
            rule_entry: Dict[str, Any] = {
                "id": rule.rule_id,
                "name": rule.name,
                "shortDescription": {"text": rule.name},
                "fullDescription": {"text": rule.description},
                "help": {"text": rule.recommendation},
                "defaultConfiguration": {
                    "level": _SARIF_SEVERITY_MAP.get(rule.severity.value, "warning")
                },
                "properties": {
                    "tags": rule.tags,
                    "category": rule.category.value,
                },
            }
            if rule.cwe_id:
                rule_entry["properties"]["cwe"] = rule.cwe_id
            if rule.owasp_id:
                rule_entry["properties"]["owasp"] = rule.owasp_id
            if rule.references:
                rule_entry["helpUri"] = rule.references[0]
            rules_seen[rule.rule_id] = rule_entry

    return {
        "driver": {
            "name": "vulndiff",
            "version": __version__,
            "informationUri": "https://github.com/example/vulndiff",
            "semanticVersion": __version__,
            "rules": list(rules_seen.values()),
        }
    }


def _build_sarif_results(result: ScanResult) -> List[Dict[str, Any]]:
    """Build the SARIF ``results`` array."""
    sarif_results: List[Dict[str, Any]] = []
    for finding in result.findings:
        level = _SARIF_SEVERITY_MAP.get(finding.severity.value, "warning")
        sarif_result: Dict[str, Any] = {
            "ruleId": finding.rule.rule_id,
            "level": level,
            "message": {
                "text": (
                    f"{finding.rule.description}\n\n"
                    f"Recommendation: {finding.rule.recommendation}"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line_number,
                            "startColumn": 1,
                            "snippet": {"text": finding.line_content},
                        },
                    }
                }
            ],
            "fingerprints": {
                "vulndiff/v1": _make_fingerprint(finding),
            },
            "properties": {
                "severity": finding.severity.value,
                "category": finding.category.value,
                "matchText": finding.match_text,
            },
        }
        if finding.rule.cwe_id:
            sarif_result["taxa"] = [
                {
                    "toolComponent": {"name": "CWE"},
                    "id": finding.rule.cwe_id,
                }
            ]
        sarif_results.append(sarif_result)
    return sarif_results


def _build_sarif_artifacts(result: ScanResult) -> List[Dict[str, Any]]:
    """Build the SARIF ``artifacts`` array from scanned file paths."""
    return [
        {
            "location": {
                "uri": file_path,
                "uriBaseId": "%SRCROOT%",
            }
        }
        for file_path in result.scanned_files
    ]


def _make_fingerprint(finding: Finding) -> str:
    """Create a stable fingerprint string for a finding.

    The fingerprint is used by SARIF-aware tools to deduplicate findings
    across runs.  It is derived from the rule ID, file path, and line number.

    Args:
        finding: The :class:`~vulndiff.models.Finding` to fingerprint.

    Returns:
        A hex string fingerprint.
    """
    import hashlib

    raw = f"{finding.rule.rule_id}:{finding.file_path}:{finding.line_number}:{finding.line_content}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Dispatch helper
# ---------------------------------------------------------------------------


def format_report(result: ScanResult, fmt: str = "rich", no_color: bool = False) -> str:
    """Format a scan result in the requested output format.

    This is the primary dispatch function used by the CLI.

    Args:
        result:   The :class:`~vulndiff.models.ScanResult` to format.
        fmt:      Output format.  One of ``"rich"``, ``"json"``, ``"sarif"``.
        no_color: When ``True`` and *fmt* is ``"rich"``, strip ANSI codes.

    Returns:
        A formatted string representation of the scan result.

    Raises:
        ValueError: If *fmt* is not one of the recognised format names.
    """
    if fmt == "rich":
        return format_rich(result, no_color=no_color)
    elif fmt == "json":
        return format_json(result)
    elif fmt == "sarif":
        return format_sarif(result)
    else:
        raise ValueError(
            f"Unknown format {fmt!r}. Expected one of: 'rich', 'json', 'sarif'."
        )
