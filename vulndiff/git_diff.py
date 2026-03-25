"""Git diff extraction for vulndiff.

This module provides functions to extract added lines and their file context
from git diff output.  Three input modes are supported:

- **staged** (``git diff --cached``) — for pre-commit hook usage.
- **head** (``git diff HEAD~1 HEAD``) — for scanning the most recent commit.
- **ref-range** (``git diff <from_ref> <to_ref>``) — for CI pipelines comparing
  branches or arbitrary commit ranges.

The public API produces :class:`~vulndiff.models.DiffHunk` objects that contain
only the *added* lines from the diff together with their file path and 1-based
line numbers in the new file.  Deleted lines, context lines, and binary-file
markers are intentionally excluded.

Example usage::

    from vulndiff.git_diff import get_staged_hunks, get_hunks_for_ref_range

    # Scan staged changes
    hunks = get_staged_hunks()

    # Scan a PR range
    hunks = get_hunks_for_ref_range("main", "feature/my-branch")

    for hunk in hunks:
        print(hunk.file_path, hunk.start_line, hunk.line_count)
"""

from __future__ import annotations

import subprocess
from typing import List, Optional, Tuple

from vulndiff.models import DiffHunk


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class GitError(RuntimeError):
    """Raised when a git subprocess command fails or git is not available.

    Attributes:
        message:   Human-readable error description.
        returncode: The process return code, or ``None`` if git was not found.
        stderr:    Captured stderr output from the git process.
    """

    def __init__(
        self,
        message: str,
        returncode: Optional[int] = None,
        stderr: str = "",
    ) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


class NotAGitRepositoryError(GitError):
    """Raised when the current working directory is not inside a git repository."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run_git(args: List[str], cwd: Optional[str] = None) -> str:
    """Execute a git command and return its stdout as a string.

    Args:
        args: List of git arguments, e.g. ``["diff", "--cached"]``.
              The ``"git"`` executable is prepended automatically.
        cwd:  Working directory for the subprocess.  Defaults to the
              current process directory when ``None``.

    Returns:
        The captured stdout of the git process decoded as UTF-8
        (with ``errors='replace'`` so malformed bytes do not raise).

    Raises:
        GitError: If git returns a non-zero exit code.
        GitError: If the ``git`` executable is not found on ``PATH``.
        NotAGitRepositoryError: If git reports that the directory is not
            inside a git repository (exit code 128).
    """
    cmd = ["git"] + args
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,  # We handle non-zero exit codes manually
        )
    except FileNotFoundError as exc:
        raise GitError(
            "git executable not found on PATH. Please install git."
        ) from exc

    stderr_text = result.stderr.decode("utf-8", errors="replace").strip()
    stdout_text = result.stdout.decode("utf-8", errors="replace")

    if result.returncode != 0:
        # Exit code 128 typically means "not a git repository"
        if result.returncode == 128 or "not a git repository" in stderr_text.lower():
            raise NotAGitRepositoryError(
                "The current directory is not inside a git repository.",
                returncode=result.returncode,
                stderr=stderr_text,
            )
        raise GitError(
            f"git command failed (exit {result.returncode}): {' '.join(cmd)}\n"
            f"stderr: {stderr_text}",
            returncode=result.returncode,
            stderr=stderr_text,
        )

    return stdout_text


def _parse_unified_diff(diff_text: str) -> List[DiffHunk]:
    """Parse unified diff text and extract added-line hunks.

    Processes the raw output of ``git diff`` (unified format) and produces
    one :class:`~vulndiff.models.DiffHunk` per ``@@`` hunk section.  Only
    lines beginning with ``+`` (but not ``+++``) are included in each hunk.

    The parser is deliberately conservative: it silently skips malformed
    hunk headers rather than raising, so that a single corrupt hunk does
    not abort an entire scan.

    Args:
        diff_text: The raw unified diff string (e.g. from ``git diff --cached``).

    Returns:
        A list of :class:`~vulndiff.models.DiffHunk` objects, one per ``@@``
        section that contains at least one added line.  Hunks with no added
        lines are excluded.
    """
    hunks: List[DiffHunk] = []

    # Current state
    current_file: str = ""
    current_hunk: Optional[DiffHunk] = None
    # Line number in the new file (right-hand side of the diff)
    current_new_line: int = 1

    for raw_line in diff_text.splitlines():
        # --- File header: "diff --git a/foo b/foo" or "--- a/foo" / "+++ b/foo" ---
        if raw_line.startswith("diff --git "):
            # Commit the previous hunk before switching files
            if current_hunk is not None and not current_hunk.is_empty():
                hunks.append(current_hunk)
            current_hunk = None
            # Extract file path: "diff --git a/foo b/foo" -> "foo"
            # The b/ prefix gives the new-file path.
            parts = raw_line.split(" b/", 1)
            if len(parts) == 2:
                current_file = parts[1].strip()
            else:
                current_file = ""
            continue

        # Skip the "--- a/..." line (old file header)
        if raw_line.startswith("--- "):
            continue

        # The "+++ b/..." line confirms the new file path (handles renames)
        if raw_line.startswith("+++ "):
            # Extract path after "+++ b/" or "+++ " (for /dev/null etc.)
            path_part = raw_line[4:]
            if path_part.startswith("b/"):
                current_file = path_part[2:].strip()
            elif path_part.strip() == "/dev/null":
                # Deleted file — no added lines possible
                current_file = ""
            # else: keep whatever we already have
            continue

        # --- Hunk header: "@@ -a,b +c,d @@ optional function context" ---
        if raw_line.startswith("@@"):
            # Commit the previous hunk
            if current_hunk is not None and not current_hunk.is_empty():
                hunks.append(current_hunk)
            current_hunk = None

            if not current_file:
                continue

            new_start, _ = _parse_hunk_header(raw_line)
            if new_start is None:
                # Malformed hunk header — skip
                continue

            current_new_line = new_start
            current_hunk = DiffHunk(
                file_path=current_file,
                start_line=new_start,
                added_lines=[],
                hunk_header=raw_line,
            )
            continue

        # --- Diff content lines ---
        if current_hunk is None:
            # We are between hunks (e.g. binary file notice, index lines)
            continue

        if raw_line.startswith("+"):
            # Added line — strip the leading '+'
            line_content = raw_line[1:]
            current_hunk.added_lines.append((current_new_line, line_content))
            current_new_line += 1

        elif raw_line.startswith("-"):
            # Deleted line — does not advance the new-file line counter
            pass

        elif raw_line.startswith("\\"):
            # "No newline at end of file" marker — ignore
            pass

        else:
            # Context line — advances the new-file line counter
            current_new_line += 1

    # Commit the final hunk
    if current_hunk is not None and not current_hunk.is_empty():
        hunks.append(current_hunk)

    return hunks


def _parse_hunk_header(header: str) -> Tuple[Optional[int], Optional[int]]:
    """Extract the new-file start line and line count from a hunk header.

    Unified diff hunk headers have the form::

        @@ -<old_start>[,<old_count>] +<new_start>[,<new_count>] @@ [context]

    Args:
        header: The raw hunk header line, e.g. ``"@@ -10,5 +12,8 @@ def foo():"``.

    Returns:
        A tuple ``(new_start, new_count)`` where both values are integers.
        If ``new_count`` is omitted in the header (implying 1), it is returned
        as ``1``.  Returns ``(None, None)`` if the header cannot be parsed.
    """
    # Find the "+..." part between the @@ markers
    try:
        # The header always starts with "@@" — find the second "@@"
        at_start = header.index("+", header.index("@@"))
        at_end = header.index(" ", at_start)
        new_part = header[at_start + 1 : at_end]  # e.g. "12,8" or "12"

        if "," in new_part:
            start_str, count_str = new_part.split(",", 1)
            new_start = int(start_str)
            new_count = int(count_str)
        else:
            new_start = int(new_part)
            new_count = 1

        # A hunk that adds zero lines (new_count == 0) is a pure-deletion hunk;
        # treat start as 1 to avoid DiffHunk validation error, but the hunk
        # will be empty anyway so it is discarded.
        if new_start < 1:
            new_start = 1

        return new_start, new_count

    except (ValueError, IndexError):
        return None, None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_staged_hunks(cwd: Optional[str] = None) -> List[DiffHunk]:
    """Return diff hunks for all currently staged changes.

    Runs ``git diff --cached --unified=0`` and parses the output.
    This is the mode used when vulndiff is invoked as a pre-commit hook.

    Args:
        cwd: Working directory to run git in.  Defaults to the current
             process directory when ``None``.

    Returns:
        A list of :class:`~vulndiff.models.DiffHunk` objects, one per
        ``@@`` section that contains at least one added line.

    Raises:
        GitError: If git fails or is not available.
        NotAGitRepositoryError: If not inside a git repository.
    """
    diff_text = _run_git(
        ["diff", "--cached", "--unified=0", "--diff-filter=ACM"],
        cwd=cwd,
    )
    return _parse_unified_diff(diff_text)


def get_head_hunks(cwd: Optional[str] = None) -> List[DiffHunk]:
    """Return diff hunks for changes introduced by the most recent commit.

    Runs ``git diff HEAD~1 HEAD --unified=0`` so the scan covers exactly
    what the last commit added.

    Args:
        cwd: Working directory to run git in.  Defaults to the current
             process directory when ``None``.

    Returns:
        A list of :class:`~vulndiff.models.DiffHunk` objects.

    Raises:
        GitError: If git fails, is not available, or there is no previous
            commit (initial commit with no parent).
        NotAGitRepositoryError: If not inside a git repository.
    """
    # For repositories with only one commit HEAD~1 may not exist; fall back
    # gracefully by comparing the empty tree to HEAD.
    try:
        diff_text = _run_git(
            ["diff", "HEAD~1", "HEAD", "--unified=0", "--diff-filter=ACM"],
            cwd=cwd,
        )
    except GitError as exc:
        # "unknown revision" or "ambiguous argument" means HEAD~1 doesn't exist
        if exc.returncode in (128, 129) or "unknown revision" in str(exc).lower():
            diff_text = _run_git(
                [
                    "diff",
                    "--unified=0",
                    "--diff-filter=ACM",
                    _empty_tree_sha(cwd),
                    "HEAD",
                ],
                cwd=cwd,
            )
        else:
            raise
    return _parse_unified_diff(diff_text)


def get_hunks_for_ref_range(
    from_ref: str,
    to_ref: str = "HEAD",
    cwd: Optional[str] = None,
) -> List[DiffHunk]:
    """Return diff hunks for an arbitrary git ref range.

    Runs ``git diff <from_ref> <to_ref> --unified=0`` so the caller can
    compare any two refs — branches, tags, commit SHAs, etc.

    Args:
        from_ref: The start of the comparison range (e.g. ``"main"`` or a
                  commit SHA).  Lines that exist in this ref but not in
                  *to_ref* are treated as deleted and ignored.
        to_ref:   The end of the comparison range.  Defaults to ``"HEAD"``.
        cwd:      Working directory to run git in.  Defaults to the current
                  process directory when ``None``.

    Returns:
        A list of :class:`~vulndiff.models.DiffHunk` objects for lines
        added between *from_ref* and *to_ref*.

    Raises:
        ValueError: If *from_ref* is an empty string.
        GitError: If git fails or is not available.
        NotAGitRepositoryError: If not inside a git repository.
    """
    if not from_ref or not from_ref.strip():
        raise ValueError("from_ref must not be empty.")
    if not to_ref or not to_ref.strip():
        raise ValueError("to_ref must not be empty.")

    diff_text = _run_git(
        ["diff", from_ref, to_ref, "--unified=0", "--diff-filter=ACM"],
        cwd=cwd,
    )
    return _parse_unified_diff(diff_text)


def parse_diff_text(diff_text: str) -> List[DiffHunk]:
    """Parse a raw unified diff string and return extracted added-line hunks.

    This function is the pure-parsing counterpart to the subprocess-based
    ``get_*`` functions.  It is primarily intended for testing and for
    scenarios where the diff is already available as a string (e.g. piped
    from CI tooling).

    Args:
        diff_text: A unified diff string in the format produced by
                   ``git diff --unified=0``.

    Returns:
        A list of :class:`~vulndiff.models.DiffHunk` objects, one per
        ``@@`` section that contains at least one added line.
    """
    return _parse_unified_diff(diff_text)


def get_diff_files(
    mode: str = "staged",
    from_ref: Optional[str] = None,
    to_ref: str = "HEAD",
    cwd: Optional[str] = None,
) -> List[str]:
    """Return a deduplicated list of file paths present in the diff.

    This is a convenience wrapper that dispatches to the appropriate
    ``get_*_hunks`` function and collects unique file paths.

    Args:
        mode:     One of ``"staged"``, ``"head"``, or ``"ref-range"``.
        from_ref: Required when *mode* is ``"ref-range"``.
        to_ref:   Used when *mode* is ``"ref-range"`` (default ``"HEAD"``).
        cwd:      Working directory for git.

    Returns:
        A sorted list of unique repository-relative file paths.

    Raises:
        ValueError: If *mode* is unrecognised or *from_ref* is missing for
            ``"ref-range"`` mode.
        GitError: If git fails.
    """
    hunks = get_hunks(
        mode=mode,
        from_ref=from_ref,
        to_ref=to_ref,
        cwd=cwd,
    )
    return sorted({h.file_path for h in hunks})


def get_hunks(
    mode: str = "staged",
    from_ref: Optional[str] = None,
    to_ref: str = "HEAD",
    cwd: Optional[str] = None,
) -> List[DiffHunk]:
    """Dispatch to the appropriate hunk-extraction function based on *mode*.

    This is the primary entry point used by the CLI and scanner to obtain
    diff hunks without knowing the specific input mode at call time.

    Args:
        mode:     Scanning mode.  Must be one of:

                  - ``"staged"`` — scan staged changes (``git diff --cached``).
                  - ``"head"``   — scan the most recent commit (``HEAD~1..HEAD``).
                  - ``"ref-range"`` — scan an arbitrary ref range.

        from_ref: Start ref for ``"ref-range"`` mode.  Ignored for other modes.
        to_ref:   End ref for ``"ref-range"`` mode (default ``"HEAD"``).
        cwd:      Working directory for git subprocesses.

    Returns:
        A list of :class:`~vulndiff.models.DiffHunk` objects.

    Raises:
        ValueError: If *mode* is not one of the recognised values, or if
            *from_ref* is ``None`` / empty for ``"ref-range"`` mode.
        GitError: If the git command fails.
        NotAGitRepositoryError: If the directory is not a git repository.
    """
    if mode == "staged":
        return get_staged_hunks(cwd=cwd)
    elif mode == "head":
        return get_head_hunks(cwd=cwd)
    elif mode == "ref-range":
        if not from_ref:
            raise ValueError(
                "from_ref must be provided when mode is 'ref-range'."
            )
        return get_hunks_for_ref_range(
            from_ref=from_ref, to_ref=to_ref, cwd=cwd
        )
    else:
        raise ValueError(
            f"Unknown mode {mode!r}. Expected one of: 'staged', 'head', 'ref-range'."
        )


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------


def _empty_tree_sha(cwd: Optional[str] = None) -> str:
    """Return the SHA of git's empty tree object.

    The empty tree is a special git object that acts as the parent of the
    very first commit (which has no real parent).  Using it in a diff
    command produces a diff showing all files in the commit as newly added.

    Args:
        cwd: Working directory for the git subprocess.

    Returns:
        The 40-character SHA-1 hex string of the empty tree.

    Raises:
        GitError: If the git command fails.
    """
    sha = _run_git(
        ["hash-object", "-t", "tree", "/dev/null"],
        cwd=cwd,
    ).strip()
    if not sha:
        # Fallback: this SHA is constant across all git installations
        return "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    return sha
