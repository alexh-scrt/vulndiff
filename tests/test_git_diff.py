"""Unit tests for vulndiff.git_diff.

Covers diff parsing logic for multi-file, multi-hunk, and edge-case
unified diffs without requiring a live git repository.  Subprocess-based
functions are tested via monkeypatching.
"""

from __future__ import annotations

from typing import List
from unittest.mock import MagicMock, patch

import pytest

from vulndiff.git_diff import (
    GitError,
    NotAGitRepositoryError,
    _parse_hunk_header,
    _run_git,
    get_hunks,
    get_staged_hunks,
    get_head_hunks,
    get_hunks_for_ref_range,
    parse_diff_text,
    get_diff_files,
)
from vulndiff.models import DiffHunk


# ---------------------------------------------------------------------------
# Fixtures / sample diffs
# ---------------------------------------------------------------------------

SIMPLE_DIFF = """\
diff --git a/app/views.py b/app/views.py
index abc1234..def5678 100644
--- a/app/views.py
+++ b/app/views.py
@@ -10,3 +10,5 @@
 context_line_1
+added_line_1
+added_line_2
 context_line_2
-removed_line
+added_line_3
"""

MULTI_HUNK_DIFF = """\
diff --git a/app/models.py b/app/models.py
index 0000001..0000002 100644
--- a/app/models.py
+++ b/app/models.py
@@ -5,2 +5,3 @@
 context
+hunk1_added_1
+hunk1_added_2
@@ -20,1 +21,2 @@
 context2
+hunk2_added_1
"""

MULTI_FILE_DIFF = """\
diff --git a/foo.py b/foo.py
index 1111111..2222222 100644
--- a/foo.py
+++ b/foo.py
@@ -1,1 +1,2 @@
 original
+foo_added
diff --git a/bar.py b/bar.py
index 3333333..4444444 100644
--- a/bar.py
+++ b/bar.py
@@ -1,1 +1,2 @@
 original
+bar_added
"""

PURE_DELETION_DIFF = """\
diff --git a/old.py b/old.py
index 1111111..2222222 100644
--- a/old.py
+++ b/old.py
@@ -1,3 +1,0 @@
-deleted_1
-deleted_2
-deleted_3
"""

NO_NEWLINE_DIFF = """\
diff --git a/noeol.py b/noeol.py
index 1111111..2222222 100644
--- a/noeol.py
+++ b/noeol.py
@@ -1,1 +1,2 @@
 original
+new_line
\\ No newline at end of file
"""

EMPTY_DIFF = ""

RENAME_DIFF = """\
diff --git a/old_name.py b/new_name.py
similarity index 90%
rename from old_name.py
rename to new_name.py
index 1111111..2222222 100644
--- a/old_name.py
+++ b/new_name.py
@@ -1,1 +1,2 @@
 original
+renamed_added
"""

NEW_FILE_DIFF = """\
diff --git a/brand_new.py b/brand_new.py
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/brand_new.py
@@ -0,0 +1,3 @@
+line_one
+line_two
+line_three
"""

SINGLE_LINE_HUNK = """\
diff --git a/single.py b/single.py
index 0000001..0000002 100644
--- a/single.py
+++ b/single.py
@@ -5 +5 @@
 context
-old
+new
"""


# ---------------------------------------------------------------------------
# Tests for _parse_hunk_header
# ---------------------------------------------------------------------------


class TestParseHunkHeader:
    """Unit tests for the _parse_hunk_header internal function."""

    def test_standard_header(self) -> None:
        """Should parse a standard '@@ -a,b +c,d @@' header."""
        start, count = _parse_hunk_header("@@ -10,5 +12,8 @@")
        assert start == 12
        assert count == 8

    def test_header_with_function_context(self) -> None:
        """Should parse header with trailing function name context."""
        start, count = _parse_hunk_header("@@ -1,3 +1,5 @@ def foo():")
        assert start == 1
        assert count == 5

    def test_header_no_count(self) -> None:
        """A header without a count after '+' should default count to 1."""
        start, count = _parse_hunk_header("@@ -5 +5 @@")
        assert start == 5
        assert count == 1

    def test_new_file_header(self) -> None:
        """'@@ -0,0 +1,3 @@' is a new-file hunk header."""
        start, count = _parse_hunk_header("@@ -0,0 +1,3 @@")
        assert start == 1
        assert count == 3

    def test_malformed_header_returns_none(self) -> None:
        """A malformed header should return (None, None) without raising."""
        start, count = _parse_hunk_header("not a hunk header at all")
        assert start is None
        assert count is None

    def test_empty_string_returns_none(self) -> None:
        """An empty string should return (None, None)."""
        start, count = _parse_hunk_header("")
        assert start is None
        assert count is None

    def test_zero_new_start_clamped_to_one(self) -> None:
        """A new-file start of 0 (deletion-only hunk) should be clamped to 1."""
        start, count = _parse_hunk_header("@@ -1,3 +0,0 @@")
        # new_start=0 is clamped to 1
        assert start == 1


# ---------------------------------------------------------------------------
# Tests for parse_diff_text (pure parser)
# ---------------------------------------------------------------------------


class TestParseDiffText:
    """Tests for the pure parse_diff_text() function."""

    def test_empty_diff_returns_empty_list(self) -> None:
        """An empty diff string should return an empty list."""
        hunks = parse_diff_text(EMPTY_DIFF)
        assert hunks == []

    def test_simple_diff_one_hunk(self) -> None:
        """A diff with one hunk should return exactly one DiffHunk."""
        hunks = parse_diff_text(SIMPLE_DIFF)
        assert len(hunks) == 1

    def test_simple_diff_file_path(self) -> None:
        """The DiffHunk should have the correct file path."""
        hunks = parse_diff_text(SIMPLE_DIFF)
        assert hunks[0].file_path == "app/views.py"

    def test_simple_diff_added_line_count(self) -> None:
        """Only added lines (starting with '+') should be in added_lines."""
        hunks = parse_diff_text(SIMPLE_DIFF)
        # SIMPLE_DIFF has 3 added lines: added_line_1, added_line_2, added_line_3
        assert hunks[0].line_count == 3

    def test_simple_diff_added_line_contents(self) -> None:
        """Line contents should not include the leading '+' character."""
        hunks = parse_diff_text(SIMPLE_DIFF)
        contents = [line for _, line in hunks[0].added_lines]
        assert "added_line_1" in contents
        assert "added_line_2" in contents
        assert "added_line_3" in contents

    def test_simple_diff_line_numbers(self) -> None:
        """Line numbers should reflect position in the new file."""
        hunks = parse_diff_text(SIMPLE_DIFF)
        line_numbers = [ln for ln, _ in hunks[0].added_lines]
        # Hunk starts at new-file line 10
        # Line 10: context_line_1 (no +), so first added is line 11
        assert line_numbers[0] == 11

    def test_pure_deletion_diff_returns_empty(self) -> None:
        """A diff with only deletions should return no hunks."""
        hunks = parse_diff_text(PURE_DELETION_DIFF)
        assert hunks == []

    def test_multi_hunk_diff_returns_two_hunks(self) -> None:
        """A diff with two @@ sections should return two DiffHunks."""
        hunks = parse_diff_text(MULTI_HUNK_DIFF)
        assert len(hunks) == 2

    def test_multi_hunk_diff_first_hunk_lines(self) -> None:
        """First hunk should contain its added lines."""
        hunks = parse_diff_text(MULTI_HUNK_DIFF)
        contents = [line for _, line in hunks[0].added_lines]
        assert "hunk1_added_1" in contents
        assert "hunk1_added_2" in contents

    def test_multi_hunk_diff_second_hunk_lines(self) -> None:
        """Second hunk should contain its added lines."""
        hunks = parse_diff_text(MULTI_HUNK_DIFF)
        contents = [line for _, line in hunks[1].added_lines]
        assert "hunk2_added_1" in contents

    def test_multi_hunk_diff_same_file(self) -> None:
        """Both hunks should reference the same file."""
        hunks = parse_diff_text(MULTI_HUNK_DIFF)
        assert all(h.file_path == "app/models.py" for h in hunks)

    def test_multi_file_diff_two_files(self) -> None:
        """A diff covering two files should produce hunks for each."""
        hunks = parse_diff_text(MULTI_FILE_DIFF)
        assert len(hunks) == 2

    def test_multi_file_diff_file_paths(self) -> None:
        """Each hunk should reference its corresponding file."""
        hunks = parse_diff_text(MULTI_FILE_DIFF)
        paths = {h.file_path for h in hunks}
        assert "foo.py" in paths
        assert "bar.py" in paths

    def test_multi_file_diff_line_contents(self) -> None:
        """Each file's hunk should contain the correct added lines."""
        hunks = parse_diff_text(MULTI_FILE_DIFF)
        by_file = {h.file_path: h for h in hunks}
        foo_lines = [line for _, line in by_file["foo.py"].added_lines]
        bar_lines = [line for _, line in by_file["bar.py"].added_lines]
        assert "foo_added" in foo_lines
        assert "bar_added" in bar_lines

    def test_no_newline_marker_ignored(self) -> None:
        """'No newline at end of file' markers should be silently ignored."""
        hunks = parse_diff_text(NO_NEWLINE_DIFF)
        assert len(hunks) == 1
        contents = [line for _, line in hunks[0].added_lines]
        assert "new_line" in contents
        # The backslash marker should NOT appear as a line
        assert any(line.startswith("\\") for line in contents) is False

    def test_rename_diff_uses_new_name(self) -> None:
        """A rename diff should use the new file name for the hunk."""
        hunks = parse_diff_text(RENAME_DIFF)
        assert len(hunks) == 1
        assert hunks[0].file_path == "new_name.py"

    def test_new_file_diff_line_numbers_start_at_one(self) -> None:
        """A new-file diff starting at +1 should have line numbers from 1."""
        hunks = parse_diff_text(NEW_FILE_DIFF)
        assert len(hunks) == 1
        line_numbers = [ln for ln, _ in hunks[0].added_lines]
        assert line_numbers == [1, 2, 3]

    def test_new_file_diff_all_lines_captured(self) -> None:
        """All three added lines of a new-file diff should be captured."""
        hunks = parse_diff_text(NEW_FILE_DIFF)
        contents = [line for _, line in hunks[0].added_lines]
        assert contents == ["line_one", "line_two", "line_three"]

    def test_hunk_header_preserved(self) -> None:
        """The raw hunk header string should be stored in DiffHunk.hunk_header."""
        hunks = parse_diff_text(SIMPLE_DIFF)
        assert "@@" in hunks[0].hunk_header

    def test_start_line_matches_hunk_header(self) -> None:
        """DiffHunk.start_line should match the new-file start in the @@ header."""
        hunks = parse_diff_text(SIMPLE_DIFF)
        # @@ -10,3 +10,5 @@ -> new-file start = 10
        assert hunks[0].start_line == 10

    def test_single_line_hunk_no_count(self) -> None:
        """A hunk with '@@ -5 +5 @@' (no count) should work."""
        hunks = parse_diff_text(SINGLE_LINE_HUNK)
        assert len(hunks) == 1
        assert hunks[0].line_count == 1
        line_contents = [line for _, line in hunks[0].added_lines]
        assert "new" in line_contents

    def test_deleted_file_produces_no_hunks(self) -> None:
        """A diff for a deleted file should produce no added-line hunks."""
        deleted_diff = (
            "diff --git a/gone.py b/gone.py\n"
            "deleted file mode 100644\n"
            "index abc1234..0000000\n"
            "--- a/gone.py\n"
            "+++ /dev/null\n"
            "@@ -1,2 +0,0 @@\n"
            "-line1\n"
            "-line2\n"
        )
        hunks = parse_diff_text(deleted_diff)
        assert hunks == []

    def test_whitespace_only_added_line_captured(self) -> None:
        """An added line that is just whitespace should still be captured."""
        diff = (
            "diff --git a/ws.py b/ws.py\n"
            "index 0000001..0000002 100644\n"
            "--- a/ws.py\n"
            "+++ b/ws.py\n"
            "@@ -1,1 +1,2 @@\n"
            " context\n"
            "+   \n"  # whitespace-only added line
        )
        hunks = parse_diff_text(diff)
        assert len(hunks) == 1
        assert hunks[0].line_count == 1

    def test_line_numbers_advance_correctly_across_context(self) -> None:
        """Line numbers should advance for context lines but not deleted lines."""
        diff = (
            "diff --git a/counter.py b/counter.py\n"
            "index 0000001..0000002 100644\n"
            "--- a/counter.py\n"
            "+++ b/counter.py\n"
            "@@ -1,5 +1,5 @@\n"
            " context_1\n"   # new line 1 (context)
            "-deleted\n"     # no new-file increment
            " context_2\n"   # new line 2 (context)
            "+added_at_3\n"  # new line 3
            " context_3\n"   # new line 4 (context)
        )
        hunks = parse_diff_text(diff)
        assert len(hunks) == 1
        line_numbers = [ln for ln, _ in hunks[0].added_lines]
        assert line_numbers == [3]

    def test_multiple_added_lines_sequential_numbers(self) -> None:
        """Consecutive added lines should have sequential line numbers."""
        diff = (
            "diff --git a/seq.py b/seq.py\n"
            "index 0000001..0000002 100644\n"
            "--- a/seq.py\n"
            "+++ b/seq.py\n"
            "@@ -1,0 +1,3 @@\n"
            "+first\n"
            "+second\n"
            "+third\n"
        )
        hunks = parse_diff_text(diff)
        assert len(hunks) == 1
        line_numbers = [ln for ln, _ in hunks[0].added_lines]
        assert line_numbers == [1, 2, 3]

    def test_returns_list_of_diff_hunk_instances(self) -> None:
        """parse_diff_text() must return a list of DiffHunk instances."""
        hunks = parse_diff_text(SIMPLE_DIFF)
        assert isinstance(hunks, list)
        for hunk in hunks:
            assert isinstance(hunk, DiffHunk)


# ---------------------------------------------------------------------------
# Tests for get_diff_files
# ---------------------------------------------------------------------------


class TestGetDiffFiles:
    """Tests for get_diff_files() using mocked git output."""

    def test_returns_sorted_unique_files(self) -> None:
        """get_diff_files() should return a sorted, deduplicated file list."""
        with patch("vulndiff.git_diff._run_git", return_value=MULTI_FILE_DIFF):
            files = get_diff_files(mode="staged")
        assert files == sorted(files)
        assert len(files) == len(set(files))

    def test_multi_file_diff_files(self) -> None:
        """Both file paths should appear in the result."""
        with patch("vulndiff.git_diff._run_git", return_value=MULTI_FILE_DIFF):
            files = get_diff_files(mode="staged")
        assert "foo.py" in files
        assert "bar.py" in files

    def test_empty_diff_returns_empty_list(self) -> None:
        """An empty diff should yield an empty file list."""
        with patch("vulndiff.git_diff._run_git", return_value=EMPTY_DIFF):
            files = get_diff_files(mode="staged")
        assert files == []


# ---------------------------------------------------------------------------
# Tests for get_hunks dispatch
# ---------------------------------------------------------------------------


class TestGetHunks:
    """Tests for the get_hunks() dispatcher."""

    def test_staged_mode_calls_staged(self) -> None:
        """mode='staged' should invoke get_staged_hunks."""
        with patch("vulndiff.git_diff.get_staged_hunks", return_value=[]) as mock:
            get_hunks(mode="staged")
            mock.assert_called_once()

    def test_head_mode_calls_head(self) -> None:
        """mode='head' should invoke get_head_hunks."""
        with patch("vulndiff.git_diff.get_head_hunks", return_value=[]) as mock:
            get_hunks(mode="head")
            mock.assert_called_once()

    def test_ref_range_mode_calls_ref_range(self) -> None:
        """mode='ref-range' should invoke get_hunks_for_ref_range."""
        with patch(
            "vulndiff.git_diff.get_hunks_for_ref_range", return_value=[]
        ) as mock:
            get_hunks(mode="ref-range", from_ref="main", to_ref="HEAD")
            mock.assert_called_once_with(from_ref="main", to_ref="HEAD", cwd=None)

    def test_ref_range_without_from_ref_raises(self) -> None:
        """mode='ref-range' without from_ref should raise ValueError."""
        with pytest.raises(ValueError, match="from_ref"):
            get_hunks(mode="ref-range", from_ref=None)

    def test_ref_range_empty_from_ref_raises(self) -> None:
        """mode='ref-range' with empty from_ref should raise ValueError."""
        with pytest.raises(ValueError, match="from_ref"):
            get_hunks(mode="ref-range", from_ref="")

    def test_unknown_mode_raises(self) -> None:
        """An unrecognised mode should raise ValueError."""
        with pytest.raises(ValueError, match="Unknown mode"):
            get_hunks(mode="invalid")


# ---------------------------------------------------------------------------
# Tests for get_staged_hunks (mocked subprocess)
# ---------------------------------------------------------------------------


class TestGetStagedHunks:
    """Tests for get_staged_hunks() with mocked git output."""

    def test_returns_hunks(self) -> None:
        """Should return DiffHunk objects when git outputs a valid diff."""
        with patch("vulndiff.git_diff._run_git", return_value=SIMPLE_DIFF):
            hunks = get_staged_hunks()
        assert len(hunks) == 1
        assert isinstance(hunks[0], DiffHunk)

    def test_passes_cached_flag(self) -> None:
        """Should invoke git with '--cached' argument."""
        with patch("vulndiff.git_diff._run_git", return_value="") as mock:
            get_staged_hunks()
            call_args = mock.call_args[0][0]
            assert "--cached" in call_args

    def test_empty_staged_diff_returns_empty(self) -> None:
        """An empty staged diff should return an empty list."""
        with patch("vulndiff.git_diff._run_git", return_value=""):
            hunks = get_staged_hunks()
        assert hunks == []

    def test_propagates_git_error(self) -> None:
        """A GitError from _run_git should propagate to the caller."""
        with patch(
            "vulndiff.git_diff._run_git", side_effect=GitError("git failed", 1)
        ):
            with pytest.raises(GitError):
                get_staged_hunks()


# ---------------------------------------------------------------------------
# Tests for get_hunks_for_ref_range
# ---------------------------------------------------------------------------


class TestGetHunksForRefRange:
    """Tests for get_hunks_for_ref_range()."""

    def test_empty_from_ref_raises(self) -> None:
        """An empty from_ref should raise ValueError."""
        with pytest.raises(ValueError, match="from_ref"):
            get_hunks_for_ref_range(from_ref="")

    def test_whitespace_from_ref_raises(self) -> None:
        """A whitespace-only from_ref should raise ValueError."""
        with pytest.raises(ValueError, match="from_ref"):
            get_hunks_for_ref_range(from_ref="   ")

    def test_empty_to_ref_raises(self) -> None:
        """An empty to_ref should raise ValueError."""
        with pytest.raises(ValueError, match="to_ref"):
            get_hunks_for_ref_range(from_ref="main", to_ref="")

    def test_valid_range_returns_hunks(self) -> None:
        """A valid ref range should return hunks parsed from git output."""
        with patch("vulndiff.git_diff._run_git", return_value=MULTI_FILE_DIFF):
            hunks = get_hunks_for_ref_range(from_ref="main", to_ref="HEAD")
        assert len(hunks) == 2

    def test_includes_from_and_to_ref_in_git_call(self) -> None:
        """The from_ref and to_ref should appear in the git arguments."""
        with patch("vulndiff.git_diff._run_git", return_value="") as mock:
            get_hunks_for_ref_range(from_ref="abc123", to_ref="def456")
            call_args = mock.call_args[0][0]
            assert "abc123" in call_args
            assert "def456" in call_args


# ---------------------------------------------------------------------------
# Tests for _run_git error handling
# ---------------------------------------------------------------------------


class TestRunGit:
    """Tests for _run_git error handling."""

    def test_raises_git_error_on_nonzero_exit(self) -> None:
        """A non-zero exit code should raise GitError."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b""
        mock_result.stderr = b"some error"
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(GitError):
                _run_git(["diff"])

    def test_raises_not_a_git_repo_on_exit_128(self) -> None:
        """Exit code 128 should raise NotAGitRepositoryError."""
        mock_result = MagicMock()
        mock_result.returncode = 128
        mock_result.stdout = b""
        mock_result.stderr = b"not a git repository"
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(NotAGitRepositoryError):
                _run_git(["diff"])

    def test_raises_git_error_when_git_not_found(self) -> None:
        """FileNotFoundError from subprocess should raise GitError."""
        with patch("subprocess.run", side_effect=FileNotFoundError("git not found")):
            with pytest.raises(GitError, match="git executable not found"):
                _run_git(["diff"])

    def test_returns_stdout_on_success(self) -> None:
        """A successful git call should return the decoded stdout string."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"hello output\n"
        mock_result.stderr = b""
        with patch("subprocess.run", return_value=mock_result):
            output = _run_git(["status"])
        assert output == "hello output\n"

    def test_git_error_stores_returncode(self) -> None:
        """GitError should expose the returncode attribute."""
        mock_result = MagicMock()
        mock_result.returncode = 2
        mock_result.stdout = b""
        mock_result.stderr = b"error text"
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(GitError) as exc_info:
                _run_git(["log"])
        assert exc_info.value.returncode == 2

    def test_git_error_stores_stderr(self) -> None:
        """GitError should expose the stderr attribute."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = b""
        mock_result.stderr = b"fatal: bad object"
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(GitError) as exc_info:
                _run_git(["log"])
        assert "fatal: bad object" in exc_info.value.stderr


# ---------------------------------------------------------------------------
# Additional edge-case parser tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Additional edge-case tests for the diff parser."""

    def test_diff_with_binary_file_notice(self) -> None:
        """Binary file notices should be silently ignored."""
        diff = (
            "diff --git a/image.png b/image.png\n"
            "index 1111111..2222222 100644\n"
            "Binary files a/image.png and b/image.png differ\n"
        )
        hunks = parse_diff_text(diff)
        assert hunks == []

    def test_diff_with_index_line(self) -> None:
        """Index lines should not be treated as added lines."""
        diff = (
            "diff --git a/foo.py b/foo.py\n"
            "index abc1234..def5678 100644\n"
            "--- a/foo.py\n"
            "+++ b/foo.py\n"
            "@@ -1,1 +1,2 @@\n"
            " original\n"
            "+added\n"
        )
        hunks = parse_diff_text(diff)
        assert len(hunks) == 1
        contents = [line for _, line in hunks[0].added_lines]
        assert contents == ["added"]
        # "index abc1234..def5678 100644" must not appear
        assert all("index" not in c for c in contents)

    def test_diff_with_mode_change_and_content(self) -> None:
        """A diff with a mode change line should parse added lines correctly."""
        diff = (
            "diff --git a/script.py b/script.py\n"
            "old mode 100644\n"
            "new mode 100755\n"
            "index abc1234..def5678\n"
            "--- a/script.py\n"
            "+++ b/script.py\n"
            "@@ -1,1 +1,2 @@\n"
            " old_line\n"
            "+new_line\n"
        )
        hunks = parse_diff_text(diff)
        assert len(hunks) == 1
        contents = [line for _, line in hunks[0].added_lines]
        assert "new_line" in contents

    def test_three_file_diff(self) -> None:
        """A diff spanning three files should produce three hunk groups."""
        diff = ""
        for i in range(1, 4):
            diff += (
                f"diff --git a/file{i}.py b/file{i}.py\n"
                f"index 000{i}..000{i + 1} 100644\n"
                f"--- a/file{i}.py\n"
                f"+++ b/file{i}.py\n"
                f"@@ -1,1 +1,2 @@\n"
                f" original\n"
                f"+added_{i}\n"
            )
        hunks = parse_diff_text(diff)
        assert len(hunks) == 3
        paths = {h.file_path for h in hunks}
        assert paths == {"file1.py", "file2.py", "file3.py"}

    def test_hunk_with_only_context_no_additions(self) -> None:
        """A @@ section with only context lines should not produce a hunk."""
        diff = (
            "diff --git a/ctx.py b/ctx.py\n"
            "index abc..def 100644\n"
            "--- a/ctx.py\n"
            "+++ b/ctx.py\n"
            "@@ -1,3 +1,2 @@\n"
            " context1\n"
            "-removed\n"
            " context2\n"
        )
        hunks = parse_diff_text(diff)
        assert hunks == []

    def test_deeply_nested_path(self) -> None:
        """File paths with subdirectories should be captured correctly."""
        diff = (
            "diff --git a/a/b/c/deep.py b/a/b/c/deep.py\n"
            "index abc..def 100644\n"
            "--- a/a/b/c/deep.py\n"
            "+++ b/a/b/c/deep.py\n"
            "@@ -1,1 +1,2 @@\n"
            " original\n"
            "+added\n"
        )
        hunks = parse_diff_text(diff)
        assert len(hunks) == 1
        assert hunks[0].file_path == "a/b/c/deep.py"

    def test_added_line_with_plus_prefix_in_content(self) -> None:
        """An added line whose content starts with '+' should preserve the extra '+'."""
        diff = (
            "diff --git a/plus.py b/plus.py\n"
            "index abc..def 100644\n"
            "--- a/plus.py\n"
            "+++ b/plus.py\n"
            "@@ -1,1 +1,2 @@\n"
            " original\n"
            "++plus_content\n"  # raw line starts with '+', content is '+plus_content'
        )
        hunks = parse_diff_text(diff)
        assert len(hunks) == 1
        contents = [line for _, line in hunks[0].added_lines]
        assert "+plus_content" in contents

    def test_multiple_hunks_line_number_continuity(self) -> None:
        """Line numbers in successive hunks should be independent and correct."""
        hunks = parse_diff_text(MULTI_HUNK_DIFF)
        assert len(hunks) == 2
        # First hunk starts at line 5 in new file, context on line 5 -> adds at 6, 7
        first_lines = [ln for ln, _ in hunks[0].added_lines]
        assert first_lines[0] >= 1
        # Second hunk starts at line 21, context on 21 -> add at 22
        second_lines = [ln for ln, _ in hunks[1].added_lines]
        assert second_lines[0] >= 1
        # The two hunks must not share line numbers (they're in different regions)
        assert set(first_lines).isdisjoint(set(second_lines))

    def test_diff_with_no_context_lines(self) -> None:
        """A diff produced with --unified=0 has no context lines."""
        diff = (
            "diff --git a/nocontext.py b/nocontext.py\n"
            "index abc..def 100644\n"
            "--- a/nocontext.py\n"
            "+++ b/nocontext.py\n"
            "@@ -5,0 +6,2 @@\n"
            "+inserted_1\n"
            "+inserted_2\n"
        )
        hunks = parse_diff_text(diff)
        assert len(hunks) == 1
        assert hunks[0].line_count == 2
        line_numbers = [ln for ln, _ in hunks[0].added_lines]
        assert line_numbers == [6, 7]

    def test_file_with_spaces_in_name(self) -> None:
        """File paths containing spaces should be captured correctly."""
        diff = (
            "diff --git a/my file.py b/my file.py\n"
            "index abc..def 100644\n"
            "--- a/my file.py\n"
            "+++ b/my file.py\n"
            "@@ -1,1 +1,2 @@\n"
            " original\n"
            "+added\n"
        )
        hunks = parse_diff_text(diff)
        assert len(hunks) == 1
        assert hunks[0].file_path == "my file.py"

    def test_parse_returns_empty_for_diff_header_only(self) -> None:
        """A diff with only the file header and no hunks should return empty."""
        diff = (
            "diff --git a/headeronly.py b/headeronly.py\n"
            "index abc..def 100644\n"
        )
        hunks = parse_diff_text(diff)
        assert hunks == []
