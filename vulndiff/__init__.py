"""vulndiff - Diff-aware security scanner for AI-assisted codebases.

This package provides tools to analyze staged or committed code changes
against a curated set of vulnerability patterns covering OWASP Top 10,
injection flaws, authentication issues, hardcoded secrets, and more.

Typical usage::

    from vulndiff import __version__
    print(f"vulndiff v{__version__}")

Or via the CLI::

    vulndiff --staged
    vulndiff --from-ref main --to-ref HEAD
"""

__version__ = "0.1.0"
__author__ = "vulndiff contributors"
__license__ = "MIT"

__all__ = ["__version__", "__author__", "__license__"]
