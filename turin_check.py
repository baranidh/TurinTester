#!/usr/bin/env python3
"""
turin_check.py — AMD Turin Latency Analyzer CLI

Analyses C++ source files for missed AMD Turin (EPYC 9005 / Zen 5)
architectural optimisations and reports findings in multiple formats.

Usage
-----
  # Check all C++ files in a directory
  python3 turin_check.py src/

  # Check specific files (e.g. changed files in a MR)
  python3 turin_check.py src/fix_parser.cpp src/order_book.hpp

  # GitLab Code Quality output
  python3 turin_check.py src/ --format gitlab --output gl-code-quality.json

  # Print loud warnings for CRITICAL/MAJOR (pipeline never fails)
  python3 turin_check.py src/

  # Only report CRITICAL
  python3 turin_check.py src/ --min-severity critical

GitLab CI integration
---------------------
  See .gitlab-ci.yml for the recommended pipeline configuration.
  The tool produces a gitlab-code-quality artifact that GitLab renders
  as inline annotations on merge request diffs.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from turin_analyzer.analyzer import TurinAnalyzer
from turin_analyzer.checks.base import Severity
from turin_analyzer.reporter import (
    to_console,
    to_gitlab_code_quality,
    to_json,
    to_markdown,
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="turin_check",
        description="AMD Turin (Zen 5) latency optimisation checker for C++ code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "paths",
        nargs="*",
        metavar="PATH",
        help="Files or directories to analyse",
    )
    p.add_argument(
        "--format",
        choices=["console", "json", "gitlab", "markdown"],
        default="console",
        help="Output format (default: console)",
    )
    p.add_argument(
        "--output",
        metavar="FILE",
        help="Write output to FILE instead of stdout",
    )
    p.add_argument(
        "--fail-on",
        choices=["critical", "major", "minor", "info", "none"],
        default="none",
        metavar="SEVERITY",
        help=(
            "Exit with code 1 if any finding at or above this severity exists. "
            "Use 'none' to never fail (default: none)"
        ),
    )
    p.add_argument(
        "--min-severity",
        choices=["critical", "major", "minor", "info"],
        default="minor",
        metavar="SEVERITY",
        help="Minimum severity level to report (default: minor)",
    )
    p.add_argument(
        "--checks",
        nargs="+",
        metavar="CHECK_ID",
        help="Run only the specified check IDs (e.g. TURIN_SIMD TURIN_NUMA)",
    )
    p.add_argument(
        "--list-checks",
        action="store_true",
        help="List all available checks and exit",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    from turin_analyzer.checks import ALL_CHECKS

    if args.list_checks:
        print("\nAvailable AMD Turin checks:\n")
        print(f"  {'CHECK_ID':<25} {'TURIN_FEATURE'}")
        print("  " + "-" * 80)
        for cls in ALL_CHECKS:
            inst = cls()
            print(f"  {inst.CHECK_ID:<25} {inst.TURIN_FEATURE}")
        print()
        return 0

    # Filter checks if --checks specified
    checks = ALL_CHECKS
    if args.checks:
        wanted = set(args.checks)
        checks = [c for c in ALL_CHECKS if c().CHECK_ID in wanted]
        if not checks:
            print(f"[ERROR] No checks matched: {args.checks}", file=sys.stderr)
            return 2

    min_sev = Severity(args.min_severity)
    analyzer = TurinAnalyzer(checks=checks, min_severity=min_sev)

    if not args.paths:
        print("[ERROR] Specify at least one PATH to analyse.", file=sys.stderr)
        return 2

    paths = [Path(p) for p in args.paths]
    missing = [p for p in paths if not p.exists()]
    if missing:
        for m in missing:
            print(f"[ERROR] Path not found: {m}", file=sys.stderr)
        return 2

    result = analyzer.analyze_paths(paths)

    # Generate output
    if args.format == "console":
        to_console(result)
        output_str = None
    elif args.format == "gitlab":
        output_str = to_gitlab_code_quality(result)
    elif args.format == "json":
        output_str = to_json(result)
    elif args.format == "markdown":
        output_str = to_markdown(result)
    else:
        output_str = None

    if output_str is not None:
        if args.output:
            Path(args.output).write_text(output_str, encoding="utf-8")
            print(f"Report written to {args.output}", file=sys.stderr)
        else:
            print(output_str)

    # Also always write console output to stderr when a file output is chosen
    if args.output and args.format != "console":
        to_console(result)

    # Severity banner — always printed to stderr so it appears in CI logs
    # regardless of output format. Pipeline never fails; findings are advisory.
    _print_severity_banners(result)

    # Honour --fail-on if the caller explicitly opted in (default: none)
    if args.fail_on != "none":
        fail_sev = Severity(args.fail_on)
        fail_order = {
            Severity.CRITICAL: 0,
            Severity.MAJOR:    1,
            Severity.MINOR:    2,
            Severity.INFO:     3,
        }
        threshold = fail_order[fail_sev]
        for finding in result.all_findings:
            if fail_order[finding.severity] <= threshold:
                return 1

    return 0


def _print_severity_banners(result: "AnalysisResult") -> None:
    """Print loud CRITICAL/MAJOR/MINOR WARNING banners to stderr."""
    from turin_analyzer.checks.base import Severity

    counts: dict = {}
    for f in result.all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    banners = [
        (Severity.CRITICAL, "CRITICAL WARNING"),
        (Severity.MAJOR,    "MAJOR WARNING"),
        (Severity.MINOR,    "MINOR WARNING"),
    ]

    printed_any = False
    for sev, label in banners:
        n = counts.get(sev, 0)
        if n:
            bar = "!" * 60
            print(f"\n{bar}", file=sys.stderr)
            print(f"  *** {label} ***  {n} {sev.value} Turin finding(s) detected!", file=sys.stderr)
            print(f"{bar}", file=sys.stderr)
            printed_any = True

    if printed_any:
        print(
            "\n  The pipeline continues — findings above are advisory.\n"
            "  Review the Code Quality report in the MR for details.\n",
            file=sys.stderr,
        )


if __name__ == "__main__":
    sys.exit(main())
