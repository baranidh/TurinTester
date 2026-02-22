"""
Report generators for the Turin Latency Analyzer.

Supported output formats:
  1. GitLab Code Quality  — JSON array of code-quality issues (GL standard)
  2. JSON                 — full detail JSON for downstream tools
  3. Console              — coloured terminal output
  4. Markdown             — summary suitable for MR description / wiki

GitLab Code Quality spec:
  https://docs.gitlab.com/ee/ci/testing/code_quality.html#implement-a-custom-tool
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List

from .analyzer import AnalysisResult, SEVERITY_ORDER
from .checks.base import Finding, Severity


# ---------------------------------------------------------------------------
# ANSI colour codes (disabled if not a TTY)
# ---------------------------------------------------------------------------
_USE_COLOUR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

_C = {
    "reset":   "\033[0m"  if _USE_COLOUR else "",
    "bold":    "\033[1m"  if _USE_COLOUR else "",
    "red":     "\033[31m" if _USE_COLOUR else "",
    "yellow":  "\033[33m" if _USE_COLOUR else "",
    "cyan":    "\033[36m" if _USE_COLOUR else "",
    "green":   "\033[32m" if _USE_COLOUR else "",
    "magenta": "\033[35m" if _USE_COLOUR else "",
}

_SEV_COLOUR = {
    Severity.CRITICAL: _C["red"],
    Severity.MAJOR:    _C["yellow"],
    Severity.MINOR:    _C["cyan"],
    Severity.INFO:     _C["magenta"],
}

_SEV_EMOJI = {
    Severity.CRITICAL: "CRITICAL",
    Severity.MAJOR:    "MAJOR   ",
    Severity.MINOR:    "MINOR   ",
    Severity.INFO:     "INFO    ",
}

# GitLab Code Quality severity mapping
_GL_SEVERITY = {
    Severity.CRITICAL: "critical",
    Severity.MAJOR:    "major",
    Severity.MINOR:    "minor",
    Severity.INFO:     "info",
}


# ---------------------------------------------------------------------------
# GitLab Code Quality JSON
# ---------------------------------------------------------------------------

def _fingerprint(f: Finding) -> str:
    """Stable fingerprint for deduplication in GL Code Quality."""
    raw = f"{f.check_id}:{f.file_path}:{f.line}:{f.title}"
    return hashlib.md5(raw.encode()).hexdigest()


def to_gitlab_code_quality(result: AnalysisResult) -> str:
    """
    Emit a GitLab Code Quality JSON array.
    Upload as an artifact with report type code_quality.
    """
    issues = []
    for finding in result.sorted_findings():
        issues.append({
            "type":        "issue",
            "check_name":  finding.check_id,
            "description": f"[Turin/{finding.turin_feature}] {finding.title}: {finding.description}",
            "severity":    _GL_SEVERITY[finding.severity],
            "fingerprint": _fingerprint(finding),
            "location": {
                "path":  finding.file_path,
                "lines": {"begin": finding.line},
            },
            "categories": ["Performance", "AMD Turin Architecture"],
            "content": {
                "body": finding.suggestion,
            },
        })
    return json.dumps(issues, indent=2)


# ---------------------------------------------------------------------------
# Full JSON report
# ---------------------------------------------------------------------------

def to_json(result: AnalysisResult) -> str:
    """Full structured JSON report for downstream tools."""
    return json.dumps(
        {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings":   result.total_findings,
                "by_severity":      result.by_severity,
                "passed":           result.passed,
            },
            "findings": [f.to_dict() for f in result.sorted_findings()],
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

def to_console(result: AnalysisResult) -> None:
    """Print findings to stdout with ANSI colour."""
    findings = result.sorted_findings()

    if not findings:
        print(f"{_C['green']}{_C['bold']}No AMD Turin latency issues found.{_C['reset']}")
        return

    print(f"\n{_C['bold']}AMD Turin Latency Analysis — {len(findings)} finding(s){_C['reset']}\n")

    for f in findings:
        sev_col = _SEV_COLOUR[f.severity]
        label   = _SEV_EMOJI[f.severity]
        print(
            f"{sev_col}{_C['bold']}[{label}]{_C['reset']} "
            f"{_C['bold']}{f.file_path}:{f.line}{_C['reset']} — {f.title}"
        )
        print(f"  Turin feature: {_C['cyan']}{f.turin_feature}{_C['reset']}")
        # Wrap description at 100 chars
        desc_lines = _wrap(f.description, 98)
        for dl in desc_lines:
            print(f"  {dl}")
        if f.suggestion:
            print(f"  {_C['bold']}Suggestion:{_C['reset']}")
            for sl in f.suggestion.splitlines():
                print(f"    {sl}")
        print()

    # Summary
    sev = result.by_severity
    print(f"{_C['bold']}Summary:{_C['reset']}")
    print(f"  Critical : {_C['red']}{sev.get('critical', 0)}{_C['reset']}")
    print(f"  Major    : {_C['yellow']}{sev.get('major', 0)}{_C['reset']}")
    print(f"  Minor    : {_C['cyan']}{sev.get('minor', 0)}{_C['reset']}")
    print(f"  Info     : {sev.get('info', 0)}")

    overall = (
        f"{_C['red']}{_C['bold']}FAIL{_C['reset']}"
        if not result.passed
        else f"{_C['green']}{_C['bold']}PASS{_C['reset']}"
    )
    print(f"\nOverall: {overall}")


# ---------------------------------------------------------------------------
# Markdown summary
# ---------------------------------------------------------------------------

def to_markdown(result: AnalysisResult) -> str:
    """Markdown summary suitable for MR description or wiki posting."""
    lines = [
        "## AMD Turin Latency Analysis",
        "",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]

    sev = result.by_severity
    status = "PASS" if result.passed else "FAIL"
    icon   = "" if result.passed else ""
    lines += [
        f"### Overall: {icon} {status}",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| Critical | {sev.get('critical', 0)} |",
        f"| Major    | {sev.get('major', 0)} |",
        f"| Minor    | {sev.get('minor', 0)} |",
        f"| Info     | {sev.get('info', 0)} |",
        "",
    ]

    if not result.all_findings:
        lines.append("No AMD Turin latency issues found.")
        return "\n".join(lines)

    lines += ["### Findings", ""]
    for f in result.sorted_findings():
        lines += [
            f"#### [{f.severity.value.upper()}] {f.title}",
            f"- **File:** `{f.file_path}:{f.line}`",
            f"- **Turin Feature:** {f.turin_feature}",
            f"- **Description:** {f.description}",
        ]
        if f.suggestion:
            lines += [
                "- **Suggestion:**",
                "  ```cpp",
            ]
            for sl in f.suggestion.splitlines():
                lines.append(f"  {sl}")
            lines.append("  ```")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _wrap(text: str, width: int) -> List[str]:
    """Simple word-wrap at width chars."""
    words  = text.split()
    result: List[str] = []
    current = ""
    for w in words:
        if len(current) + len(w) + 1 > width:
            if current:
                result.append(current)
            current = w
        else:
            current = f"{current} {w}" if current else w
    if current:
        result.append(current)
    return result
