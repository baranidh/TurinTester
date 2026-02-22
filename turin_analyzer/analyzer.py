"""
Main analysis engine — orchestrates all checks over a set of source files.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .checks import ALL_CHECKS
from .checks.base import BaseCheck, CheckResult, Finding, Severity


# ---------------------------------------------------------------------------
# Severity ordering for sorting / filtering
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.MAJOR:    1,
    Severity.MINOR:    2,
    Severity.INFO:     3,
}


class AnalysisResult:
    """Full results of analysing one or more files."""

    def __init__(self) -> None:
        self.file_results: List[CheckResult] = []
        self.all_findings: List[Finding]     = []

    def add_result(self, result: CheckResult) -> None:
        self.file_results.append(result)
        self.all_findings.extend(result.findings)

    @property
    def total_findings(self) -> int:
        return len(self.all_findings)

    @property
    def by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def passed(self) -> bool:
        """True if no CRITICAL or MAJOR findings."""
        for f in self.all_findings:
            if f.severity in (Severity.CRITICAL, Severity.MAJOR):
                return False
        return True

    def sorted_findings(self) -> List[Finding]:
        return sorted(
            self.all_findings,
            key=lambda f: (SEVERITY_ORDER[f.severity], f.file_path, f.line),
        )


class TurinAnalyzer:
    """
    Orchestrator: runs all enabled checks over a collection of paths.

    Parameters
    ----------
    checks : list of BaseCheck subclasses (default: ALL_CHECKS)
    min_severity : lowest severity level to report (default: MINOR)
    """

    def __init__(
        self,
        checks: Optional[List[type]] = None,
        min_severity: Severity = Severity.MINOR,
    ) -> None:
        self.checks: List[BaseCheck] = [
            cls() for cls in (checks or ALL_CHECKS)
        ]
        self.min_severity = min_severity

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_path(self, path: Path) -> AnalysisResult:
        """Analyse a single file or recursively a directory."""
        result = AnalysisResult()
        if path.is_dir():
            for p in sorted(path.rglob("*")):
                if p.is_file():
                    self._analyze_file(p, result)
        elif path.is_file():
            self._analyze_file(path, result)
        return result

    def analyze_paths(self, paths: Iterable[Path]) -> AnalysisResult:
        """Analyse a list of paths."""
        combined = AnalysisResult()
        for path in paths:
            sub = self.analyze_path(path)
            for r in sub.file_results:
                combined.add_result(r)
        return combined

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _analyze_file(self, path: Path, result: AnalysisResult) -> None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"[WARN] Cannot read {path}: {exc}", file=sys.stderr)
            return

        lines = text.splitlines()

        for check in self.checks:
            if not check.applies_to(path):
                continue
            cr = check.check_file(path, lines)
            # Filter by min severity
            cr.findings = [
                f for f in cr.findings
                if SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[self.min_severity]
            ]
            if cr.findings:
                cr.passed = False
            result.add_result(cr)
