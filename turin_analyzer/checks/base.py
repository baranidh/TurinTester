"""Base class for all AMD Turin architectural checks."""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional


class Severity(str, Enum):
    """Finding severity aligned with GitLab Code Quality spec."""
    CRITICAL = "critical"   # Hot-path bottleneck — measurable latency hit
    MAJOR    = "major"      # Missing key Turin optimisation
    MINOR    = "minor"      # Nice-to-have improvement
    INFO     = "info"       # Informational note


@dataclass
class Finding:
    """A single missed-optimisation finding in a source file."""
    check_id:    str
    severity:    Severity
    title:       str
    description: str
    file_path:   str
    line:        int
    column:      int = 1
    suggestion:  str = ""
    # Turin feature that is missing
    turin_feature: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id":     self.check_id,
            "severity":     self.severity.value,
            "title":        self.title,
            "description":  self.description,
            "file_path":    self.file_path,
            "line":         self.line,
            "column":       self.column,
            "suggestion":   self.suggestion,
            "turin_feature": self.turin_feature,
        }


@dataclass
class CheckResult:
    """Aggregated result of running one check over one file."""
    check_name:  str
    file_path:   str
    findings:    List[Finding] = field(default_factory=list)
    passed:      bool = True

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.passed = False


class BaseCheck:
    """
    Every architectural check subclasses this.

    Subclasses MUST set:
        CHECK_ID    – short snake_case identifier
        TITLE       – one-liner shown in report
        TURIN_FEATURE – which Turin HW/SW feature is being tested
        DESCRIPTION – paragraph explaining why it matters for low latency

    Subclasses MUST implement:
        check_file(path, lines) -> CheckResult
    """

    CHECK_ID:      str = ""
    TITLE:         str = ""
    TURIN_FEATURE: str = ""
    DESCRIPTION:   str = ""

    # File extensions this check applies to
    APPLICABLE_EXTENSIONS = {".cpp", ".cc", ".cxx", ".c", ".hpp", ".h", ".hxx"}

    def applies_to(self, path: Path) -> bool:
        return path.suffix.lower() in self.APPLICABLE_EXTENSIONS

    def check_file(self, path: Path, lines: List[str]) -> CheckResult:
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def find_pattern(
        lines: List[str],
        pattern: str,
        flags: int = 0,
    ) -> List[tuple[int, re.Match]]:
        """Return list of (1-based line number, match) for every hit."""
        compiled = re.compile(pattern, flags)
        return [
            (idx + 1, m)
            for idx, line in enumerate(lines)
            for m in [compiled.search(line)]
            if m
        ]

    @staticmethod
    def file_contains(lines: List[str], pattern: str, flags: int = 0) -> bool:
        compiled = re.compile(pattern, flags)
        return any(compiled.search(line) for line in lines)

    @staticmethod
    def strip_comments(line: str) -> str:
        """Remove C++-style line comments (best-effort)."""
        idx = line.find("//")
        return line[:idx] if idx != -1 else line
