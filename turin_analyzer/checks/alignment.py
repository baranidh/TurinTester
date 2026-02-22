"""
Check: Cache-line alignment (64 bytes on AMD Turin / Zen 5).

AMD Turin uses 64-byte cache lines (same as all x86-64 chips).
Structures placed in hot paths — order-book price levels, FIX field
tables, order records — that are not aligned to 64 bytes cause partial
cache-line loads and unnecessary evictions, adding dozens of nanoseconds
per access.

What we look for:
  MISSING — structs/classes in hot-path files that have no alignas(64),
             no CACHE_LINE_SIZE constant, no __attribute__((aligned(64))).
  PRESENT — the reverse.

We also flag raw `struct` or `class` declarations containing multiple
unrelated fields that look like they could suffer false sharing
(handled more deeply in false_sharing.py).
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List

from .base import BaseCheck, CheckResult, Finding, Severity


# Patterns that INDICATE alignment awareness
_GOOD_PATTERNS = [
    r"\balignof\s*\(",
    r"\balignof\s*<",
    r"\balignof\s+",
    r"\balignas\s*\(\s*6[04]\s*\)",          # alignas(64) or alignas(60) edge cases
    r"\balignas\s*\(.*CACHE_LINE",            # alignas(CACHE_LINE_SIZE)
    r"__attribute__\s*\(\s*\(\s*aligned\s*\(\s*6[04]\s*\)",
    r"hardware_destructive_interference_size",
    r"hardware_constructive_interference_size",
    r"CACHE_LINE_SIZE\s*=\s*64",
    r"CACHELINE_SIZE\s*=\s*64",
    r"L1_CACHE_BYTES\s*=\s*64",
]

# Patterns that indicate a struct/class definition is being declared
_STRUCT_DECL = re.compile(
    r"^\s*(struct|class)\s+\w+",
)

# Alignment annotation anywhere on the same line as struct
_ALIGN_ON_STRUCT = re.compile(
    r"alignas\s*\(|__attribute__\s*\(\s*\(\s*aligned|CACHE_LINE"
)

# Files that belong to hot paths based on common naming conventions
_HOT_PATH_NAMES = re.compile(
    r"(order_?book|risk|fix_?pars|pars|order|match|engine|protocol|codec|handler)",
    re.IGNORECASE,
)


class AlignmentCheck(BaseCheck):
    CHECK_ID      = "TURIN_ALIGN"
    TITLE         = "Cache-line alignment (64 B) not enforced"
    TURIN_FEATURE = "Zen 5 64-byte L1/L2/L3 cache lines"
    DESCRIPTION   = (
        "AMD Turin (Zen 5) uses 64-byte cache lines across L1, L2 and L3. "
        "Hot-path data structures must be 64-byte aligned so each struct "
        "occupies whole cache lines, avoiding unnecessary partial-line "
        "fetches, split-load penalties and false sharing between cores. "
        "Use alignas(64), std::hardware_destructive_interference_size, or "
        "__attribute__((aligned(64))) on every latency-critical struct."
    )

    def check_file(self, path: Path, lines: List[str]) -> CheckResult:
        result = CheckResult(check_name=self.CHECK_ID, file_path=str(path))

        is_hot_path = bool(_HOT_PATH_NAMES.search(path.stem))
        has_global_align = any(
            re.search(p, "\n".join(lines), re.IGNORECASE)
            for p in _GOOD_PATTERNS
        )

        # Scan for struct/class declarations without alignment annotation
        for lineno, line in enumerate(lines, 1):
            clean = self.strip_comments(line)
            if _STRUCT_DECL.match(clean):
                if not _ALIGN_ON_STRUCT.search(clean):
                    # Report only when:
                    #   - hot-path file AND no global alignment awareness
                    #   - or non-hot-path file AND no global alignment awareness
                    # If the file already has a CACHE_LINE constant or similar,
                    # trust the developer to apply it; avoid noise.
                    if not has_global_align:
                        result.add(Finding(
                            check_id=self.CHECK_ID,
                            severity=Severity.MAJOR if is_hot_path else Severity.MINOR,
                            title=self.TITLE,
                            description=(
                                f"Struct/class declaration on line {lineno} has no "
                                "cache-line alignment annotation. On AMD Turin "
                                "(Zen 5), unaligned hot-path structs cause "
                                "partial cache-line loads and extra memory "
                                "transactions, increasing latency."
                            ),
                            file_path=str(path),
                            line=lineno,
                            suggestion=(
                                "Add `alignas(64)` before the struct keyword, e.g.:\n"
                                "    struct alignas(64) OrderRecord { ... };\n"
                                "Or define a compile-time constant:\n"
                                "    static constexpr size_t CACHE_LINE = 64;\n"
                                "    struct alignas(CACHE_LINE) OrderRecord { ... };"
                            ),
                            turin_feature=self.TURIN_FEATURE,
                        ))

        return result
