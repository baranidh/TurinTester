"""
Check: Software prefetching for AMD Turin's memory hierarchy.

AMD Turin (Zen 5) memory latency:
  L1 cache:   4 cycles  (~1.3 ns at 3 GHz)
  L2 cache:  12 cycles  (~4   ns)
  L3 cache:  40 cycles  (~13  ns)
  DRAM:     ~300 cycles (~100 ns)

The hardware prefetcher handles sequential access patterns well, but
random or strided patterns (e.g., hash table lookups for order book,
symbol lookup in risk tables) require explicit software prefetches.

For a pre-trade risk engine:
  - Before looking up position limits: prefetch the limit table entry
  - Before processing the next FIX message: prefetch it into L1
  - Order book price level lookup: prefetch the level struct
  - Binary protocol encode: prefetch destination buffer

Good patterns: __builtin_prefetch, _mm_prefetch,
  _mm_prefetch with _MM_HINT_T0/T1/T2/NTA, prefetch pipelines.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List

from .base import BaseCheck, CheckResult, Finding, Severity

_GOOD = re.compile(
    r"__builtin_prefetch\s*\("
    r"|_mm_prefetch\s*\("
    r"|_MM_HINT_T0"
    r"|_MM_HINT_T1"
    r"|_MM_HINT_NTA"
    r"|prefetch_range\s*\("
    r"|__dcbt\s*\("           # PowerPC (might be in ported code)
)

# Patterns that suggest data access where prefetch would help
_MAP_LOOKUP = re.compile(
    r"\.(find|at|count|operator\[\])\s*\("   # std container lookup
    r"|\bmap\b|\bunordered_map\b|\bhash_map\b"
)

_ARRAY_ACCESS = re.compile(
    r"\w+\s*\[\s*\w+\s*\]"  # array[index]
)

_HOT_PATH = re.compile(
    r"(pars|fix|order_?book|risk|engine|codec|handler|match|lookup|table)",
    re.IGNORECASE,
)

_LOOP = re.compile(r"^\s*(for|while)\s*\(")


class PrefetchCheck(BaseCheck):
    CHECK_ID      = "TURIN_PREFETCH"
    TITLE         = "No software prefetch instructions in data-intensive loops"
    TURIN_FEATURE = "AMD Turin Zen 5 hardware+software prefetcher — 300 ns DRAM latency hiding"
    DESCRIPTION   = (
        "AMD Turin (Zen 5) DRAM latency is ~100–150 ns (300 cycles at 3 GHz). "
        "The hardware prefetcher covers sequential streams but misses "
        "irregular access patterns in hash lookups (risk tables), pointer "
        "chasing (order book linked levels), or strided access. "
        "Software prefetch (__builtin_prefetch / _mm_prefetch) issued "
        "~100–200 cycles before the load can fully hide DRAM latency. "
        "For a risk engine processing thousands of orders/second, the "
        "difference between a cache hit and DRAM access is 2–10 μs."
    )

    def check_file(self, path: Path, lines: List[str]) -> CheckResult:
        result = CheckResult(check_name=self.CHECK_ID, file_path=str(path))

        joined = "\n".join(lines)
        has_prefetch = bool(_GOOD.search(joined))
        is_hot = bool(_HOT_PATH.search(path.stem))

        if has_prefetch or not is_hot:
            return result

        # Look for loops with map lookups or random array accesses
        in_loop = False
        for lineno, line in enumerate(lines, 1):
            clean = self.strip_comments(line)
            if _LOOP.match(clean):
                in_loop = True
            if in_loop and _MAP_LOOKUP.search(clean):
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.MAJOR,
                    title=self.TITLE,
                    description=(
                        f"Container lookup inside loop on line {lineno} with "
                        "no prefetch. Each cache miss costs ~100 ns on Turin. "
                        "Prefetch the next iteration's data while processing "
                        "the current one to hide DRAM latency."
                    ),
                    file_path=str(path),
                    line=lineno,
                    suggestion=(
                        "Add software prefetch N iterations ahead:\n"
                        "  for (int i = 0; i < N; ++i) {\n"
                        "      __builtin_prefetch(&table[keys[i+8]], 0, 1);\n"
                        "      // process table[keys[i]]\n"
                        "  }\n"
                        "Use hint 0 (read), 1 (L2 temporal) for most cases.\n"
                        "Use _MM_HINT_NTA for streaming data not reused."
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))
                in_loop = False  # report once per loop

        return result
