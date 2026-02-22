"""
Check: False sharing between thread-local data in shared structs.

AMD Turin (Zen 5) has 64-byte cache lines. When two threads write to
different fields that share a cache line, every write by one thread
invalidates the cache line in the other thread's L1/L2 cache — even
though the threads are writing to logically independent data.

This is called false sharing. In a pre-trade risk engine:
  - Thread A updates order count, Thread B updates fill count —
    if both fields are in the same cache line: false sharing.
  - The fix: pad structs so per-thread fields each occupy their own
    cache line, or use alignas(64) between them.

Detection heuristics:
  1. A struct has multiple numeric counters/flags without
     explicit padding between them.
  2. A struct mixes frequently-written fields (counts, flags)
     without alignas(64) separation.
  3. global/static arrays of objects smaller than 64 bytes
     (adjacent elements in different threads → false sharing).

Good patterns: alignas(64) on struct members, explicit char padding[],
  std::hardware_destructive_interference_size padding.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List

from .base import BaseCheck, CheckResult, Finding, Severity

_STRUCT_START = re.compile(r"^\s*(struct|class)\s+\w+")
_STRUCT_END   = re.compile(r"^\s*\}\s*;")

_COUNTER_FIELD = re.compile(
    # Matches: int total_count, std::atomic<long> reject_count, etc.
    r"(int|uint\d*_t|size_t|long|atomic|std::atomic)(\s*<[^>]+>)?\s+\w*(count|cnt|seq|idx|head|tail|flag|pos|num|total)",
    re.IGNORECASE,
)

_PADDING = re.compile(
    r"alignas\s*\(\s*6[04]\s*\)"
    r"|char\s+\w*pad\w*\s*\["
    r"|hardware_destructive_interference_size"
    r"|CACHE_LINE_PADDING"
    r"|std::hardware"
)

_HOT_PATH = re.compile(
    r"(order_?book|risk|engine|queue|ring|session|thread|worker)",
    re.IGNORECASE,
)


class FalseSharingCheck(BaseCheck):
    CHECK_ID      = "TURIN_FALSE_SHARE"
    TITLE         = "Potential false sharing — struct fields lack cache-line padding"
    TURIN_FEATURE = "AMD Turin Zen 5 MESI cache coherence — 64-byte cache line isolation"
    DESCRIPTION   = (
        "AMD Turin (Zen 5) uses the MESIF cache coherence protocol. When "
        "two CPU cores write to different variables that share a 64-byte "
        "cache line, the coherence protocol forces the line to bounce "
        "between L1 caches — costing ~50–200 ns per write. "
        "Structs used in multi-threaded hot paths must pad frequently "
        "written fields to cache-line boundaries using alignas(64) or "
        "explicit char padding[]. Particular risk: stats/counters "
        "structs, per-thread state, and producer/consumer ring buffer "
        "head/tail pointers."
    )

    def check_file(self, path: Path, lines: List[str]) -> CheckResult:
        result = CheckResult(check_name=self.CHECK_ID, file_path=str(path))

        is_hot = bool(_HOT_PATH.search(path.stem))
        if not is_hot:
            return result

        # Parse struct bodies looking for counter clusters without padding
        in_struct     = False
        struct_start  = 0
        counter_lines: List[int] = []
        has_padding   = False

        for lineno, line in enumerate(lines, 1):
            clean = self.strip_comments(line)

            if _STRUCT_START.match(clean):
                in_struct    = True
                struct_start = lineno
                counter_lines = []
                has_padding  = False
                continue

            if _STRUCT_END.match(clean) and in_struct:
                # Evaluate what we found
                if len(counter_lines) >= 2 and not has_padding:
                    result.add(Finding(
                        check_id=self.CHECK_ID,
                        severity=Severity.MAJOR,
                        title=self.TITLE,
                        description=(
                            f"Struct starting on line {struct_start} has "
                            f"{len(counter_lines)} counter/flag fields "
                            f"(lines {counter_lines}) without cache-line "
                            "padding. If threads write to different fields, "
                            "false sharing will serialise their L1 caches."
                        ),
                        file_path=str(path),
                        line=struct_start,
                        suggestion=(
                            "Separate hot fields with cache-line padding:\n"
                            "  struct alignas(64) Stats {\n"
                            "      std::atomic<uint64_t> orders_in{0};\n"
                            "      char _pad0[64 - sizeof(std::atomic<uint64_t>)];\n"
                            "      std::atomic<uint64_t> orders_out{0};\n"
                            "      char _pad1[64 - sizeof(std::atomic<uint64_t>)];\n"
                            "  };\n"
                            "Or use std::hardware_destructive_interference_size."
                        ),
                        turin_feature=self.TURIN_FEATURE,
                    ))
                in_struct = False
                continue

            if in_struct:
                if _COUNTER_FIELD.search(clean):
                    counter_lines.append(lineno)
                if _PADDING.search(clean):
                    has_padding = True

        return result
