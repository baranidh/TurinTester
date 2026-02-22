"""
Check: Huge page usage (2 MB / 1 GB pages) for TLB pressure reduction.

AMD Turin (Zen 5) has:
  - 64-entry L1 DTLB (4K pages) / 32-entry L1 DTLB (2M pages)
  - 2048-entry L2 TLB (unified)

A pre-trade risk engine touching gigabytes of order-book and risk data
will cause significant TLB misses when using standard 4 KB pages.
Switching to 2 MB transparent huge pages (THP) or explicit mmap
MAP_HUGETLB reduces TLB misses by 512x for the same working set.

Good patterns to look for:
  mmap with MAP_HUGETLB, madvise(MADV_HUGEPAGE), posix_memalign with
  huge sizes, explicit 2MB/1GB allocations, HugePageAllocator,
  std::pmr with huge-page backing resource.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List

from .base import BaseCheck, CheckResult, Finding, Severity

# Signals that huge pages ARE being used
_GOOD = re.compile(
    r"MAP_HUGETLB"
    r"|MAP_HUGE_2MB"
    r"|MAP_HUGE_1GB"
    r"|MADV_HUGEPAGE"
    r"|madvise\s*\(.*HUGEPAGE"
    r"|HUGE_PAGE"
    r"|HugePage"
    r"|hugepage"
    r"|huge_page"
    r"|posix_memalign.*2\s*\*\s*1024\s*\*\s*1024"   # 2MB alignment
    r"|1\s*<<\s*21"                                   # 2^21 = 2MB
    r"|2097152"                                        # 2MB literal
    r"|1073741824"                                     # 1GB literal
    r"|sys/mman\.h",                                   # mman.h is a pre-condition
)

# Patterns indicating large allocations where huge pages would help
_LARGE_ALLOC = re.compile(
    r"new\s+\w+\s*\["                           # array new
    r"|malloc\s*\("
    r"|calloc\s*\("
    r"|std::vector"
    r"|std::deque"
    r"|std::unordered_map"
)

_MMAP = re.compile(r"\bmmap\b")


class HugePagesCheck(BaseCheck):
    CHECK_ID      = "TURIN_HUGEPAGES"
    TITLE         = "Large allocations not using huge pages (TLB pressure)"
    TURIN_FEATURE = "AMD Turin Zen 5 TLB hierarchy — 2 MB / 1 GB huge pages"
    DESCRIPTION   = (
        "AMD Turin's Zen 5 TLB has 64 L1 DTLB entries for 4K pages and "
        "only 32 for 2M pages, but the 2M coverage is 512x larger. "
        "Large working sets (order books, risk arrays, FIX buffers) "
        "exhaust the 4K TLB instantly, causing page-walk latency on "
        "every cache miss. Use mmap(MAP_HUGETLB|MAP_HUGE_2MB) or "
        "madvise(addr, len, MADV_HUGEPAGE) for all large allocations."
    )

    def check_file(self, path: Path, lines: List[str]) -> CheckResult:
        result = CheckResult(check_name=self.CHECK_ID, file_path=str(path))

        joined = "\n".join(lines)
        has_huge = bool(_GOOD.search(joined))

        if has_huge:
            return result  # file already uses huge pages somewhere — pass

        # Flag each large allocation site
        for lineno, line in enumerate(lines, 1):
            clean = self.strip_comments(line)
            if _LARGE_ALLOC.search(clean) or _MMAP.search(clean):
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.MAJOR,
                    title=self.TITLE,
                    description=(
                        f"Large allocation on line {lineno} does not use "
                        "huge pages. On AMD Turin/Zen 5, 4 KB page allocations "
                        "for large working sets cause severe TLB pressure, "
                        "adding ~50–200 ns per TLB-miss page walk."
                    ),
                    file_path=str(path),
                    line=lineno,
                    suggestion=(
                        "Replace with huge-page backed allocation:\n"
                        "  void* p = mmap(nullptr, size,\n"
                        "                 PROT_READ|PROT_WRITE,\n"
                        "                 MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB|MAP_HUGE_2MB,\n"
                        "                 -1, 0);\n"
                        "Or enable transparent huge pages:\n"
                        "  madvise(ptr, size, MADV_HUGEPAGE);\n"
                        "For std::vector, use a custom PMR allocator backed by huge pages."
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))

        return result
