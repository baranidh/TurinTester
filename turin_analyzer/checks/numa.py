"""
Check: NUMA-aware memory allocation and thread placement.

AMD Turin is a multi-CCD, optionally multi-socket architecture:
  - Up to 12 CCDs per socket (Zen 5)
  - Each socket is a separate NUMA node
  - Within a socket, each pair of CCDs shares a sub-NUMA cluster (SNC)
  - Cross-NUMA memory access: ~60–100 ns extra latency vs local NUMA

For a pre-trade risk engine:
  - Order book arrays must be allocated on the NUMA node where the
    processing thread runs.
  - FIX parsing threads, order book threads, and risk threads that
    communicate should be pinned to the same NUMA node.
  - Queues between threads across NUMA nodes introduce avoidable latency.

Good patterns:
  numa_alloc_onnode(), numa_alloc_local(), mbind(), set_mempolicy(),
  numactl hints in deployment scripts, NUMA_NO_NODE checks,
  libnuma usage, hwloc, or at least NUMA_INTERLEAVE with awareness.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List

from .base import BaseCheck, CheckResult, Finding, Severity

_GOOD_INCLUDE = re.compile(
    r'#\s*include\s*[<"]\s*(numa\.h|numaif\.h|hwloc\.h)\s*[>"]'
)

_GOOD_CALL = re.compile(
    r"numa_alloc_onnode\s*\("
    r"|numa_alloc_local\s*\("
    r"|numa_run_on_node\s*\("
    r"|mbind\s*\("
    r"|set_mempolicy\s*\("
    r"|get_mempolicy\s*\("
    r"|numa_set_preferred\s*\("
    r"|hwloc_membind"
    r"|hwloc_cpubind"
    r"|NUMA_NO_NODE"
    r"|numa_node_of_cpu\s*\("
    r"|numa_distance\s*\("
)

_ALLOCATION = re.compile(
    r"\bnew\b\s"
    r"|\bmalloc\s*\("
    r"|\bcalloc\s*\("
    r"|\bposix_memalign\s*\("
    r"|\bmmap\s*\("
    r"|std::vector"
    r"|std::make_shared"
    r"|std::make_unique"
)

_HOT_PATH = re.compile(
    r"(order_?book|risk|fix_?pars|engine|handler|session|queue|ring)",
    re.IGNORECASE,
)


class NumaCheck(BaseCheck):
    CHECK_ID      = "TURIN_NUMA"
    TITLE         = "Memory allocation not NUMA-aware"
    TURIN_FEATURE = "AMD Turin multi-CCD NUMA topology (libnuma / mbind)"
    DESCRIPTION   = (
        "AMD Turin supports up to 12 CCDs per socket. Each socket (and "
        "with SNC enabled, each pair of CCDs) is a distinct NUMA node. "
        "Allocating memory without NUMA affinity means cache-line fills "
        "may cross NUMA boundaries, adding 60–100 ns of latency. "
        "Use libnuma (numa_alloc_onnode / numa_run_on_node) or hwloc to "
        "pin threads and their memory to the same NUMA node."
    )

    def check_file(self, path: Path, lines: List[str]) -> CheckResult:
        result = CheckResult(check_name=self.CHECK_ID, file_path=str(path))

        joined = "\n".join(lines)
        has_numa = bool(_GOOD_INCLUDE.search(joined) or _GOOD_CALL.search(joined))
        if has_numa:
            return result  # NUMA awareness already present

        is_hot = bool(_HOT_PATH.search(path.stem))
        if not is_hot:
            return result  # Only report on hot-path files

        for lineno, line in enumerate(lines, 1):
            clean = self.strip_comments(line)
            if _ALLOCATION.search(clean):
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.MAJOR,
                    title=self.TITLE,
                    description=(
                        f"Memory allocation on line {lineno} is not NUMA-aware. "
                        "AMD Turin's multi-CCD topology means cross-NUMA access "
                        "adds 60–100 ns latency. For a pre-trade risk engine "
                        "this is unacceptable on the critical path."
                    ),
                    file_path=str(path),
                    line=lineno,
                    suggestion=(
                        "Use libnuma for NUMA-local allocation:\n"
                        "  #include <numa.h>\n"
                        "  void* buf = numa_alloc_onnode(size, numa_node_of_cpu(sched_getcpu()));\n"
                        "Pin the thread first:\n"
                        "  numa_run_on_node(node_id);\n"
                        "Or use hwloc for portable topology-aware placement."
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))

        return result
