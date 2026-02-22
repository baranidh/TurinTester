"""
Check: CPU core affinity / thread pinning.

AMD Turin has up to 192 cores across 12 CCDs. Without explicit thread
pinning the OS scheduler migrates threads between cores, causing:
  1. L1/L2 cache warmup latency after migration (~10–50 μs)
  2. Potential NUMA-crossing if migrated to a different CCD
  3. SMT contention if the scheduler co-locates two hot threads
     on the same physical core

For a pre-trade risk engine:
  - FIX parser thread → pinned to isolated core (isolcpus / taskset)
  - Order book maintenance thread → pinned to neighbouring core on
    same CCD (shares 32 MB L3 slab)
  - Risk engine thread → same CCD
  - Network interrupt threads → pinned using /proc/irq/*/smp_affinity

Good patterns: pthread_setaffinity_np, sched_setaffinity, CPU_SET,
  isolcpus kernel param references, hwloc_cpubind, cpuset.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List

from .base import BaseCheck, CheckResult, Finding, Severity

_GOOD = re.compile(
    r"pthread_setaffinity_np\s*\("
    r"|sched_setaffinity\s*\("
    r"|CPU_SET\s*\("
    r"|CPU_ZERO\s*\("
    r"|CPU_CLR\s*\("
    r"|hwloc_cpubind"
    r"|cpuset"
    r"|cpu_set_t"
    r"|isolcpus"
    r"|taskset"
    r"|rte_thread_set_affinity"    # DPDK
    r"|numa_run_on_node"
)

_THREAD_CREATE = re.compile(
    r"std::thread\s*\{"
    r"|std::thread\s+\w+"
    r"|pthread_create\s*\("
    r"|std::async\s*\("
    r"|std::jthread"
)

_HOT_PATH = re.compile(
    r"(engine|main|init|setup|thread|session|fix|order|risk)",
    re.IGNORECASE,
)


class AffinityCheck(BaseCheck):
    CHECK_ID      = "TURIN_AFFINITY"
    TITLE         = "Thread created without CPU core affinity pinning"
    TURIN_FEATURE = "AMD Turin 192-core topology — isolcpus + sched_setaffinity"
    DESCRIPTION   = (
        "AMD Turin (Zen 5) has up to 192 cores across 12 CCDs per socket. "
        "Without explicit CPU affinity, the Linux scheduler may migrate "
        "threads between CCDs, flushing L2 cache (1 MB/core) and "
        "potentially crossing NUMA boundaries. For a pre-trade risk engine, "
        "each critical thread (FIX parser, order book, risk) must be pinned "
        "to a dedicated, isolated core using pthread_setaffinity_np or "
        "sched_setaffinity, and the kernel boot line should include "
        "isolcpus= and nohz_full= for those cores."
    )

    def check_file(self, path: Path, lines: List[str]) -> CheckResult:
        result = CheckResult(check_name=self.CHECK_ID, file_path=str(path))

        joined = "\n".join(lines)
        has_affinity = bool(_GOOD.search(joined))

        if has_affinity:
            return result

        is_hot = bool(_HOT_PATH.search(path.stem))
        if not is_hot:
            return result

        # Report each thread creation without affinity
        for lineno, line in enumerate(lines, 1):
            clean = self.strip_comments(line)
            if _THREAD_CREATE.search(clean):
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.CRITICAL,
                    title=self.TITLE,
                    description=(
                        f"Thread created on line {lineno} with no CPU affinity. "
                        "On AMD Turin, unbound threads can migrate across CCDs, "
                        "causing cold L2 cache and potential NUMA crossing. "
                        "Critical-path threads must be pinned."
                    ),
                    file_path=str(path),
                    line=lineno,
                    suggestion=(
                        "Pin the thread immediately after creation:\n"
                        "  cpu_set_t cpuset;\n"
                        "  CPU_ZERO(&cpuset);\n"
                        "  CPU_SET(core_id, &cpuset);\n"
                        "  pthread_setaffinity_np(thread.native_handle(),\n"
                        "                         sizeof(cpuset), &cpuset);\n"
                        "Also set kernel boot params: isolcpus=<cores> nohz_full=<cores> rcu_nocbs=<cores>"
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))

        return result
