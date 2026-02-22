"""
Check: Lock-free / wait-free patterns in hot paths.

AMD Turin (Zen 5) supports:
  - TSX (Transactional Synchronisation Extensions) — hardware transactional
    memory via XBEGIN/XEND (on server-class SKUs)
  - LOCK-prefixed atomic instructions with single-cycle CAS on cache-resident
    lines
  - WFE (Wait-For-Event) style spinning with MWAITX / MONITORX

For a pre-trade risk engine:
  - std::mutex in a hot path adds 50–200 ns minimum (OS context switch
    if contended)
  - A cache-local spinlock with PAUSE adds ~5 ns
  - A lock-free ring buffer (SPSC / MPSC) adds ~2 ns
  - std::atomic with memory_order_relaxed for per-thread counters: <1 ns

Red flags:
  - std::mutex in hot-path files
  - std::unique_lock / std::lock_guard in parsing / order-book loops
  - Condition variables on the critical path

Good patterns:
  - std::atomic + memory_order_relaxed/acquire/release (NOT seq_cst)
  - SPSC / MPSC ring buffers
  - _mm_pause() in busy-wait loops (PAUSE instruction)
  - MWAITX / MONITORX for efficient spinning
  - seqlock pattern
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List

from .base import BaseCheck, CheckResult, Finding, Severity

_BAD_MUTEX = re.compile(
    r"\bstd::mutex\b"
    r"|\bstd::recursive_mutex\b"
    r"|\bpthread_mutex_t\b"
    r"|\bpthread_mutex_lock\s*\("
    r"|\bpthread_rwlock_t\b"
)

_BAD_LOCK_GUARD = re.compile(
    r"\bstd::unique_lock\b"
    r"|\bstd::lock_guard\b"
    r"|\bstd::scoped_lock\b"
)

_BAD_CONDVAR = re.compile(
    r"\bstd::condition_variable\b"
    r"|\bpthread_cond_wait\s*\("
)

_GOOD_LOCKFREE = re.compile(
    r"\bstd::atomic\b"
    r"|\bstd::atomic_flag\b"
    r"|memory_order_relaxed"
    r"|memory_order_acquire"
    r"|memory_order_release"
    r"|\b_mm_pause\s*\("
    r"|MWAITX"
    r"|MONITORX"
    r"|__sync_val_compare_and_swap"
    r"|compare_exchange_strong"
    r"|compare_exchange_weak"
    r"|fetch_add|fetch_sub|fetch_or|fetch_and"
)

_SEQ_CST = re.compile(r"memory_order_seq_cst")

_HOT_PATH = re.compile(
    r"(pars|fix|order_?book|risk|engine|codec|handler|match|queue|ring|session)",
    re.IGNORECASE,
)


class LockFreeCheck(BaseCheck):
    CHECK_ID      = "TURIN_LOCKFREE"
    TITLE         = "Mutex / blocking synchronisation on hot path"
    TURIN_FEATURE = "AMD Turin Zen 5 cache-coherent atomic ops + PAUSE/MWAITX"
    DESCRIPTION   = (
        "AMD Turin (Zen 5) delivers sub-nanosecond cache-resident atomic "
        "CAS operations, but std::mutex introduces OS scheduling overhead "
        "(50–200 ns when uncontended, microseconds when contended). "
        "For a pre-trade risk engine:\n"
        "  • Replace hot-path mutexes with lock-free ring buffers or\n"
        "    seqlock patterns using std::atomic.\n"
        "  • Use memory_order_acquire/release rather than the default\n"
        "    seq_cst (which emits a full MFENCE on x86-64).\n"
        "  • Spin with _mm_pause() to reduce bus lock contention and\n"
        "    enable Zen 5's power-aware spinning (MWAITX)."
    )

    def check_file(self, path: Path, lines: List[str]) -> CheckResult:
        result = CheckResult(check_name=self.CHECK_ID, file_path=str(path))

        is_hot = bool(_HOT_PATH.search(path.stem))
        if not is_hot:
            return result

        joined = "\n".join(lines)
        has_lockfree = bool(_GOOD_LOCKFREE.search(joined))

        for lineno, line in enumerate(lines, 1):
            clean = self.strip_comments(line)

            if _BAD_MUTEX.search(clean):
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.CRITICAL,
                    title=self.TITLE,
                    description=(
                        f"std::mutex / pthread_mutex on line {lineno} in a "
                        "hot-path file. Mutex acquisition costs 50–200 ns "
                        "uncontended and microseconds when contended. "
                        "AMD Turin can execute hundreds of risk checks in "
                        "that time."
                    ),
                    file_path=str(path),
                    line=lineno,
                    suggestion=(
                        "Replace with lock-free pattern:\n"
                        "  // SPSC ring buffer (zero-lock for single producer/consumer)\n"
                        "  std::atomic<uint64_t> head{0}, tail{0};\n"
                        "  // Or seqlock for read-mostly risk limits:\n"
                        "  std::atomic<uint64_t> seq{0};  // even=stable, odd=writing\n"
                        "  // Spin with pause to reduce bus traffic:\n"
                        "  while (busy.load(memory_order_acquire)) _mm_pause();"
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))

            if _BAD_CONDVAR.search(clean):
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.CRITICAL,
                    title="condition_variable on critical path",
                    description=(
                        f"condition_variable on line {lineno} involves kernel "
                        "syscall (futex). On AMD Turin a busy-wait with "
                        "_mm_pause() + MWAITX achieves sub-microsecond "
                        "wake latency without OS involvement."
                    ),
                    file_path=str(path),
                    line=lineno,
                    suggestion=(
                        "Replace with a busy-wait loop using MWAITX:\n"
                        "  // Spin for up to N cycles then yield\n"
                        "  while (!flag.load(memory_order_acquire)) {\n"
                        "      for (int i = 0; i < 100; ++i) _mm_pause();\n"
                        "  }"
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))

            if _SEQ_CST.search(clean):
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.MINOR,
                    title="memory_order_seq_cst emits unnecessary MFENCE",
                    description=(
                        f"memory_order_seq_cst on line {lineno} generates a "
                        "full MFENCE barrier on x86-64, serialising the "
                        "store buffer. Use memory_order_release for stores "
                        "and memory_order_acquire for loads unless total "
                        "ordering is truly required."
                    ),
                    file_path=str(path),
                    line=lineno,
                    suggestion=(
                        "Use weaker but correct ordering:\n"
                        "  flag.store(true, std::memory_order_release);   // writer\n"
                        "  if (flag.load(std::memory_order_acquire)) ...  // reader"
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))

        return result
