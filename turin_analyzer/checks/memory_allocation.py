"""
Check: Dynamic memory allocation (new/delete/malloc) on the hot path.

Every call to operator new / malloc:
  1. Acquires an internal heap lock (glibc ptmalloc / jemalloc)
  2. Searches free lists
  3. May call brk() / mmap() — a kernel syscall
  4. Touches cold memory pages — TLB miss on first access

On AMD Turin at 3 GHz, a malloc/free pair costs 50–500 ns depending
on heap state. A pre-trade risk engine processing 100K orders/second
cannot afford this per order.

Correct approach:
  - Pre-allocate all memory at startup
  - Use object pools / slab allocators
  - Use std::pmr::memory_resource with a fixed-size pool_resource
  - Use placement new into pre-allocated arenas
  - Use ring buffers with fixed-size slots for FIX messages and orders

Red flags in hot-path files:
  - `new` / `delete` / `malloc` / `free` / `calloc` / `realloc`
  - std::vector::push_back without reserve()
  - std::string construction inside loops
  - std::make_shared (2 allocations: control block + object)
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List

from .base import BaseCheck, CheckResult, Finding, Severity

_BAD_ALLOC = re.compile(
    r"\bnew\s+\w"             # new Foo (not placement new)
    r"|\bmalloc\s*\("
    r"|\bcalloc\s*\("
    r"|\brealloc\s*\("
    r"|\bfree\s*\(\s*\w"
    r"|\bdelete\s+\w"
    r"|\bdelete\s*\[\s*\]"
)

_PLACEMENT_NEW = re.compile(r"new\s*\(")   # placement new — OK

_VECTOR_PUSH = re.compile(r"\.(push_back|emplace_back)\s*\(")
_VECTOR_RESERVE = re.compile(r"\.reserve\s*\(")

_STRING_CTOR = re.compile(r"\bstd::string\s+\w+\s*[=(]")

_MAKE_SHARED = re.compile(r"\bstd::make_shared\s*<")

_GOOD_POOL = re.compile(
    r"std::pmr::"
    r"|pool_resource"
    r"|monotonic_buffer_resource"
    r"|ObjectPool"
    r"|MemoryPool"
    r"|SlabAllocator"
    r"|placement\s+new"
    r"|new\s*\("            # placement new
    r"|jemalloc"
    r"|tcmalloc"
    r"|mimalloc"
)

_HOT_PATH = re.compile(
    r"(pars|fix|order_?book|risk|engine|codec|handler|match|session)",
    re.IGNORECASE,
)

# Lines that are clearly inside a constructor / init function
_INIT_CONTEXT = re.compile(
    r"(init|setup|start|open|connect|ctor|constructor|main)\s*\(",
    re.IGNORECASE,
)


class MemoryAllocationCheck(BaseCheck):
    CHECK_ID      = "TURIN_ALLOC"
    TITLE         = "Dynamic memory allocation (new/malloc) on hot path"
    TURIN_FEATURE = "AMD Turin zero-allocation critical path — pre-allocated arenas"
    DESCRIPTION   = (
        "Dynamic memory allocation (new/malloc) in the critical path of a "
        "pre-trade risk engine adds 50–500 ns per allocation due to heap "
        "lock acquisition, free-list search, and potential kernel syscalls. "
        "AMD Turin cannot overcome this software overhead. The correct "
        "pattern is to pre-allocate all working memory at startup using "
        "fixed-size arenas or std::pmr::monotonic_buffer_resource, and "
        "use placement new or object pools for per-message objects."
    )

    def check_file(self, path: Path, lines: List[str]) -> CheckResult:
        result = CheckResult(check_name=self.CHECK_ID, file_path=str(path))

        is_hot = bool(_HOT_PATH.search(path.stem))
        if not is_hot:
            return result

        joined = "\n".join(lines)
        has_pool = bool(_GOOD_POOL.search(joined))

        for lineno, line in enumerate(lines, 1):
            clean = self.strip_comments(line)

            # Skip placement new
            if _PLACEMENT_NEW.search(clean):
                continue

            if _BAD_ALLOC.search(clean) and not has_pool:
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.CRITICAL,
                    title=self.TITLE,
                    description=(
                        f"Dynamic allocation on line {lineno} in a hot-path file. "
                        "Each new/malloc invocation acquires a heap lock and may "
                        "trigger a kernel mmap call. At 3 GHz, this costs "
                        "50–500 ns — AMD Turin cannot hide this latency."
                    ),
                    file_path=str(path),
                    line=lineno,
                    suggestion=(
                        "Use a pre-allocated pool:\n"
                        "  // At startup:\n"
                        "  alignas(64) static char pool[MAX_ORDERS * sizeof(Order)];\n"
                        "  std::pmr::monotonic_buffer_resource res{pool, sizeof(pool)};\n"
                        "  std::pmr::polymorphic_allocator<Order> alloc{&res};\n"
                        "  // On critical path:\n"
                        "  Order* o = alloc.allocate(1);  // no lock, ~2 ns\n"
                        "  new (o) Order{...};            // placement new"
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))

            if _VECTOR_PUSH.search(clean):
                # Check if there's a reserve nearby
                context_start = max(0, lineno - 20)
                context = lines[context_start:lineno]
                has_reserve = any(_VECTOR_RESERVE.search(l) for l in context)
                if not has_reserve:
                    result.add(Finding(
                        check_id=self.CHECK_ID,
                        severity=Severity.MAJOR,
                        title="std::vector::push_back may reallocate",
                        description=(
                            f"push_back / emplace_back on line {lineno} without "
                            "a prior reserve() may trigger heap reallocation and "
                            "memcpy of the entire buffer. Pre-reserve to max "
                            "expected size at construction time."
                        ),
                        file_path=str(path),
                        line=lineno,
                        suggestion=(
                            "Reserve at construction:\n"
                            "  std::vector<Order> orders;\n"
                            "  orders.reserve(MAX_ORDERS);  // one-time allocation\n"
                            "Or use a fixed-capacity array:\n"
                            "  std::array<Order, MAX_ORDERS> orders{};"
                        ),
                        turin_feature=self.TURIN_FEATURE,
                    ))

            if _MAKE_SHARED.search(clean):
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.MAJOR,
                    title="std::make_shared performs two allocations",
                    description=(
                        f"make_shared on line {lineno} performs a single "
                        "allocation but shared_ptr itself requires an atomic "
                        "ref-count update on every copy — avoid on hot path. "
                        "Prefer raw pointers into pre-allocated arenas or "
                        "intrusive reference counting."
                    ),
                    file_path=str(path),
                    line=lineno,
                    suggestion=(
                        "Replace shared_ptr on hot paths with pool-allocated "
                        "raw pointers or intrusive_ptr with embedded refcount."
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))

        return result
