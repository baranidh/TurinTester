# Turin Latency Analyzer

Static analysis tool for C++ pre-trade risk engines.
Detects code patterns that fail to leverage **AMD Turin (EPYC 9005 / Zen 5)**
architectural features for low-latency execution.

Integrates with **GitLab Merge Request pipelines** via the Code Quality report
format, producing inline annotations on changed files.

---

## AMD Turin (EPYC 9005 / Zen 5) Architecture Highlights

Understanding these features is the foundation of the analyzer.

### 1. Zen 5 Core Microarchitecture

| Feature | Zen 4 (Turin predecessor) | Zen 5 (Turin) |
|---------|--------------------------|----------------|
| AVX-512 execution width | 256-bit (folded) | **512-bit native** |
| L1 I-cache | 32 KB | 32 KB |
| L1 D-cache | 32 KB | **48 KB** |
| L2 cache | 1 MB | 1 MB |
| Branch predictor | Enhanced | **Improved BTB + indirect** |
| Integer ALU width | Wider vs Zen 3 | Wider still |
| IPC improvement vs Zen 4 | — | **~16% more IPC** |

**Key implication:** AVX-512 operations that cost 2 cycles on Zen 4 (due to
folding) cost 1 cycle on Zen 5. Code using `_mm512_*` intrinsics is now
economically viable — this is a differentiating feature of Turin.

### 2. Cache Hierarchy (Zen 5 per-core)

```
L1 D-cache:  48 KB,  4-cycle latency   — 64-byte cache lines
L2 cache:     1 MB, 12-cycle latency   — 64-byte cache lines
L3 cache:    32 MB per CCD, ~40-cycle latency (shared across cores in a CCD)
DRAM:        ~100-150 ns (~300-450 cycles at 3 GHz)
```

**Implication for risk engines:**
- Order book price levels must fit in L1/L2 → `alignas(64)` structs
- Risk limit tables accessed per-order must be L3-resident → NUMA-local
- FIX message buffers → 2 MB huge pages to avoid TLB misses

### 3. Full-Width AVX-512 (Zen 5 breakthrough)

AMD Turin is the **first AMD architecture** with full-width 512-bit AVX-512
execution units. Available extensions:

| Extension | Use in risk engine |
|-----------|-------------------|
| AVX-512F  | 16x float or 8x double operations |
| AVX-512BW | **64-byte compare in 1 cycle** — FIX delimiter scanning |
| AVX-512VL | 128/256-bit variants of AVX-512 ops |
| AVX-512VNNI | Integer dot products — position aggregation |
| AVX-512VBMI | Byte shuffle — protocol conversion |

**Critical example — FIX parsing:**
```cpp
// SCALAR: ~64 cycles to scan 64 bytes for '=' delimiter
while (i < len && buf[i] != '=') ++i;

// AVX-512: ~1 cycle for the same 64 bytes
__m512i chunk  = _mm512_loadu_si512(buf + i);
__m512i needle = _mm512_set1_epi8('=');
uint64_t mask  = _mm512_cmpeq_epi8_mask(chunk, needle);
int pos        = __builtin_ctzll(mask);
```

64x throughput improvement for FIX field scanning.

### 4. NUMA Topology (Multi-CCD / Multi-Socket)

```
Socket 0 (NUMA node 0)          Socket 1 (NUMA node 1)
  CCD 0  CCD 1  CCD 2  CCD 3     CCD 6  CCD 7 ...
  └──────────────────────┘         └──────────────┘
  32 MB L3 per CCD group           32 MB L3 per CCD group
  ↓                                ↓
  12-ch DDR5 (288 GB/s)           12-ch DDR5 (288 GB/s)
```

| Access type | Latency |
|-------------|---------|
| L1 cache hit | ~1.3 ns |
| L2 cache hit | ~4 ns |
| L3 cache hit (same CCD) | ~13 ns |
| DRAM local NUMA node | ~100 ns |
| DRAM remote NUMA node | **~160-200 ns** |

Cross-NUMA access adds **60-100 ns** per cache line. For a risk engine, this
means order book memory and the processing thread MUST be on the same NUMA node.

### 5. Memory Subsystem

- **12-channel DDR5** per socket — 576 GB/s aggregate bandwidth
- **Sub-NUMA Clustering (SNC)** — each pair of CCDs forms a sub-NUMA domain
  for finer-grained locality control
- **CXL 2.0** — for persistent memory tiering (not on critical path)
- **Huge pages:** 2 MB and 1 GB supported via Linux `MAP_HUGETLB`

**TLB capacity:**
```
L1 DTLB: 64 entries (4K pages) / 32 entries (2M pages)
L2 TLB:  2048 entries (unified)
```

Using 4 KB pages for a 512 MB order book requires 131,072 TLB entries —
far exceeding L2 TLB capacity. Every cache miss also incurs a 5-level page
table walk. **2 MB huge pages reduce this to 256 entries** — fully fitting
in L2 TLB.

### 6. Branch Predictor (Zen 5)

- Improved Branch Target Buffer (BTB) — more entries, better aliasing
- Better indirect branch predictor — benefits virtual dispatch and jump tables
- **Static hints via `[[likely]]`/`[[unlikely]]`** (C++20) allow the compiler
  to arrange basic blocks for minimum taken-branch penalty

For a FIX parser where 99.9% of messages are valid:
```cpp
if (checksum_valid()) [[likely]] {
    process_message();
} else [[unlikely]] {
    log_error();
}
```

### 7. Hardware Prefetcher

- **Stride prefetcher:** detects regular stride patterns automatically
- **Stream prefetcher:** handles sequential access
- **Software prefetch required for:** hash table lookups, pointer chasing,
  random access in risk/position tables

```cpp
// Software prefetch 8 iterations ahead — hides 300-cycle DRAM latency
for (int i = 0; i < N; ++i) {
    __builtin_prefetch(&risk_table[symbols[i + 8]], 0, 1);
    check_risk(risk_table[symbols[i]]);
}
```

### 8. Atomic Operations & Synchronisation

| Primitive | Cost on Zen 5 |
|-----------|--------------|
| `memory_order_relaxed` load/store | ~1-2 cycles |
| `memory_order_acquire/release` | ~1-4 cycles (no MFENCE) |
| `memory_order_seq_cst` store | **~30-100 cycles (MFENCE)** |
| `std::mutex::lock()` uncontended | ~50-200 ns |
| `std::mutex::lock()` contended | **microseconds** |
| `_mm_pause()` in spinloop | Reduces bus pressure, ~5 ns |
| `MWAITX` | Efficient OS-free sleep |

### 9. Essential Compiler Flags for Turin

```bash
-march=znver5          # Full Zen 5 ISA (AVX-512, CLDEMOTE, MOVDIRI)
-O3                    # Full optimisation
-mavx512f              # AVX-512 Foundation
-mavx512bw             # Byte/Word (FIX scanning)
-mavx512vl             # Vector Length extensions
-ffast-math            # Allow SIMD FP reassociation
-funroll-loops         # Loop unrolling
-flto=auto             # Link-Time Optimisation
-fprofile-use          # Profile-Guided Optimisation (after training run)
-std=c++20             # [[likely]], [[unlikely]], std::hardware_*_interference_size
```

### 10. OS Configuration for Sub-Microsecond Latency

```bash
# Kernel boot parameters
isolcpus=2-15          # Isolate cores 2-15 from scheduler
nohz_full=2-15         # Disable timer interrupts on isolated cores
rcu_nocbs=2-15         # Move RCU callbacks off isolated cores
intel_idle.max_cstate=0 # (or processor.max_cstate=0) prevent C-state

# IRQ affinity: pin NIC interrupts to cores 0-1
echo 3 > /proc/irq/<NIC_IRQ>/smp_affinity

# Huge pages: pre-allocate 2 MB pages
echo 1024 > /proc/sys/vm/nr_hugepages

# NUMA: disable automatic memory balancing
echo 0 > /proc/sys/kernel/numa_balancing
```

---

## Tool Architecture

```
TurinTester/
├── turin_check.py              # CLI entry point
├── .gitlab-ci.yml              # GitLab MR pipeline integration
├── requirements.txt
├── turin_analyzer/
│   ├── analyzer.py             # Orchestration engine
│   ├── reporter.py             # Output formatters
│   └── checks/
│       ├── alignment.py        # TURIN_ALIGN   — 64-byte alignas()
│       ├── huge_pages.py       # TURIN_HUGEPAGES — MAP_HUGETLB / MADV_HUGEPAGE
│       ├── numa.py             # TURIN_NUMA    — libnuma / mbind
│       ├── simd.py             # TURIN_SIMD    — AVX-512 / AVX2 intrinsics
│       ├── affinity.py         # TURIN_AFFINITY — pthread_setaffinity_np
│       ├── branch_prediction.py# TURIN_BRANCH  — [[likely]] / __builtin_expect
│       ├── prefetch.py         # TURIN_PREFETCH — __builtin_prefetch
│       ├── lock_free.py        # TURIN_LOCKFREE — std::atomic / no mutex
│       ├── memory_allocation.py# TURIN_ALLOC   — no new/malloc on hot path
│       ├── false_sharing.py    # TURIN_FALSE_SHARE — cache-line padding
│       └── compiler_flags.py   # TURIN_CFLAGS  — -march=znver5 -O3 -flto
├── sample_cpp/
│   ├── fix_parser_bad.hpp      # Intentionally unoptimised — triggers all checks
│   ├── fix_parser_good.hpp     # Optimised reference implementation
│   ├── order_book_bad.hpp      # Unoptimised order book
│   ├── order_book_good.hpp     # AVX-512 + NUMA + lock-free order book
│   ├── risk_engine_bad.cpp     # Full bad example
│   ├── CMakeLists_bad.txt      # Missing -march=znver5 / -O0
│   └── CMakeLists_good.txt     # Full Turin compiler flags
└── tests/
    └── test_checks.py          # 46 unit tests (pytest)
```

---

## Checks Reference

| Check ID | Severity | What it detects | Turin feature |
|----------|----------|-----------------|---------------|
| `TURIN_ALIGN` | MAJOR | Structs without `alignas(64)` | 64-byte cache lines |
| `TURIN_HUGEPAGES` | MAJOR | Large allocs without `MAP_HUGETLB` | TLB: 2 MB pages |
| `TURIN_NUMA` | MAJOR | Allocation without libnuma on hot-path files | Multi-CCD NUMA |
| `TURIN_SIMD` | CRITICAL/MAJOR | Scalar byte loops, no `_mm512_*` | Native AVX-512 |
| `TURIN_AFFINITY` | CRITICAL | Threads without `pthread_setaffinity_np` | 192-core topology |
| `TURIN_BRANCH` | MINOR | Branches without `[[likely]]`/`__builtin_expect` | Zen 5 BTB |
| `TURIN_PREFETCH` | MAJOR | Map lookups in loops without `__builtin_prefetch` | 300-cycle DRAM |
| `TURIN_LOCKFREE` | CRITICAL | `std::mutex` / `condition_variable` on hot path | Sub-ns atomics |
| `TURIN_ALLOC` | CRITICAL | `new`/`malloc` on hot path | Zero-alloc path |
| `TURIN_FALSE_SHARE` | MAJOR | Counters without cache-line padding | MESI coherence |
| `TURIN_CFLAGS` | CRITICAL | Missing `-march=znver5`, `-O3`, `-flto` | Full ISA |

---

## Usage

### Local development

```bash
# Check all C++ files in src/
python3 turin_check.py src/

# Check only specific files
python3 turin_check.py src/fix_parser.cpp src/order_book.hpp

# GitLab Code Quality JSON output
python3 turin_check.py src/ --format gitlab --output gl-code-quality.json

# Full JSON report
python3 turin_check.py src/ --format json --output report.json

# Markdown summary
python3 turin_check.py src/ --format markdown --output summary.md

# Only run SIMD and NUMA checks
python3 turin_check.py src/ --checks TURIN_SIMD TURIN_NUMA

# List all checks
python3 turin_check.py --list-checks

# Exit 0 even if findings exist (useful for non-blocking report)
python3 turin_check.py src/ --fail-on none
```

### GitLab MR Pipeline

Add `.gitlab-ci.yml` from this repository to your project root.
The pipeline:

1. Runs on every MR — analyses only the **changed C++ files**
2. Uploads `gl-code-quality.json` as a Code Quality artifact
3. GitLab renders findings as **inline annotations on the MR diff**
4. Pipeline **fails** if any CRITICAL or MAJOR finding exists

```yaml
# In your .gitlab-ci.yml
include:
  - project: 'your-group/TurinTester'
    file: '.gitlab-ci.yml'
```

Or copy `.gitlab-ci.yml` directly into your project.

---

## Running the Test Suite

```bash
pip install pytest
python3 -m pytest tests/ -v
```

Expected: **46 passed**.

---

## Quick Demo

```bash
# See the tool catch all bad patterns in sample files
python3 turin_check.py sample_cpp/fix_parser_bad.hpp sample_cpp/order_book_bad.hpp sample_cpp/risk_engine_bad.cpp sample_cpp/CMakeLists_bad.txt

# Confirm good patterns pass the SIMD and compiler-flags checks
python3 turin_check.py --checks TURIN_SIMD TURIN_CFLAGS sample_cpp/fix_parser_good.hpp sample_cpp/CMakeLists_good.txt
```

---

## Extending the Tool

Each check is a standalone Python class in `turin_analyzer/checks/`. To add a
new check:

1. Create `turin_analyzer/checks/my_check.py` subclassing `BaseCheck`
2. Set `CHECK_ID`, `TITLE`, `TURIN_FEATURE`, `DESCRIPTION`
3. Implement `check_file(path, lines) -> CheckResult`
4. Add to `turin_analyzer/checks/__init__.py` `ALL_CHECKS` list
5. Add unit tests in `tests/test_checks.py`

---

## References

- AMD EPYC 9005 (Turin) Product Page
- AMD Software Optimization Guide for AMD EPYC 9005 Processors
- [GCC AVX-512 Intrinsics](https://gcc.gnu.org/onlinedocs/gcc/x86-Options.html)
- [Intel Intrinsics Guide](https://www.intel.com/content/www/us/en/docs/intrinsics-guide/)
- [Linux NUMA API (libnuma)](https://linux.die.net/man/3/numa)
- [GitLab Code Quality Report Format](https://docs.gitlab.com/ee/ci/testing/code_quality.html)
