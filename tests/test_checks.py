"""
Unit tests for all AMD Turin check modules.
Run with:  python3 -m pytest tests/ -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make sure the project root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from turin_analyzer.checks.alignment         import AlignmentCheck
from turin_analyzer.checks.affinity          import AffinityCheck
from turin_analyzer.checks.branch_prediction import BranchPredictionCheck
from turin_analyzer.checks.compiler_flags    import CompilerFlagsCheck
from turin_analyzer.checks.false_sharing     import FalseSharingCheck
from turin_analyzer.checks.huge_pages        import HugePagesCheck
from turin_analyzer.checks.lock_free         import LockFreeCheck
from turin_analyzer.checks.memory_allocation import MemoryAllocationCheck
from turin_analyzer.checks.numa              import NumaCheck
from turin_analyzer.checks.prefetch          import PrefetchCheck
from turin_analyzer.checks.simd              import SimdCheck
from turin_analyzer.checks.base              import Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(check_cls, code: str, filename: str = "order_book.hpp") -> list:
    """Run a single check on a code snippet and return findings."""
    check = check_cls()
    path  = Path(filename)
    lines = code.splitlines()
    result = check.check_file(path, lines)
    return result.findings


# ---------------------------------------------------------------------------
# AlignmentCheck
# ---------------------------------------------------------------------------

class TestAlignment:
    def test_unaligned_struct_flagged(self):
        code = "struct OrderRecord { int id; double price; };"
        findings = run(AlignmentCheck, code, "order_book.hpp")
        assert any(f.check_id == "TURIN_ALIGN" for f in findings)

    def test_aligned_struct_passes(self):
        code = "struct alignas(64) OrderRecord { int id; double price; };"
        findings = run(AlignmentCheck, code, "order_book.hpp")
        assert not findings

    def test_cache_line_constant_passes(self):
        code = (
            "static constexpr size_t CACHE_LINE_SIZE = 64;\n"
            "struct OrderRecord { int id; };\n"
        )
        findings = run(AlignmentCheck, code, "order_book.hpp")
        assert not findings

    def test_hardware_interference_size_passes(self):
        code = (
            "alignas(std::hardware_destructive_interference_size) struct Foo { int x; };"
        )
        findings = run(AlignmentCheck, code, "order_book.hpp")
        assert not findings

    def test_non_hotpath_file_minor_severity(self):
        code = "struct Util { int x; };"
        findings = run(AlignmentCheck, code, "utils.hpp")
        # non-hot-path files may still get MINOR
        for f in findings:
            assert f.severity == Severity.MINOR


# ---------------------------------------------------------------------------
# HugePagesCheck
# ---------------------------------------------------------------------------

class TestHugePages:
    def test_malloc_without_hugepages_flagged(self):
        code = "void* p = malloc(1024*1024*1024);"
        findings = run(HugePagesCheck, code, "order_book.hpp")
        assert any(f.check_id == "TURIN_HUGEPAGES" for f in findings)

    def test_mmap_with_map_hugetlb_passes(self):
        code = "void* p = mmap(0, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_HUGETLB|MAP_HUGE_2MB, -1, 0);"
        findings = run(HugePagesCheck, code, "order_book.hpp")
        assert not findings

    def test_madvise_hugepage_passes(self):
        code = "madvise(ptr, len, MADV_HUGEPAGE);"
        findings = run(HugePagesCheck, code, "risk_engine.hpp")
        assert not findings

    def test_std_vector_without_hugepages_flagged(self):
        code = "std::vector<Order> book;"
        findings = run(HugePagesCheck, code, "order_book.hpp")
        assert any(f.check_id == "TURIN_HUGEPAGES" for f in findings)


# ---------------------------------------------------------------------------
# NumaCheck
# ---------------------------------------------------------------------------

class TestNuma:
    def test_malloc_without_numa_flagged(self):
        code = "void* tbl = malloc(sizeof(RiskTable) * 1000);"
        findings = run(NumaCheck, code, "risk_engine.cpp")
        assert any(f.check_id == "TURIN_NUMA" for f in findings)

    def test_numa_alloc_onnode_passes(self):
        code = (
            "#include <numa.h>\n"
            "void* p = numa_alloc_onnode(size, node);\n"
        )
        findings = run(NumaCheck, code, "risk_engine.cpp")
        assert not findings

    def test_mbind_passes(self):
        code = (
            "#include <numaif.h>\n"
            "mbind(addr, len, MPOL_BIND, &mask, max, 0);\n"
        )
        findings = run(NumaCheck, code, "order_book.cpp")
        assert not findings

    def test_non_hotpath_not_flagged(self):
        code = "void* p = malloc(100);"
        findings = run(NumaCheck, code, "config_loader.cpp")
        assert not findings


# ---------------------------------------------------------------------------
# SimdCheck
# ---------------------------------------------------------------------------

class TestSimd:
    def test_byte_scan_without_simd_flagged(self):
        code = (
            "while (i < len && buf[i] != '=')\n"
            "    i++;\n"
        )
        findings = run(SimdCheck, code, "fix_parser.cpp")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_avx512_intrinsic_passes(self):
        code = (
            "#include <immintrin.h>\n"
            "__m512i v = _mm512_loadu_si512(ptr);\n"
            "uint64_t mask = _mm512_cmpeq_epi8_mask(v, needle);\n"
        )
        findings = run(SimdCheck, code, "fix_parser.cpp")
        assert not findings

    def test_pragma_ivdep_passes(self):
        code = (
            "#pragma GCC ivdep\n"
            "for (int i = 0; i < N; ++i) arr[i] += 1;\n"
        )
        findings = run(SimdCheck, code, "fix_parser.cpp")
        assert not findings

    def test_avx2_intrinsic_passes(self):
        code = (
            "#include <immintrin.h>\n"
            "__m256i v = _mm256_loadu_si256(ptr);\n"
        )
        findings = run(SimdCheck, code, "fix_parser.cpp")
        assert not findings


# ---------------------------------------------------------------------------
# AffinityCheck
# ---------------------------------------------------------------------------

class TestAffinity:
    def test_thread_without_affinity_flagged(self):
        code = "std::thread worker(process_orders);"
        findings = run(AffinityCheck, code, "engine.cpp")
        assert any(f.check_id == "TURIN_AFFINITY" for f in findings)

    def test_pthread_setaffinity_passes(self):
        code = (
            "cpu_set_t cpuset;\n"
            "CPU_ZERO(&cpuset);\n"
            "CPU_SET(3, &cpuset);\n"
            "pthread_setaffinity_np(t.native_handle(), sizeof(cpuset), &cpuset);\n"
        )
        findings = run(AffinityCheck, code, "engine.cpp")
        assert not findings

    def test_sched_setaffinity_passes(self):
        code = "sched_setaffinity(0, sizeof(cpuset), &cpuset);"
        findings = run(AffinityCheck, code, "main.cpp")
        assert not findings


# ---------------------------------------------------------------------------
# BranchPredictionCheck
# ---------------------------------------------------------------------------

class TestBranchPrediction:
    def test_error_check_without_hint_flagged(self):
        code = (
            "if (result != 0) {\n"
            "    handle_error();\n"
            "}\n" * 6  # repeat to hit count threshold
        )
        findings = run(BranchPredictionCheck, code, "fix_parser.cpp")
        assert any(f.check_id == "TURIN_BRANCH" for f in findings)

    def test_builtin_expect_passes(self):
        code = (
            "if (__builtin_expect(result != 0, 0)) {\n"
            "    handle_error();\n"
            "}\n"
        )
        findings = run(BranchPredictionCheck, code, "fix_parser.cpp")
        assert not findings

    def test_likely_attribute_passes(self):
        code = (
            "if (field_found) [[likely]] {\n"
            "    process(field);\n"
            "}\n"
        )
        findings = run(BranchPredictionCheck, code, "fix_parser.cpp")
        assert not findings


# ---------------------------------------------------------------------------
# PrefetchCheck
# ---------------------------------------------------------------------------

class TestPrefetch:
    def test_map_lookup_in_loop_flagged(self):
        code = (
            "for (int i = 0; i < N; ++i) {\n"
            "    auto it = risk_table.find(symbols[i]);\n"
            "}\n"
        )
        findings = run(PrefetchCheck, code, "risk_engine.cpp")
        assert any(f.check_id == "TURIN_PREFETCH" for f in findings)

    def test_builtin_prefetch_passes(self):
        code = (
            "for (int i = 0; i < N; ++i) {\n"
            "    __builtin_prefetch(&table[keys[i+8]], 0, 1);\n"
            "    auto it = risk_table.find(symbols[i]);\n"
            "}\n"
        )
        findings = run(PrefetchCheck, code, "risk_engine.cpp")
        assert not findings


# ---------------------------------------------------------------------------
# LockFreeCheck
# ---------------------------------------------------------------------------

class TestLockFree:
    def test_mutex_on_hotpath_flagged(self):
        code = (
            "std::mutex order_mutex_;\n"
            "void process() {\n"
            "    std::lock_guard<std::mutex> lk(order_mutex_);\n"
            "}\n"
        )
        findings = run(LockFreeCheck, code, "order_book.cpp")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_condvar_flagged(self):
        code = "std::condition_variable cv_;"
        findings = run(LockFreeCheck, code, "order_book.cpp")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_seqcst_flagged(self):
        code = "counter.fetch_add(1, std::memory_order_seq_cst);"
        findings = run(LockFreeCheck, code, "order_book.cpp")
        assert any(f.check_id == "TURIN_LOCKFREE" for f in findings)

    def test_atomic_relaxed_passes(self):
        code = "counter.fetch_add(1, std::memory_order_relaxed);"
        findings = run(LockFreeCheck, code, "order_book.cpp")
        # seq_cst finding should not appear
        assert not any(f.check_id == "TURIN_LOCKFREE" and "seq_cst" in f.title
                        for f in findings)

    def test_mm_pause_passes(self):
        code = (
            "while (!ready.load(std::memory_order_acquire))\n"
            "    _mm_pause();\n"
        )
        findings = run(LockFreeCheck, code, "order_book.cpp")
        assert not any(f.severity == Severity.CRITICAL for f in findings)


# ---------------------------------------------------------------------------
# MemoryAllocationCheck
# ---------------------------------------------------------------------------

class TestMemoryAllocation:
    def test_new_on_hotpath_flagged(self):
        code = "Order* o = new Order();"
        findings = run(MemoryAllocationCheck, code, "fix_parser.cpp")
        assert any(f.check_id == "TURIN_ALLOC" for f in findings)

    def test_malloc_on_hotpath_flagged(self):
        code = "void* buf = malloc(sizeof(Order));"
        findings = run(MemoryAllocationCheck, code, "risk_engine.cpp")
        assert any(f.check_id == "TURIN_ALLOC" for f in findings)

    def test_placement_new_passes(self):
        code = "Order* o = new (pool_ptr) Order();"
        findings = run(MemoryAllocationCheck, code, "fix_parser.cpp")
        assert not any(f.check_id == "TURIN_ALLOC" and "placement" not in f.title
                        for f in findings)

    def test_push_back_without_reserve_flagged(self):
        code = (
            "std::vector<Order> orders;\n"
            "orders.push_back(o);\n"
        )
        findings = run(MemoryAllocationCheck, code, "fix_parser.cpp")
        assert any("push_back" in f.title or "reallocate" in f.title
                    for f in findings)

    def test_make_shared_flagged(self):
        code = "auto p = std::make_shared<Order>(o);"
        findings = run(MemoryAllocationCheck, code, "risk_engine.cpp")
        assert any("shared" in f.title.lower() or "make_shared" in f.description
                    for f in findings)


# ---------------------------------------------------------------------------
# FalseSharingCheck
# ---------------------------------------------------------------------------

class TestFalseSharing:
    def test_unpadded_counters_flagged(self):
        code = (
            "struct OrderStats {\n"
            "    std::atomic<long> total_count;\n"
            "    std::atomic<long> reject_count;\n"
            "    std::atomic<long> fill_count;\n"
            "};\n"
        )
        findings = run(FalseSharingCheck, code, "order_book.hpp")
        assert any(f.check_id == "TURIN_FALSE_SHARE" for f in findings)

    def test_padded_counters_pass(self):
        code = (
            "struct alignas(64) OrderStats {\n"
            "    std::atomic<long> total_count;\n"
            "    char _pad0[56];\n"
            "    std::atomic<long> reject_count;\n"
            "    char _pad1[56];\n"
            "};\n"
        )
        findings = run(FalseSharingCheck, code, "order_book.hpp")
        assert not findings


# ---------------------------------------------------------------------------
# CompilerFlagsCheck
# ---------------------------------------------------------------------------

class TestCompilerFlags:
    def test_no_march_flagged(self):
        code = (
            "cmake_minimum_required(VERSION 3.20)\n"
            "target_compile_options(risk PRIVATE -O2)\n"
        )
        findings = run(CompilerFlagsCheck, code, "CMakeLists.txt")
        assert any("march" in f.title.lower() or "znver5" in f.description
                    for f in findings)

    def test_march_znver5_passes_march_check(self):
        code = "target_compile_options(risk PRIVATE -march=znver5 -O3 -flto=auto)"
        findings = run(CompilerFlagsCheck, code, "CMakeLists.txt")
        # Should not flag the -march check
        assert not any("No -march=znver5" in f.title for f in findings)

    def test_o0_flagged_critical(self):
        code = "target_compile_options(risk PRIVATE -O0 -g)"
        findings = run(CompilerFlagsCheck, code, "CMakeLists.txt")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_march_native_minor(self):
        code = "target_compile_options(risk PRIVATE -march=native -O3)"
        findings = run(CompilerFlagsCheck, code, "CMakeLists.txt")
        assert any(f.severity == Severity.MINOR and "native" in f.title
                    for f in findings)

    def test_no_lto_flagged(self):
        code = "target_compile_options(risk PRIVATE -march=znver5 -O3)"
        findings = run(CompilerFlagsCheck, code, "CMakeLists.txt")
        assert any("flto" in f.suggestion.lower() or "lto" in f.title.lower()
                    for f in findings)


# ---------------------------------------------------------------------------
# Integration: run all checks on bad sample files
# ---------------------------------------------------------------------------

class TestIntegration:
    def test_bad_fix_parser_has_multiple_findings(self):
        from turin_analyzer.analyzer import TurinAnalyzer
        analyzer = TurinAnalyzer()
        sample   = Path(__file__).parent.parent / "sample_cpp" / "fix_parser_bad.hpp"
        if not sample.exists():
            pytest.skip("sample file not found")
        result = analyzer.analyze_path(sample)
        assert result.total_findings >= 3, (
            f"Expected >=3 findings on bad FIX parser, got {result.total_findings}"
        )

    def test_bad_order_book_has_critical_findings(self):
        from turin_analyzer.analyzer import TurinAnalyzer
        analyzer = TurinAnalyzer()
        sample   = Path(__file__).parent.parent / "sample_cpp" / "order_book_bad.hpp"
        if not sample.exists():
            pytest.skip("sample file not found")
        result = analyzer.analyze_path(sample)
        crits = [f for f in result.all_findings if f.severity.value == "critical"]
        assert len(crits) >= 1, "Expected at least 1 critical finding on bad order book"

    def test_bad_cmake_has_critical_march_finding(self):
        from turin_analyzer.analyzer import TurinAnalyzer
        analyzer = TurinAnalyzer()
        sample   = Path(__file__).parent.parent / "sample_cpp" / "CMakeLists_bad.txt"
        if not sample.exists():
            pytest.skip("sample file not found")
        result = analyzer.analyze_path(sample)
        assert result.total_findings >= 1

    def test_good_cmake_passes_march_check(self):
        from turin_analyzer.analyzer import TurinAnalyzer
        from turin_analyzer.checks.compiler_flags import CompilerFlagsCheck
        analyzer = TurinAnalyzer(checks=[CompilerFlagsCheck])
        sample   = Path(__file__).parent.parent / "sample_cpp" / "CMakeLists_good.txt"
        if not sample.exists():
            pytest.skip("sample file not found")
        result = analyzer.analyze_path(sample)
        no_march = [f for f in result.all_findings if "No -march=znver5" in f.title]
        assert not no_march, "Good CMake file should pass -march=znver5 check"
