"""
Check: AVX-512 / AVX2 SIMD usage for data-parallel operations.

AMD Turin (Zen 5) is the FIRST AMD microarchitecture with FULL-WIDTH
native 512-bit AVX-512 execution units (Zen 4 folded two 256-bit
passes). This makes AVX-512 practically free vs Zen 4's 2x overhead.

Turin AVX-512 extensions available:
  AVX-512F, AVX-512BW, AVX-512CD, AVX-512DQ, AVX-512VL,
  AVX-512IFMA, AVX-512VBMI, AVX-512VBMI2, AVX-512VNNI,
  AVX-512BITALG, AVX-512VPOPCNTDQ

Hot-path opportunities in a risk engine:
  - FIX message byte scanning (find '=' and '\x01' separators)
  - Price/quantity comparison across order book levels
  - Risk limit checks across multiple positions simultaneously
  - Checksum computation for FIX messages
  - Binary protocol field packing/unpacking

Good patterns: _mm512_*, _mm256_*, <immintrin.h>, <avxintrin.h>,
  __attribute__((target("avx512f"))), pragma GCC target, auto-vectorisation
  hints (__restrict__, #pragma GCC ivdep).
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List

from .base import BaseCheck, CheckResult, Finding, Severity

# File has explicit SIMD usage
_SIMD_INCLUDE = re.compile(
    r'#\s*include\s*[<"]\s*(immintrin\.h|avxintrin\.h|avx512fintrin\.h|x86intrin\.h)\s*[>"]'
)

_AVX512_INTRINSIC = re.compile(r"\b_mm512_")
_AVX2_INTRINSIC   = re.compile(r"\b_mm256_")
_SSE_INTRINSIC    = re.compile(r"\b_mm_(?!pause|sfence|lfence|mfence|prefetch)")

_PRAGMA_SIMD = re.compile(
    r"#\s*pragma\s+GCC\s+target.*avx"
    r"|#\s*pragma\s+clang\s+attribute.*avx"
    r"|__attribute__\s*\(\s*\(\s*target\s*\(.*avx"
    r"|#\s*pragma\s+GCC\s+ivdep"
    r"|__restrict__"
)

# Operations that COULD benefit from SIMD but don't use it
_SCALAR_LOOP = re.compile(
    r"for\s*\(.*;\s*\w+\s*[<>]=?\s*\w+"   # for loop with comparison
)

_MEMCPY = re.compile(r"\b(memcpy|memmove|memset|memcmp)\s*\(")
_STRCMP = re.compile(r"\b(strcmp|strncmp|memcmp)\s*\(")

_BYTE_SCAN = re.compile(
    r"while\s*\(.*\[\w+\]\s*!=|for\s*\(.*\[\w+\]\s*!="  # byte-by-byte scan
)

_HOT_PATH = re.compile(
    r"(pars|fix|order_?book|risk|engine|codec|protocol|handler|match)",
    re.IGNORECASE,
)


class SimdCheck(BaseCheck):
    CHECK_ID      = "TURIN_SIMD"
    TITLE         = "No AVX-512 / AVX2 SIMD — scalar code on AMD Turin"
    TURIN_FEATURE = "AMD Turin Zen 5 full-width native AVX-512 (512-bit EU)"
    DESCRIPTION   = (
        "AMD Turin (Zen 5) introduces full-width 512-bit AVX-512 execution "
        "units — the first AMD chip without folded AVX-512. Operations that "
        "previously had to be split into two 256-bit passes now execute in "
        "one cycle. For a pre-trade risk engine:\n"
        "  • FIX byte scanning: _mm512_cmpeq_epi8 finds all '=' or SOH "
        "    delimiters across 64 bytes in a single instruction.\n"
        "  • Risk checks: compare 8 int64 positions to limits simultaneously.\n"
        "  • Checksums: vectorised XOR / ADD across the whole message.\n"
        "Scalar loops for these operations waste Turin's most differentiating "
        "new capability."
    )

    def check_file(self, path: Path, lines: List[str]) -> CheckResult:
        result = CheckResult(check_name=self.CHECK_ID, file_path=str(path))

        joined = "\n".join(lines)
        has_simd = bool(
            _SIMD_INCLUDE.search(joined)
            or _AVX512_INTRINSIC.search(joined)
            or _AVX2_INTRINSIC.search(joined)
            or _PRAGMA_SIMD.search(joined)
        )

        if has_simd:
            return result  # Already using SIMD

        is_hot = bool(_HOT_PATH.search(path.stem))
        if not is_hot:
            return result

        # Look for byte-by-byte scan patterns — prime candidates for SIMD
        for lineno, line in enumerate(lines, 1):
            clean = self.strip_comments(line)

            if _BYTE_SCAN.search(clean):
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.CRITICAL,
                    title="Scalar byte scan — AVX-512 would process 64 bytes/cycle",
                    description=(
                        f"Byte-by-byte loop on line {lineno} is a prime candidate "
                        "for AVX-512 vectorisation. AMD Turin's native 512-bit "
                        "units can scan 64 bytes per cycle using _mm512_cmpeq_epi8, "
                        "giving 64x throughput vs scalar iteration for FIX field "
                        "delimiter scanning."
                    ),
                    file_path=str(path),
                    line=lineno,
                    suggestion=(
                        "Replace scalar byte scan with:\n"
                        "  #include <immintrin.h>\n"
                        "  __m512i haystack = _mm512_loadu_si512(ptr);\n"
                        "  __m512i needle   = _mm512_set1_epi8('=');\n"
                        "  uint64_t mask    = _mm512_cmpeq_epi8_mask(haystack, needle);\n"
                        "  int pos = __builtin_ctzll(mask);  // first '=' position"
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))

            if _SCALAR_LOOP.search(clean) and not has_simd:
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.MAJOR,
                    title=self.TITLE,
                    description=(
                        f"Scalar loop on line {lineno} — AMD Turin's AVX-512 "
                        "units are idle. Add #pragma GCC ivdep or __restrict__ "
                        "qualifiers, or rewrite with AVX-512 intrinsics."
                    ),
                    file_path=str(path),
                    line=lineno,
                    suggestion=(
                        "Enable auto-vectorisation at minimum:\n"
                        "  #pragma GCC ivdep\n"
                        "  for (int i = 0; i < N; ++i) { ... }\n"
                        "Or compile with -march=znver5 -O3 -ffast-math to let "
                        "the compiler auto-vectorise to AVX-512."
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))

        return result
