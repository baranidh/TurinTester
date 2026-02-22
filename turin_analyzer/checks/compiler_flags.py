"""
Check: Compiler flags targeting AMD Turin / Zen 5.

The correct compiler invocation for AMD Turin is critical — without
-march=znver5 the compiler cannot emit:
  • AVX-512 instructions (native 512-bit on Zen 5)
  • VPCLMULQDQ, VAES (vectorised AES for FIX checksums)
  • MOVDIRI / MOVDIR64B (streaming stores for low-latency NIC writes)
  • CLDEMOTE (cache line demotion hint)
  • AMX (Advanced Matrix Extensions — not Turin but future-proofing)

Essential flags for a pre-trade risk engine on Turin:
  -march=znver5            — full Zen 5 ISA including AVX-512
  -O3                      — full optimisation
  -ffast-math              — allow SIMD FP reassociation (safe for risk)
  -funroll-loops           — loop unrolling for parsers
  -fprofile-generate/-use  — Profile-Guided Optimisation
  -fno-omit-frame-pointer  — for profiling with perf/VTune
  -flto                    — Link-Time Optimisation

Red flags:
  -march=native without znver5 (might pick wrong target on cross-compile)
  -O2 (misses some vectorisations)
  -O0 / -Og (debug mode — catastrophic for latency)
  No -march flag at all (defaults to x86-64 baseline, no AVX-512)

We check CMakeLists.txt, Makefile, meson.build, compile_commands.json,
and any .cmake files.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List

from .base import BaseCheck, CheckResult, Finding, Severity

# Build files we can check
_BUILD_EXTENSIONS = {
    ".cmake", ".txt",   # CMakeLists.txt
    "",                  # Makefile (no extension)
    ".mk",
    ".mak",
    ".json",             # compile_commands.json
    ".build",            # meson.build
    ".toml",             # meson options
}

_BUILD_NAMES = re.compile(
    r"(CMakeLists|Makefile|meson\.build|compile_commands|\.cmake$|conanfile)",
    re.IGNORECASE,
)

# Good flags
_MARCH_ZNVER5  = re.compile(r"-march\s*=\s*znver5")
_MARCH_NATIVE  = re.compile(r"-march\s*=\s*native")
_O3            = re.compile(r"\b-O3\b")
_AVX512_FLAG   = re.compile(r"-mavx512f|-mavx512bw|-mavx512vl")
_PGO           = re.compile(r"-fprofile-(generate|use|data)")
_LTO           = re.compile(r"\b-flto\b|-flto=")
_FAST_MATH     = re.compile(r"\b-ffast-math\b")

# Bad flags
_O0_OG         = re.compile(r"\b-O0\b|\b-Og\b")
_O1_O2         = re.compile(r"\b-O1\b|\b-O2\b")
_NO_MARCH      = re.compile(r"-march")  # any -march present

# C++ source flags check (inline)
_PRAGMA_OPT    = re.compile(r'#\s*pragma\s+GCC\s+optimize\s*\(\s*"O3"')
_TARGET_ATTR   = re.compile(r'__attribute__\s*\(\s*\(\s*target\s*\(\s*"avx512')


class CompilerFlagsCheck(BaseCheck):
    CHECK_ID      = "TURIN_CFLAGS"
    TITLE         = "Missing AMD Turin / Zen 5 compiler flags"
    TURIN_FEATURE = "AMD Turin Zen 5 — -march=znver5 -O3 -mavx512f -flto"
    DESCRIPTION   = (
        "Without -march=znver5, the compiler targets the generic x86-64 "
        "baseline (SSE2 only) and cannot emit AVX-512, CLDEMOTE, "
        "MOVDIRI or other Turin-specific instructions. This leaves "
        "up to 8–16x throughput on the table for vectorisable code "
        "like FIX parsing and risk array scans. "
        "Profile-Guided Optimisation (-fprofile-use) further improves "
        "branch layout and inlining decisions for the specific message "
        "distribution seen in production."
    )

    def applies_to(self, path: Path) -> bool:
        name = path.name
        return (
            bool(_BUILD_NAMES.search(name))
            or path.suffix.lower() in {".cpp", ".cc", ".cxx", ".hpp", ".h"}
        )

    def check_file(self, path: Path, lines: List[str]) -> CheckResult:
        result = CheckResult(check_name=self.CHECK_ID, file_path=str(path))

        joined = "\n".join(lines)

        # For build files: check flags
        if _BUILD_NAMES.search(path.name):
            has_znver5  = bool(_MARCH_ZNVER5.search(joined))
            has_native  = bool(_MARCH_NATIVE.search(joined))
            has_any_march = bool(_NO_MARCH.search(joined))
            has_o3      = bool(_O3.search(joined))
            has_avx512  = bool(_AVX512_FLAG.search(joined))
            has_lto     = bool(_LTO.search(joined))
            has_bad_opt = bool(_O0_OG.search(joined))
            has_o2      = bool(_O1_O2.search(joined))

            if not has_znver5 and not has_native:
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.CRITICAL,
                    title="No -march=znver5 — AMD Turin AVX-512 unused",
                    description=(
                        "Build file has no -march=znver5 flag. The compiler "
                        "will generate generic x86-64 code (SSE2 only), "
                        "missing AVX-512, CLDEMOTE, MOVDIRI and all other "
                        "Zen 5 extensions. This is the most impactful single "
                        "flag for AMD Turin performance."
                    ),
                    file_path=str(path),
                    line=1,
                    suggestion=(
                        "Add to CMakeLists.txt:\n"
                        "  target_compile_options(risk_engine PRIVATE\n"
                        "      -march=znver5\n"
                        "      -O3\n"
                        "      -mavx512f -mavx512bw -mavx512vl\n"
                        "      -ffast-math\n"
                        "      -funroll-loops\n"
                        "      -flto\n"
                        "  )\n"
                        "Or for Makefile:\n"
                        "  CXXFLAGS += -march=znver5 -O3 -mavx512f -flto"
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))
            elif has_native:
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.MINOR,
                    title="-march=native detected — prefer -march=znver5 for reproducibility",
                    description=(
                        "-march=native picks up the current host's CPU features. "
                        "If built on a non-Turin machine, AVX-512 will NOT be "
                        "emitted. Hardcode -march=znver5 for CI/CD builds "
                        "targeting Turin deployment."
                    ),
                    file_path=str(path),
                    line=1,
                    suggestion=(
                        "Replace -march=native with -march=znver5 in CI builds."
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))

            if not has_o3 and not has_bad_opt:
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.MAJOR,
                    title="Missing -O3 optimisation level",
                    description=(
                        "-O3 enables loop unrolling, function inlining, "
                        "vectorisation and other transforms disabled at -O2. "
                        "For a latency-critical risk engine, -O3 is the "
                        "minimum required optimisation level."
                    ),
                    file_path=str(path),
                    line=1,
                    suggestion="Add -O3 to compiler flags.",
                    turin_feature=self.TURIN_FEATURE,
                ))

            if has_bad_opt:
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.CRITICAL,
                    title="Debug optimisation level (-O0/-Og) in build",
                    description=(
                        "-O0 or -Og disables all optimisations. On AMD Turin "
                        "the resulting code is 10–100x slower than -O3 for "
                        "hot loops. Never ship a latency-sensitive binary "
                        "without at least -O3."
                    ),
                    file_path=str(path),
                    line=1,
                    suggestion="Replace -O0/-Og with -O3 -march=znver5.",
                    turin_feature=self.TURIN_FEATURE,
                ))

            if not has_lto:
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.MINOR,
                    title="Link-Time Optimisation (-flto) not enabled",
                    description=(
                        "-flto allows the compiler to inline and optimise "
                        "across translation unit boundaries. For a risk engine "
                        "split across many .cpp files this can eliminate "
                        "virtual dispatch and enable cross-TU vectorisation."
                    ),
                    file_path=str(path),
                    line=1,
                    suggestion=(
                        "Add -flto=auto (GCC) or -flto=thin (Clang) to "
                        "both CXXFLAGS and LDFLAGS."
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))

        # For C++ source files: look for per-function target attributes
        else:
            joined = "\n".join(lines)
            if not _TARGET_ATTR.search(joined) and not _PRAGMA_OPT.search(joined):
                # Only report if the source has SIMD-looking operations without the attribute
                if re.search(r"for\s*\(.*;\s*\w+\s*[<>]=?\s*\w+", joined):
                    pass  # defer to SIMD check

        return result
