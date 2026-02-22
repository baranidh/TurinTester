"""
Check: Branch prediction hints for the Zen 5 predictor.

AMD Turin (Zen 5) has an improved branch predictor with a larger
branch target buffer (BTB) and enhanced indirect-branch predictors.
However, even the best predictor cannot overcome code that fails to
annotate hot vs cold paths.

C++20 [[likely]] / [[unlikely]] and GCC's __builtin_expect allow the
compiler to:
  1. Re-order basic blocks so the hot path has no taken branch
  2. Emit PREFETCHW on cold-path branch targets
  3. Help the branch predictor via static prediction hints

In a FIX parser / risk engine, the common cases are:
  - Field found:     likely
  - Checksum valid:  likely
  - Risk check pass: likely
  - Malformed message / reject: unlikely

Good patterns: [[likely]], [[unlikely]], __builtin_expect,
  __builtin_expect_with_probability, __attribute__((hot)),
  __attribute__((cold)), LIKELY/UNLIKELY macros.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import List

from .base import BaseCheck, CheckResult, Finding, Severity

_GOOD = re.compile(
    r"\[\[\s*likely\s*\]\]"
    r"|\[\[\s*unlikely\s*\]\]"
    r"|__builtin_expect\s*\("
    r"|__builtin_expect_with_probability\s*\("
    r"|\bLIKELY\s*\("
    r"|\bUNLIKELY\s*\("
    r"|__attribute__\s*\(\s*\(\s*hot\s*\)\s*\)"
    r"|__attribute__\s*\(\s*\(\s*cold\s*\)\s*\)"
)

# Conditions in hot-path code that should have hints
_IF_STMT = re.compile(r"^\s*if\s*\(")

_ERROR_CHECK = re.compile(
    r"if\s*\(.*(!= 0|== -1|== nullptr|== NULL|== false|failed|error|err\b|!ok|rejected|reject)",
    re.IGNORECASE,
)

_HOT_PATH = re.compile(
    r"(pars|fix|order_?book|risk|engine|codec|handler|match|session)",
    re.IGNORECASE,
)


class BranchPredictionCheck(BaseCheck):
    CHECK_ID      = "TURIN_BRANCH"
    TITLE         = "No branch prediction hints (likely/unlikely) on hot-path conditionals"
    TURIN_FEATURE = "AMD Turin Zen 5 enhanced branch predictor + C++20 [[likely]]/[[unlikely]]"
    DESCRIPTION   = (
        "AMD Turin (Zen 5) improves the indirect branch predictor and BTB "
        "capacity, but relies on correct static annotation to optimise "
        "basic-block layout. [[likely]] and [[unlikely]] (C++20) and "
        "__builtin_expect (GCC/Clang) tell the compiler to keep the hot "
        "path fall-through (no branch taken penalty) and move cold code "
        "out of the instruction cache. For a FIX parser processing "
        "thousands of messages per second, every mis-predicted branch "
        "costs 15–20 cycles on Zen 5."
    )

    def check_file(self, path: Path, lines: List[str]) -> CheckResult:
        result = CheckResult(check_name=self.CHECK_ID, file_path=str(path))

        joined = "\n".join(lines)
        has_hints = bool(_GOOD.search(joined))

        is_hot = bool(_HOT_PATH.search(path.stem))
        if not is_hot:
            return result

        if has_hints:
            return result  # File already uses prediction hints

        # Count plain if-statements to gauge severity
        if_count = sum(1 for line in lines if _IF_STMT.match(line))
        if if_count == 0:
            return result

        # Find error-check patterns — these are almost always unlikely
        for lineno, line in enumerate(lines, 1):
            clean = self.strip_comments(line)
            if _ERROR_CHECK.search(clean):
                result.add(Finding(
                    check_id=self.CHECK_ID,
                    severity=Severity.MINOR,
                    title=self.TITLE,
                    description=(
                        f"Error-check branch on line {lineno} has no "
                        "[[unlikely]] annotation. The Zen 5 compiler can "
                        "move this cold path out of the icache working set, "
                        "improving instruction-fetch efficiency on the hot path."
                    ),
                    file_path=str(path),
                    line=lineno,
                    suggestion=(
                        "Annotate error branches with [[unlikely]]:\n"
                        "  if (__builtin_expect(result != 0, 0)) [[unlikely]] {\n"
                        "      // error path\n"
                        "  }\n"
                        "Or define convenience macros:\n"
                        "  #define LIKELY(x)   __builtin_expect(!!(x), 1)\n"
                        "  #define UNLIKELY(x) __builtin_expect(!!(x), 0)"
                    ),
                    turin_feature=self.TURIN_FEATURE,
                ))

        # Report once per file for the general pattern
        if if_count > 5:
            result.add(Finding(
                check_id=self.CHECK_ID,
                severity=Severity.MINOR,
                title=self.TITLE,
                description=(
                    f"File contains {if_count} if-statements with no branch "
                    "prediction hints. Add [[likely]]/[[unlikely]] to hot "
                    "conditionals to help Zen 5 block-layout optimisation."
                ),
                file_path=str(path),
                line=1,
                suggestion=(
                    "Use C++20 attributes:\n"
                    "  if (field_found) [[likely]] { ... }\n"
                    "  if (checksum_bad) [[unlikely]] { ... }\n"
                    "Compile with -std=c++20 to enable these attributes."
                ),
                turin_feature=self.TURIN_FEATURE,
            ))

        return result
