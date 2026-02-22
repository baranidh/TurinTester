"""Individual architectural check modules for AMD Turin / Zen 5."""

from .alignment         import AlignmentCheck
from .huge_pages        import HugePagesCheck
from .numa              import NumaCheck
from .simd              import SimdCheck
from .affinity          import AffinityCheck
from .branch_prediction import BranchPredictionCheck
from .prefetch          import PrefetchCheck
from .lock_free         import LockFreeCheck
from .memory_allocation import MemoryAllocationCheck
from .false_sharing     import FalseSharingCheck
from .compiler_flags    import CompilerFlagsCheck

ALL_CHECKS = [
    AlignmentCheck,
    HugePagesCheck,
    NumaCheck,
    SimdCheck,
    AffinityCheck,
    BranchPredictionCheck,
    PrefetchCheck,
    LockFreeCheck,
    MemoryAllocationCheck,
    FalseSharingCheck,
    CompilerFlagsCheck,
]
