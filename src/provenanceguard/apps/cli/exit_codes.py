"""
CLI Exit Code Semantics Specification

0 = PASS / PASS_WITH_WARNING (Policy constraints met, pipeline can proceed)
1 = BLOCK / Verification Failure (Policy failure or risk score exceeded block threshold)
2 = Configuration Error (Invalid CLI args, missing config, invalid syntax)
3 = System Execution Error (Internal verifier exception, backend connection failure, timeout)
"""

from enum import IntEnum


class ExitCode(IntEnum):
    PASS = 0
    BLOCK = 1
    CONFIG_ERROR = 2
    SYSTEM_ERROR = 3
