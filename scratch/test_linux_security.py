"""
Verification script for Linux security boundary tests (symlink & FIFO fail-closed checks)
"""

import os
import pathlib
import sys

# Add src/ to import path
src_path = "/mnt/c/Users/abhishek/.gemini/antigravity-ide/scratch/provenanceguard/src"
sys.path.insert(0, src_path)

from provenanceguard.builders.isolated.artifact_collector import collect_build_artifacts
from provenanceguard.builders.isolated.exceptions import (
    SpecialFileViolationError,
    SymlinkViolationError,
)

print("Starting Linux Security Boundary Verification...")

# 1. Verify Symlink Rejection
tmp_dir = pathlib.Path("/tmp/test_symlink_security")
if tmp_dir.exists():
    import shutil

    shutil.rmtree(tmp_dir)
tmp_dir.mkdir(parents=True, exist_ok=True)

target_file = tmp_dir / "target.txt"
target_file.write_text("sensitivedata")
symlink_file = tmp_dir / "symlink.txt"
os.symlink(target_file, symlink_file)

dest_dir = pathlib.Path("/tmp/test_symlink_dest")
if dest_dir.exists():
    import shutil

    shutil.rmtree(dest_dir)
dest_dir.mkdir(parents=True, exist_ok=True)

symlink_caught = False
try:
    collect_build_artifacts(tmp_dir, dest_dir, container_is_running=False)
except SymlinkViolationError as e:
    symlink_caught = True
    print(f"PASS: test_symlink_artifact_fail_closed caught SymlinkViolationError -> {e}")
except Exception as e:
    print(f"FAIL: Unexpected exception type -> {type(e)}: {e}")

if not symlink_caught:
    print("FAIL: test_symlink_artifact_fail_closed did NOT fail closed!")
    sys.exit(1)

# 2. Verify FIFO Rejection
tmp_fifo_dir = pathlib.Path("/tmp/test_fifo_security")
if tmp_fifo_dir.exists():
    import shutil

    shutil.rmtree(tmp_fifo_dir)
tmp_fifo_dir.mkdir(parents=True, exist_ok=True)

fifo_file = tmp_fifo_dir / "test.fifo"
os.mkfifo(fifo_file)

fifo_dest_dir = pathlib.Path("/tmp/test_fifo_dest")
if fifo_dest_dir.exists():
    import shutil

    shutil.rmtree(fifo_dest_dir)
fifo_dest_dir.mkdir(parents=True, exist_ok=True)

fifo_caught = False
try:
    collect_build_artifacts(tmp_fifo_dir, fifo_dest_dir, container_is_running=False)
except SpecialFileViolationError as e:
    fifo_caught = True
    print(f"PASS: test_fifo_socket_special_file_rejection caught SpecialFileViolationError -> {e}")
except Exception as e:
    print(f"FAIL: Unexpected exception type -> {type(e)}: {e}")

if not fifo_caught:
    print("FAIL: test_fifo_socket_special_file_rejection did NOT fail closed!")
    sys.exit(1)

print("ALL LINUX SECURITY TESTS PASSED EXPLICITLY ON LINUX KERNEL / EXT4 (2/2 PASS)")
