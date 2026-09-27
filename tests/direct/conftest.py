"""Direct Mode harness for contracts/breachcourt.py (see support.py for what is and
is not mocked). Validator logic is exercised through direct_vm.run_validator(),
which hands the captured validator closure a forged leader result while the
mocks stand in for the validator's own view of the web and the model."""

import os
import sys

import pytest

from tests.direct.support import CONTRACT, NOW


# -- Windows compatibility shim for genlayer-test 0.29.2 ----------------------
#
# The official direct runner injects the transaction message by writing it to a
# temp file, dup2-ing that file onto fd 0 and unlinking the path while fd 0
# still references it. POSIX permits that; Windows refuses with WinError 32, so
# every direct test errors at deploy on a fresh Windows checkout. The shim
# tolerates that one refusal and changes nothing else. It is a no-op on Linux
# and macOS, so CI runs the runner as published.

def _tolerate_windows_unlink():
    if os.name != "nt":
        return
    try:
        from gltest.direct import loader as _loader
    except ImportError:
        return
    original = _loader._inject_message_to_fd0
    if getattr(original, "_breachcourt_shim", False):
        return

    def inject_tolerant(vm):
        real_unlink = os.unlink

        def unlink_tolerant(path, *args, **kwargs):
            try:
                real_unlink(path, *args, **kwargs)
            except PermissionError:
                pass
        os.unlink = unlink_tolerant
        try:
            return original(vm)
        finally:
            os.unlink = real_unlink

    inject_tolerant._breachcourt_shim = True
    _loader._inject_message_to_fd0 = inject_tolerant


_tolerate_windows_unlink()


# -- make warp() move the transaction clock -----------------------------------
#
# direct_vm.warp() sets the block timestamp the SDK's datetime.now() reads, but
# leaves gl.message_raw["datetime"] - the transaction time every window in this
# contract is measured against - at whatever the deploy injected. Without this,
# no test could cross a window. The shim only keeps the two in step.

def _warp_moves_the_message_clock():
    try:
        from gltest.direct.vm import VMContext
    except ImportError:
        return
    original = VMContext.warp
    if getattr(original, "_breachcourt_shim", False):
        return

    def warp(self, timestamp: str) -> None:
        original(self, timestamp)
        gl = sys.modules.get("genlayer.gl")
        if gl is not None and getattr(gl, "message_raw", None) is not None:
            gl.message_raw["datetime"] = timestamp

    warp._breachcourt_shim = True
    VMContext.warp = warp


_warp_moves_the_message_clock()


@pytest.fixture
def court(direct_vm, direct_deploy):
    direct_vm.check_pickling = True
    direct_vm.warp(NOW)
    return direct_deploy(CONTRACT)


@pytest.fixture
def mod(court):
    """The loaded contract module: pure helpers are tested through it."""
    for name, module in sys.modules.items():
        if name.endswith("breachcourt") and hasattr(module, "_parse_challenge"):
            return module
    raise AssertionError("the contract module is not loaded")
