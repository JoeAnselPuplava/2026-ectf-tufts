# tests for read command
from test_common import *

import time
from loguru import logger

def read_files_w_slot(val_pin, slot):
    cmd = "read"
    return host_call(cmd, val_pin, slot)


# read operation with valid pin where file is present
def success_read_files(suppress_output=False):
    process_time = time.perf_counter()
    # Defaulting to slot 0 for general read tests
    res = read_files_w_slot(True, ["0", "./"])
    process_time = time.perf_counter() - process_time

    logs = res.stdout

    # Matches any debug noise followed immediately by success
    msg = DEBUG_NOISE + r"Read successful"

    check_result(msg, logs, "success_read_files")

    if not suppress_output:
        logger.success(f"success_read_files - passed")

    return process_time


# New Function: Test all 8 valid slots and boundary conditions
def test_slot_boundaries():
    # 1. Test Valid Slots (0 through 7)
    for slot_num in range(8):
        res = read_files_w_slot(True, [str(slot_num), "./"])
        logs = res.stdout
        msg = DEBUG_NOISE + r"Read successful"

        check_result(msg, logs, f"read_slot_{slot_num}")
    logger.success("Valid slots 0-7 - passed")

    # 2. Test Invalid Slot Boundaries (< 0 and >= 8)
    # Adjust error message expectation based on your actual firmware response
    invalid_slots = ["^-1", "8"]

    for slot_num in invalid_slots:
        res = read_files_w_slot(True, [slot_num, "./"])
        logs = res.stderr

        # This regex looks for a generic failure if the specific opcode varies
        # If you know the specific opcode (e.g. INVALID_SLOT), replace the end of this string
        msg = DEBUG_NOISE + r"HSM failed with error"

        check_result(msg, logs, f"invalid_slot_{slot_num}")

    logger.success("Invalid slot boundaries - passed")

# list operation with invalid pin
def pin_error_read_files(suppress_output=False):
    # Defaulting to slot 0
    res = read_files_w_slot(False, ["0", "./"])

    logs = res.stdout

    # Matches ANY debug noise (including the lockout countdowns) followed by the error
    msg = (
        DEBUG_NOISE
        + r"HSM failed with error: Message\(opcode=<Opcode\.ERROR: 69>, body=b'Invalid pin'\)"
    )

    check_result(msg, logs, "pin_error_read_files")

    if not suppress_output:
        logger.success(f"pin_error_read_files - passed")


# read operation with valid pin where file is present
def empty_error_read_files(suppress_output=False):
    res = read_files_w_slot(True, ["0", "./"])

    logs = res.stdout

    msg = (
        DEBUG_NOISE + 
        r"HSM failed with error: Message\(opcode=<Opcode\.ERROR: 69>, body=b'Failed to read file'\)"
    )

    check_result(msg, logs, "empty_error_read_files")

    if not suppress_output:
        logger.success(f"empty_error_read_files - passed")


# read operation with valid pin where file is present
def permission_error_read_files(suppress_output=False):
    res = read_files_w_slot(True, ["0", "./"])

    logs = res.stdout

    msg = (
        DEBUG_NOISE + 
        r"HSM failed with error: Message\(opcode=<Opcode\.ERROR: 69>, body=b'Invalid permission'\)"
    )

    check_result(msg, logs, "permission_error_read_files")

    if not suppress_output:
        logger.success(f"permission_error_read_files - passed")

    return process_time


# check time constraints on read operation
def time_success_read_files():
    timer_test(success_read_files, TIME_READ, "Read")


def time_pin_error_read_files():
    for _ in range(ITERATIONS):
        # Measure time locally since pin_error_read_files does not return time
        start = time.perf_counter()
        pin_error_read_files(suppress_output=True)
        time_taken = (time.perf_counter() - start) * 1000

        assert time_taken < TIME_PIN_ERROR, (
            f"Time for Read Operation exceeded {TIME_PIN_ERROR}ms: got {time_taken}ms."
        )

    logger.success(f"Timing requirement for `Read Operation` - passed")
