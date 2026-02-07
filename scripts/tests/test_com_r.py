# tests for read command
import test_common

import time
from loguru import logger

# Reusable regex to ignore any lines starting with 'Got DEBUG message'
# Matches: "Got DEBUG message: " followed by anything until newline, zero or more times.
DEBUG_NOISE = r"(?:Got DEBUG message: .*\n)*"


def read_files_w_slot(val_pin, slot):
    cmd = "read"
    return test_common.host_call(cmd, val_pin, slot)


# list operation with valid pin where no files are present
# needs to be updated to support multiple files
def success_read_files(suppress_output=False):
    process_time = time.perf_counter()
    # Defaulting to slot 0 for general read tests
    res = read_files_w_slot(True, 0)
    process_time = time.perf_counter() - process_time

    logs = res.stdout

    # Matches any debug noise followed immediately by success
    msg = DEBUG_NOISE + r"List successful"

    test_common.check_result(msg, logs, "success_read_files")

    if not suppress_output:
        logger.success(f"success_read_files - passed")

    return process_time


# list operation with invalid pin
def pin_error_read_files(suppress_output=False):
    # Defaulting to slot 0
    res = read_files_w_slot(False, 0)

    logs = res.stdout

    # Matches ANY debug noise (including the lockout countdowns) followed by the error
    msg = (
        DEBUG_NOISE
        + r"HSM failed with error: Message\(opcode=<Opcode\.ERROR: 69>, body=b'Invalid pin'\)"
    )

    test_common.check_result(msg, logs, "pin_error_read_files")

    if not suppress_output:
        logger.success(f"pin_error_read_files - passed")


# New Function: Test all 8 valid slots and boundary conditions
def test_slot_boundaries():
    # 1. Test Valid Slots (0 through 7)
    for slot_num in range(8):
        res = read_files_w_slot(True, slot_num)
        logs = res.stdout
        msg = DEBUG_NOISE + r"Read successful"

        test_common.check_result(msg, logs, f"read_slot_{slot_num}")
    logger.success("Valid slots 0-7 - passed")

    # 2. Test Invalid Slot Boundaries (< 0 and >= 8)
    # Adjust error message expectation based on your actual firmware response
    invalid_slots = [-1, 8]

    for slot_num in invalid_slots:
        res = read_files_w_slot(True, slot_num)
        logs = res.stdout

        # This regex looks for a generic failure if the specific opcode varies
        # If you know the specific opcode (e.g. INVALID_SLOT), replace the end of this string
        msg = DEBUG_NOISE + r"HSM failed with error"

        test_common.check_result(msg, logs, f"invalid_slot_{slot_num}")

    logger.success("Invalid slot boundaries - passed")


# check time constraints on read operation
def time_success_read_files():
    for _ in range(test_common.ITERATIONS):
        time_val = success_read_files(suppress_output=True)
        time_taken = (time_val) * 1000
        assert time_taken < test_common.TIME_READ, (
            f"Time for Read Operation exceeded {test_common.TIME_READ}ms: got {time_taken}ms."
        )

    logger.success(f"Timing requirement for `Read Operation` - passed")


def time_pin_error_read_files():
    for _ in range(test_common.ITERATIONS):
        # Measure time locally since pin_error_read_files does not return time
        start = time.perf_counter()
        pin_error_read_files(suppress_output=True)
        time_taken = (time.perf_counter() - start) * 1000

        assert time_taken < test_common.TIME_PIN_ERROR, (
            f"Time for Read Operation exceeded {test_common.TIME_PIN_ERROR}ms: got {time_taken}ms."
        )

    logger.success(f"Timing requirement for `Read Operation` - passed")
