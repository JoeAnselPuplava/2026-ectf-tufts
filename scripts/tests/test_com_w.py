# tests for write command
from test_common import *

import time
from loguru import logger

def write_files(val_pin, slot, perm):
    cmd = "write"
    args = [slot, perm, FILE]
    return host_call(cmd, val_pin, args)

# successful write operation on slot 0 with test file 
def success_write_files(suppress_output=False):
    process_time = time.perf_counter()
    res = write_files(True, "0", GROUP)
    process_time = time.perf_counter() - process_time

    logs = res.stdout
    msg = (DEBUG_NOISE + r"Write successful")

    check_result(msg, logs, "success_write_files")

    if not suppress_output:
        logger.success(f"success_write_files - passed")

    return process_time

# successful write operation on slot 0 with test file 
def success_overwrite_files(suppress_output=False):
    process_time = time.perf_counter()
    res = write_files(True, "0", GROUP)
    process_time = time.perf_counter() - process_time

    logs = res.stdout
    msg = (DEBUG_NOISE + r"Write successful")

    check_result(msg, logs, "success_overwrite_files")

    if not suppress_output:
        logger.success(f"success_overwrite_files - passed")

    return process_time

# list operation with invalid pin
def pin_error_write_files(suppress_output=False):
    process_time = time.perf_counter()
    res = write_files(False, "0", GROUP)
    process_time = time.perf_counter() - process_time

    logs = res.stdout
    msg = (
        DEBUG_NOISE +
        r"HSM failed with error: Message\(opcode=<Opcode\.ERROR: 69>, body=b'Invalid pin'\)"
    )

    check_result(msg, logs, "pin_error_write_files")

    if not suppress_output:
        logger.success(f"pin_error_write_files - passed")
    
    return process_time

# read operation with valid pin where file is present
def permission_error_write_files(suppress_output=False):
    res = write_files(True, "0", ERROR_GROUP)

    logs = res.stdout

    msg = (
        DEBUG_NOISE + 
        r"HSM failed with error: Message\(opcode=<Opcode\.ERROR: 69>, body=b'Invalid permission'\)"
    )

    check_result(msg, logs, "permission_error_write_files")

    if not suppress_output:
        logger.success(f"permission_error_write_files - passed")


# check time constraints on list operation
def time_success_write_files():
    timer_test(success_write_files, TIME_WRITE, "Write")

def time_pin_error_write_files():
    timer_test(pin_error_write_files, TIME_PIN_ERROR, "Write")


