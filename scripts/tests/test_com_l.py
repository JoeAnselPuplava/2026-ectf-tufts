# tests for list
import test_common

import time
from loguru import logger

def list_files(val_pin):
    cmd = "list"
    args = ""
    return test_common.host_call(cmd, val_pin, args)

# list operation with valid pin where no files are present
# needs to be updated to support multiple files
def success_list_files(suppress_output=False):
    process_time = time.perf_counter()
    res = list_files(True)
    process_time = time.perf_counter() - process_time

    logs = res.stdout
    msg = (
        r"Got DEBUG message: b'Checking PIN\\n'\n"
        r"Got DEBUG message: b'PIN OK\\n'\n"
        r"List successful"
    )

    test_common.check_result(msg, logs, "success_list_files")

    if not suppress_output:
        logger.success(f"success_list_files - passed")

    return process_time

# list operation with invalid pin
def pin_error_list_files(suppress_output=False):
    process_time = time.perf_counter()
    res = list_files(False)
    process_time = time.perf_counter() - process_time

    logs = res.stdout
    msg = (
        r"Got DEBUG message: b'Checking PIN\\n'\n"
        r"Got DEBUG message: b'PIN INVALID\\n'\n"
        r"Got DEBUG message: b'Entering PIN lockout'\n"
        r"Got DEBUG message: b'Initial lockout time: \d+'\n"
        r"(?:Got DEBUG message: b'Waiting 1 second\.\.\. \(remaining: \d+\)'\n"
        r"Got DEBUG message: b'Lockout period elapsed, decrementing lockout time'\n"
        r"Got DEBUG message: b'New lockout time: \d+'\n)+"
        r"Got DEBUG message: b'PIN lockout complete'\n"
        r"HSM failed with error: Message\(opcode=<Opcode\.ERROR: 69>, body=b'Invalid pin'\)"
    )

    test_common.check_result(msg, logs, "pin_error_list_files")

    if not suppress_output:
        logger.success(f"pin_error_list_files - passed")
    
    return process_time

# check time constraints on list operation
def time_success_list_files():
    for _ in range(test_common.ITERATIONS):
        time = success_list_files(suppress_output=True)
        time_taken = (time) * 1000
        assert time_taken < test_common.TIME_LIST, (
            f"Time for List Operation exceeded {test_common.TIME_LIST}ms: got {time_taken}ms."
        )

    logger.success(f"Timing requirement for `List Operation` - passed")

def time_pin_error_list_files():
    for _ in range(test_common.ITERATIONS):
        time = pin_error_list_files(suppress_output=True)
        time_taken = (time) * 1000
        assert time_taken < test_common.TIME_PIN_ERROR, (
            f"Time for List Operation exceeded {test_common.TIME_PIN_ERROR}ms: got {time_taken}ms."
        )

    logger.success(f"Timing requirement for `List Operation` - passed")


