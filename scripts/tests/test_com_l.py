# tests for list
from test_common import *

import time
from loguru import logger

def list_files(val_pin):
    cmd = "list"
    args = []
    return host_call(cmd, val_pin, args)

# list operation with valid pin where no files are present
# needs to be updated to support multiple files
def success_list_files(suppress_output=False):
    process_time = time.perf_counter()
    res = list_files(True)
    process_time = time.perf_counter() - process_time

    logs = res.stdout
    msg = (DEBUG_NOISE + r"List successful")

    check_result(msg, logs, "success_list_files")

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
        DEBUG_NOISE +
        r"HSM failed with error: Message\(opcode=<Opcode\.ERROR: 69>, body=b'Invalid pin'\)"
    )

    check_result(msg, logs, "pin_error_list_files")

    if not suppress_output:
        logger.success(f"pin_error_list_files - passed")
    
    return process_time

# check time constraints on list operation
def time_success_list_files():
    timer_test(success_list_files, TIME_LIST, "List")

def time_pin_error_list_files():
    timer_test(pin_error_list_files, TIME_PIN_ERROR, "List")


