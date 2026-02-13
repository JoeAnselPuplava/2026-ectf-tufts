# tests for interrogate command
from test_common import *

import time
from loguru import logger

def interrogate_files(val_pin):
    cmd = "interrogate"
    args = []
    return host_call(cmd, val_pin, args)

# successful interogate operation 
def success_interrogate_files(suppress_output=False):
    listen(False)
    process_time = time.perf_counter()
    res = interrogate_files(True)
    process_time = time.perf_counter() - process_time

    logs = res.stdout
    msg = (DEBUG_NOISE + r"Interrogate successful")

    check_result(msg, logs, "success_interrogate_files")

    if not suppress_output:
        logger.success(f"success_interrogate_files - passed")

    return process_time

# interrogate operation with invalid pin
def pin_error_interrogate_files(suppress_output=False):
    proc = listen(False)
    process_time = time.perf_counter()
    res = interrogate_files(False)
    process_time = time.perf_counter() - process_time
    kill_listen(proc[0])

    logs = res.stdout
    msg = (
        DEBUG_NOISE +
        r"HSM failed with error: Message\(opcode=<Opcode\.ERROR: 69>, body=b'Invalid pin'\)"
    )

    check_result(msg, logs, "pin_error_interrogate_files")

    if not suppress_output:
        logger.success(f"pin_error_interrogate_files - passed")
    
    return process_time

# check time constraints on list operation
def time_success_list_files():
    timer_test(success_interrogate_files, TIME_INT, "Interrogate")

def time_pin_error_list_files():
    timer_test(pin_error_interrogate_files, TIME_PIN_ERROR, "Interrogate")


