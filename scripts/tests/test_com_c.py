# tests for recieve command
from test_common import *

import time
from loguru import logger

def receive_files(val_pin, slot_r, slot_w, perm):
    cmd = "receive"
    args = [slot_r, slot_w, perm, "./helloworld.txt"]
    return host_call(cmd, val_pin, args)

# successful receive operation on slot 0 with test file 
def success_receive_files(suppress_output=False):
    listen(False)
    process_time = time.perf_counter()
    res = receive_files(True, "0", "0", GROUP)
    process_time = time.perf_counter() - process_time

    logs = res.stdout
    msg = (DEBUG_NOISE + r"Receive successful")

    check_result(msg, logs, "success_receive_files")

    if not suppress_output:
        logger.success(f"success_receive_files - passed")

    return process_time

# list operation with invalid pin
def pin_error_receive_files(suppress_output=False):
    proc = listen(False)
    process_time = time.perf_counter()
    res = receive_files(False, "0", "0", GROUP)
    process_time = time.perf_counter() - process_time
    kill_listen(proc[0])

    logs = res.stdout
    msg = (
        DEBUG_NOISE +
        r"HSM failed with error: Message\(opcode=<Opcode\.ERROR: 69>, body=b'Invalid pin'\)"
    )

    check_result(msg, logs, "pin_error_receive_files")

    if not suppress_output:
        logger.success(f"pin_error_receive_files - passed")
    
    return process_time

# read operation with valid pin where file is present
def permission_error_receive_files(suppress_output=False):
    proc = listen(False)
    res = receive_files(True, "0", "0", ERROR_GROUP)
    kill_listen(proc[0])

    logs = res.stdout

    msg = (
        DEBUG_NOISE + 
        r"HSM failed with error: Message\(opcode=<Opcode\.ERROR: 69>, body=b'Invalid permission'\)"
    )

    check_result(msg, logs, "permission_error_receive_files")

    if not suppress_output:
        logger.success(f"permission_error_receive_files - passed")


# check time constraints on list operation
def time_success_receive_files():
    timer_test(success_receive_files, TIME_REC, "Receive")

def time_pin_error_receive_files():
    timer_test(pin_error_receive_files, TIME_PIN_ERROR, "Receive")


