# tests for list
import test_common

import time

def list_files(val_pin): 
    cmd = "list"
    return test_common.host_call(cmd, val_pin)

# check that list is successful 
def success_list_files(suppress_output=False):
    res = list_files(True)

    logs = res.stdout
    msg = (
        r"Got DEBUG message: b'Checking PIN\\n'\n"
        r"Got DEBUG message: b'PIN OK\\n'\n"
        r"List successful"
    )

    test_common.check_result(
        msg, 
        logs, 
        "success_list_files"
    )

def pin_error_list_files(suppress_output=False):
    res = list_files(False)

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

    test_common.check_result(
        msg, 
        logs, 
        "pin_error_list_files"
    )

    


# check that time constraints followed 