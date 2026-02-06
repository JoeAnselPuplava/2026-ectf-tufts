# tests for list
import test_common

import time

def list_files(): 
    cmd = "list"
    return test_common.host_call(cmd)

# check that list is successful 
def success_list_files(suppress_output=False):
    res = list_files()

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

    # add more tests 

    


# check that time constraints followed 