# tests for listen command
from test_common import *

import time
from loguru import logger

# check that listen works properly, i.e. spits no errors 
def success_listen(suppress_output=False):
    res = listen(True)

    logs = res[0]
    errs = res[1]
    msg = ""

    check_result(
        msg,
        logs,
        "success_listen"
    )

    check_result(
        msg,
        errs,
        "success_listen"
    )

    if not suppress_output:
        logger.success(f"success_listen - passed")


