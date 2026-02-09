# var initialization and shared testing functions
import os
import re
import subprocess
from loguru import logger

# initailized variables
UART_PORT = "/dev/tty.usbmodemM43210051"
SECRETS_PATH = "global.secrets"
PIN = "123abc"
ERROR_PIN = "111111"

VERBOSE = False
ITERATIONS = 100

# timing requirments (ms)
TIME_DEVICE_WAKE = 1000
TIME_LIST = 500
TIME_READ = 3000
TIME_WRITE = 3000
TIME_REC = 3000
TIME_INT = 1000
TIME_PIN_ERROR = 5000

# check test result output
def check_result(pattern, in_str, out_str):
    matched = re.search(pattern, in_str)
    if not matched:
        print(f"TEST {out_str} FAILED!")
        print("Expected to find string:")
        print(repr(pattern))
        print("Inside of string:")
        print(repr(in_str))
        raise Exception(f"test {out_str} failed")

# run actual command call
def host_call(cmd, val_pin, args):
    if val_pin:
        pin = PIN
    else:
        pin = ERROR_PIN

    if (args == ""):
        command = ["uvx",
                    "ectf",
                    "tools",
                    UART_PORT,
                    cmd,
                    pin]
    else:
        command = ["uvx",
                    "ectf",
                    "tools",
                    UART_PORT,
                    cmd,
                    pin,
                    args]

    if VERBOSE:
        logger.info(command)

    env = os.environ
    env["LOGURU_COLORIZE"] = "NO"

    res = subprocess.run(command, capture_output=True, text=True, env=env)

    if VERBOSE:
        logger.info(res)

    return res
