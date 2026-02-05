# var initialization and shared testing functions 
import os 
import re
import subprocess
from loguru import logger 

from loguru import logger

# initailized variables 
UART_PORT = "/dev/tty.usbmodemM43210051"
SECRETS_PATH = "global.secrets"
PIN = "123abc"

VERBOSE = False 

#   size requirements 
#   num testing iterations 

# random data generation - TBD 

# clean up 

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
def host_call(cmd): 
    # potentially add virtual environment 
    command = ["uvx",
               "ectf",
               "tools", 
               UART_PORT, 
               cmd, 
               PIN]

    if VERBOSE:
        logger.info(command)

    env = os.environ
    env["LOGURU_COLORIZE"] = "NO"
    
    res = subprocess.run(command, 
                         capture_output=True, 
                         text=True, 
                         env=env)

    if VERBOSE:
        logger.info(res)

    return res


