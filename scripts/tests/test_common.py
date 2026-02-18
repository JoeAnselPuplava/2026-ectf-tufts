# var initialization and shared testing functions
import os
import re
import subprocess
import signal
import time
from loguru import logger

# initailized variables
UART_PORT = "/dev/tty.usbmodemM43210051"
SCND_PORT = "/dev/tty.usbmodemM43210054"
SECRETS_PATH = "global.secrets"
FILE = "./helloworld.txt"
PIN = "123abc"
ERROR_PIN = "111111"
GROUP = "0x4321"
ERROR_GROUP = "1234"

# Reusable regex to ignore any lines starting with 'Got DEBUG message'
# Matches: "Got DEBUG message: " followed by anything until newline, zero or more times.
DEBUG_NOISE = r"(?:Got DEBUG message: .*\n)*"

VERBOSE = False
ITERATIONS = 10

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

# clean up old test files
def delete_test_files():
    cmd = ["rm", FILE]

    if VERBOSE:
        logger.info(cmd)

    env = os.environ
    env["LOGURU_COLORIZE"] = "NO"

    subprocess.run(cmd, env=env)

# run actual command call
def host_call(cmd, val_pin, args):
    if val_pin:
        pin = PIN
    else:
        pin = ERROR_PIN

    command = ["uvx",
               "ectf",
               "tools",
               UART_PORT,
               cmd,
               pin]

    if (args != []):
        for arg in args:
            command.append(arg)

    if VERBOSE:
        logger.info(command)

    env = os.environ
    env["LOGURU_COLORIZE"] = "NO"

    res = subprocess.run(command, capture_output=True, text=True, env=env)

    if VERBOSE:
        logger.info(res)

    return res

def listen(prim_port):
    if prim_port: 
        port = UART_PORT
    else: 
        port = SCND_PORT

    cmd = ["uvx", "ectf", "tools", port, "listen"]

    if VERBOSE:
        logger.info(cmd)

    env = os.environ
    env["LOGURU_COLORIZE"] = "NO"

    proc = subprocess.Popen(cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            env=env,
                            preexec_fn=os.setsid)

    # time.sleep(5)
    # os.killpg(proc.pid, signal.SIGINT)

    res, err = proc.communicate()

    if VERBOSE:
        logger.info(res)

    return [proc, res, err]

def kill_listen(proc): 
    os.killpg(proc.pid, signal.SIGINT)

# timer test
def timer_test(test_fun, com_time, com_name):
    for _ in range(ITERATIONS):
        time = test_fun(suppress_output=True)
        time_taken = (time) * 1000
        print(time_taken)
        # assert time_taken < com_time, (
        #     f"Time for {com_name} Operation exceeded {com_time}ms: got {time_taken}ms."
        # )

    logger.success(f"Timing requirement for `{com_name} Operation` - passed")