import re
import random
import os
import subprocess
from loguru import logger

DECODER_ID = 0xDEADBEEF


UART_PORT = "/dev/ttymax78000-dev"
SECRETS_PATH = "global.secrets"

# Channels with secrets generated
CHANNELS = [1, 2, 3, 4, 5, 6, 7, 4294967295, 8, 9]

CHANNEL_ID_SIZE = 32
DECODER_ID_SIZE = 32
TIMESTAMP_SIZE = 64
MAX_SUBS = 8

MAX_TIMESTAMP = pow(2, TIMESTAMP_SIZE) - 1
MAX_CHANNEL_ID = pow(2, CHANNEL_ID_SIZE) - 1
MAX_DECODER_ID = pow(2, DECODER_ID_SIZE) - 1

# Number of times timing requirements are tested
ITERATIONS = 100

VERBOSE = False

SUBSCRIPTION_LIST = []


def get_random_period():
    start = random.randint(0, MAX_TIMESTAMP)
    end = random.randint(start, MAX_TIMESTAMP)
    return (start, end)


def get_random_subscribed_channel():
    return random.choice(CHANNELS[:8])


def get_random_channel():
    return random.choice(CHANNELS)


def remove_if_exists(filename):
    if os.path.exists(filename):
        os.remove(filename)


def check_result(pattern: str, raw_input: str, out_str: str):
    matched = re.search(pattern, raw_input)
    if not matched:
        print(f"MATCH {out_str} FAILED!")
        print("Expected to find string:")
        print(repr(pattern))
        print("Inside of string:")
        print(repr(raw_input))
        raise Exception(f"match {out_str} failed")


def process(cmd):
    cmd = [".venv/bin/python", "-m"] + cmd
    if VERBOSE:
        logger.info(cmd)

    env = os.environ
    env["LOGURU_COLORIZE"] = "NO"
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)

    if VERBOSE:
        logger.info(res)

    return res
