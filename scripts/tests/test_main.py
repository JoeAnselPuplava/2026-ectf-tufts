###########################################################
#
# Testing Files Structure
#   main - handles board operation, testing cleanup,
#          command line parsing, function calling
#   test files - one per command
#   common - contains variable initialization and shared helpers
#            for other tests
#   edge - checks for security edge cases
#
###########################################################

from test_common import *
from test_com_l import *
from test_com_r import * 
from test_com_w import * 
from test_com_n import *

import argparse
import os
import time

# reset board to prevent error
def reset_board():
    if VERBOSE:
        os.system(  # probably need new commands
            "openocd -f interface/cmsis-dap.cfg -f target/max78000.cfg -c 'init; reset; exit;'"
        )
    else:
        os.system(
            "openocd -f interface/cmsis-dap.cfg -f target/max78000.cfg -c 'init; reset; exit;' > /dev/null 2>&1"
        )
    time.sleep(1)

# clean up old test files
def delete_test_files():
   return 0
   # change as files are created by tests

# command line parsing
def parse_args():
    # create the parser
    parser = argparse.ArgumentParser()

    # add arguments
    parser.add_argument(
        "--port1",
        "-p",
        type=str,
        required=True,
        default=UART_PORT,
        help="Specify the serial port of the board",
    )
    parser.add_argument(
        "--port2",
        "-s",
        type=str,
        required=True,
        default=SCND_PORT,
        help="Specify the second serial port of the board",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print logs for debugging"
    )

    return parser.parse_args()


def main():
    args = parse_args()
    UART_PORT = args.port1
    SCND_PORT = args.port2

    if args.verbose:
        test_common.VERBOSE = True

    reset_board()
    delete_test_files()

    # start calling tests
    if VERBOSE:
        logger.info("Start testing - list")

    success_list_files()
    pin_error_list_files()
    # currently failing 
    # time_success_list_files()
    # time_pin_error_list_files()

    if VERBOSE:
        logger.info("Start testing - read")

    # success_read_files()
    # test_slot_boundaries() # may be unnessassary test 
    pin_error_read_files()
    empty_error_read_files()
    # permission_error_read_files()
    # time_success_read_files()
    # time_pin_error_read_files()

    if VERBOSE:
        logger.info("Start testing - write")

    # success_write_files()
    # success_overwrite_files()
    pin_error_write_files()
    permission_error_write_files()
    # time_success_write_files()
    # time_pin_error_write_files()

    if VERBOSE:
        logger.info("Start testing - listen")

    #listen tests 
    success_listen()


if __name__ == "__main__":
    main()
