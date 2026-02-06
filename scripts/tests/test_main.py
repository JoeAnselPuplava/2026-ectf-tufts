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

from test_com_l import * 

import argparse
import os
import time

# reset board to prevent error 
def reset_board(): 
    if test_common.VERBOSE:
        os.system( # probably need new commands 
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
        "--port",
        "-p",
        type=str,
        required=True,
        default=test_common.UART_PORT,
        help="Specify the serial port of the board",
    )
    parser.add_argument(
        "--verbose", 
        "-v", 
        action="store_true", 
        help="Print logs for debugging"
    )

    return parser.parse_args()

def main(): 
    args = parse_args()
    test_common.UART_PORT = args.port

    if args.verbose:
        test_common.VERBOSE = True

    reset_board() 
    delete_test_files() 

    # start calling tests 
    if test_common.VERBOSE:
        logger.info("Start testing - list")

    success_list_files()

    pin_error_list_files()

    time_success_list_files() 

    time_pin_error_list_files()


if __name__ == "__main__":
    main()