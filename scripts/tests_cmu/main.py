# before run, remember to restart the board
# cmd: python scripts/tests/main.py -p $uart_port

from test_list import *
from test_subscription import *
from test_frame import *

import argparse
import glob
import os
from loguru import logger


def reset_board():
    if common.VERBOSE:
        os.system(
            "openocd -f interface/cmsis-dap.cfg -f target/max78000.cfg -c 'init; reset; exit;'"
        )
    else:
        os.system(
            "openocd -f interface/cmsis-dap.cfg -f target/max78000.cfg -c 'init; reset; exit;' > /dev/null 2>&1"
        )
    time.sleep(1)


def del_subscription_files():
    for f in glob.glob("test_*"):
        os.remove(f)


def parse_args():
    # Create the argument parser
    parser = argparse.ArgumentParser()

    # Add the argument --port or -p
    parser.add_argument(
        "--port",
        "-p",
        type=str,
        required=True,
        default=common.UART_PORT,
        help="Specify the serial port of the board",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print logs for debugging"
    )

    return parser.parse_args()


def main():
    args = parse_args()
    common.UART_PORT = args.port

    if args.verbose:
        common.VERBOSE = True

    reset_board()

    del_subscription_files()

    if common.VERBOSE:
        logger.info("Start testing - list 0 channel")

    success_list_channel(0)

    if common.VERBOSE:
        logger.info("Start testing - decode frames in channel 0")
    success_frame_channel_0_all()

    if common.VERBOSE:
        logger.info("Start testing - decode duplicate frames")
    fail_frame_duplicate_timstamp()

    if common.VERBOSE:
        logger.info("Start testing - decode frames without subscription")

    fail_frame_no_subscription_attack()

    if common.VERBOSE:
        logger.info("Start testing - subscribe 7 channels with random")

    for i in range(0, 7):
        # hardcoded number for running stress_test
        start = 0
        end = common.MAX_TIMESTAMP
        success_update_subscription(start, end, common.CHANNELS[i], common.DECODER_ID)

        success_list_channel(i + 1)

    if common.VERBOSE:
        logger.info(
            f"Start testing - subscribe 8th channels with id {common.MAX_CHANNEL_ID}"
        )
    success_update_subscription(
        0, common.MAX_TIMESTAMP, common.MAX_CHANNEL_ID, common.DECODER_ID
    )
    success_list_channel(8)

    if common.VERBOSE:
        logger.info(f"Start testing - subscribe 9th channels")
    fail_subscribe_more_than_8_channels()

    if common.VERBOSE:
        logger.info("Start testing - subscribe with wrong decoder id")
    fail_subscribe_wrong_decoder_id()

    fail_subscribe_channel_0()

    del_subscription_files()

    if common.VERBOSE:
        logger.info("Start testing - update subscription (channel 4)")
    del_subscription_files()
    success_update_subscription(0x10, 0x30, 4, common.DECODER_ID)

    if common.VERBOSE:
        logger.info("Start testing - decode frames in channel 0 second times")
    reset_board()
    success_frame_channel_0_all()

    if common.VERBOSE:
        logger.info("Start testing - decode frames in a valid and activate channel")
    reset_board()
    success_frame_within_subscription_time()

    if common.VERBOSE:
        logger.info(
            "Start testing - decode frames from a channel with a timestamp eariler than subscription start time"
        )
    reset_board()
    fail_frame_playback_attack()

    if common.VERBOSE:
        logger.info("Start testing - decode frames from a subscription-expired channel")
    reset_board()
    fail_frame_expired_attack()

    if common.VERBOSE:
        logger.info("Start testing - decode frames from a channel with unknown decoder")
    reset_board()
    fail_frame_pirated_attack()

    reset_board()
    del_subscription_files()

    if common.VERBOSE:
        logger.info("Start testing - frame stress test")
    success_frame_stress_test()

    if common.VERBOSE:
        logger.info("Start testing - list channel time")
    test_list_channels_time()

    if common.VERBOSE:
        logger.info("Start testing - update subscription time")
    test_update_sub_time()


if __name__ == "__main__":
    main()
