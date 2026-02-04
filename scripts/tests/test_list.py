import common

import time
import re
from loguru import logger

LIST_TIME_CONSTRAINT = 500


def success_list_channel(expected_number, suppress_output=False):
    process_time = time.perf_counter()
    res = list_channel()
    process_time = time.perf_counter() - process_time

    logs = res.stderr
    # list correct number
    common.check_result(
        "ectf25.utils.decoder:list.+Reported {} subscribed channels".format(
            expected_number
        ),
        logs,
        f"list exact {expected_number} channels",
    )

    # print SUCCESS
    common.check_result("SUCCESS.+ List successful", logs, "list ran without error")

    pattern = re.compile(r"Found subscription: Channel (\d+) (\d+):(\d+)")
    matches = pattern.findall(logs)
    assert len(matches) == expected_number
    assert len(matches) == len(common.SUBSCRIPTION_LIST)

    for i in range(expected_number):
        assert matches[i] == common.SUBSCRIPTION_LIST[i]

    if not suppress_output:
        logger.success(f"test_list_channel {expected_number} channels - passed")

    return process_time


def test_list_channels_time():
    total_time = 0
    for _ in range(common.ITERATIONS):
        time = success_list_channel(8, suppress_output=True)
        time_taken = (time) * 1000
        assert time_taken < LIST_TIME_CONSTRAINT, (
            f"Avg. time for List Channels exceeded {LIST_TIME_CONSTRAINT}ms: got {time_taken}ms."
        )

    logger.success(f"Timing requirement for `List Channels` - passed")


# PRIVATE METHOD


def list_channel():
    cmd = ["ectf25.tv.list", common.UART_PORT]
    return common.process(cmd)
