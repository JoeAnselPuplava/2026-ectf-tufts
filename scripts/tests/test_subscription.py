import common
from test_list import success_list_channel

import time
from loguru import logger


UPDATE_SUB_TIME_CONSTRAINT = 500


def success_gen_subscription(start, end, channel, decoder_id):
    res = gen_sub(start, end, channel, decoder_id)
    assert res.stderr == "", "gen_subscription ran without error"


def success_subscribe(channel, start, end, suppress_output=False):
    process_time = time.perf_counter()
    res = subscribe(channel)
    process_time = time.perf_counter() - process_time

    # print success
    common.check_result(
        "SUCCESS.+Subscribe successful", res.stderr, "subscribe ran without error"
    )

    if not suppress_output:
        logger.success(f"success_subscribe with channel {channel} - passed")

    # save to subscription list
    index = next(
        (i for i, s in enumerate(common.SUBSCRIPTION_LIST) if s[0] == str(channel)), -1
    )
    if index != -1:
        # update existing item
        common.SUBSCRIPTION_LIST[index] = (str(channel), str(start), str(end))
    else:
        common.SUBSCRIPTION_LIST.append((str(channel), str(start), str(end)))

    return process_time


def fail_subscribe(channel):
    res = subscribe(channel)
    # print should  fail
    check_fail(res, "subscribe ran with expected error")


def success_update_subscription(start, end, channel, decoder_id):
    success_gen_subscription(start, end, channel, decoder_id)
    success_subscribe(channel, start, end)


def fail_subscribe_more_than_8_channels():
    success_list_channel(8, suppress_output=True)

    start, end = common.get_random_period()
    success_gen_subscription(start, end, common.CHANNELS[8], common.DECODER_ID)

    fail_subscribe(common.CHANNELS[8])
    success_list_channel(8, suppress_output=True)
    logger.success("fail_subscribe_more_than_8_channels - passed")

    common.remove_if_exists(sub_bin(common.CHANNELS[8]))


def fail_subscribe_wrong_decoder_id():
    wrong_decoder_id = common.MAX_DECODER_ID
    channel = common.get_random_channel()
    common.remove_if_exists(sub_bin(channel))

    start, end = common.get_random_period()
    success_gen_subscription(start, end, channel, wrong_decoder_id)
    fail_subscribe(channel)

    logger.success("fail_subscribe_wrong_decoder_id - passed")

    common.remove_if_exists(sub_bin(channel))


def fail_subscribe_channel_0():
    channel = 0
    start, end = common.get_random_period()
    success_gen_subscription(start, end, channel, common.DECODER_ID)
    fail_subscribe(channel)

    logger.success("fail_subscribe_channel_0 - passed")
    common.remove_if_exists(sub_bin(channel))


def test_update_sub_time():
    total_time = 0
    for _ in range(common.ITERATIONS):
        channel = common.get_random_subscribed_channel()
        start, end = common.get_random_period()
        gen_sub(start, end, channel, common.DECODER_ID)

        time = success_subscribe(channel, start, end, suppress_output=True)
        time_taken = (time) * 1000
        assert time_taken < UPDATE_SUB_TIME_CONSTRAINT, (
            f"Avg. time for Subscription Update exceeded {UPDATE_SUB_TIME_CONSTRAINT}ms: got {time_taken}ms."
        )
        common.remove_if_exists(sub_bin(channel))

    logger.success(f"Timing requirement for `Update Subscription` - passed")


# PRIVATE METHOD
def sub_bin(channel):
    return f"test_sub{channel}.bin"


def gen_sub(start, end, channel, decoder_id):
    cmd = [
        "ectf25_design.gen_subscription",
        "global.secrets",
        sub_bin(channel),
        str(decoder_id),
        str(start),
        str(end),
        str(channel),
    ]
    return common.process(cmd)


def subscribe(channel):
    cmd = ["ectf25.tv.subscribe", sub_bin(channel), common.UART_PORT]
    return common.process(cmd)


def check_fail(res, out_str):
    common.check_result(
        r"Opcode\.ERROR.+Failed to update subscription", res.stderr, out_str
    )
