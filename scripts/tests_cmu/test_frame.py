from ectf25.utils import Encoder
import common

from loguru import logger
import subprocess
import time
import re
import math
from collections import namedtuple
import random
from tqdm import tqdm
import json
import base64


raw_frame_pattern = re.compile(r"RAW IN.*?b'([^']*)'")
error_pattern = re.compile("Failed to decode frame..*")
decoded_frame_pattern = re.compile(r"DEC OUT.*?b'([^']*)'")
stat_decode_pattern = re.compile("STATS: .+ decoder (\\d+) B/s")
frame_throughput_pattern = re.compile(r"Throughput.*?([\d.]+) KBps")

STRESS_TEST_DUMP = "test_frame.dump"
STRESS_TEST_SIZE = 1000

# maximum transmitting time per frame is 150 ms (0.15 s)
DECODE_TIME_REQUIREMENT = 0.15
# encoder - minimum throughput is 64KBps
ENCODE_THROUGHPUT_REQUIREMENT = 64.0
# decoder - minimum throughput is 640Bps (0.64KBps)
DECODE_THROUGHPUT_REQUIREMENT = 0.64

Frame = namedtuple("Frame", ["channel", "data", "timestamp"])


# channel 0 should successfully run any frames
# covered cases:
# 1. frame at timestamp 0
# 2. frame at the last timestamp 0xFFFFFFFFFFFFFFFF
# 3. frame = 64B
# 4. frame < 64B
# 5. frame = 0B
def success_frame_channel_0_all():
    channel = 0
    for raw_frame, decoded_frame, err_matched in process(frames(channel)):
        check_success(raw_frame, decoded_frame, err_matched)

    logger.success("success_frame_channel_0_all passed")


# channel 4 subscription time from 16 to 48
# convered ceses:
# 1. frames time == 16
# 2. frames time > 16 and < 48
# 3. frames time == 48
def success_frame_within_subscription_time():
    channel = 4
    fs = frames(channel)[6:9]
    for raw_frame, decoded_frame, err_matched in process(fs):
        check_success(raw_frame, decoded_frame, err_matched)

    logger.success("success_frame_within_subscription_time passed")


def success_frame_stress_test():
    gen_stress_test_frames()
    res = process_decoder_stress_test()
    decode_throughput_matched = frame_throughput_pattern.search(res.stderr)
    assert decode_throughput_matched is not None, (
        "stress_test - decoder throughput logged"
    )

    throughput = float(decode_throughput_matched.group(1))
    assert throughput > DECODE_THROUGHPUT_REQUIREMENT, (
        "stress_test - decoder throughput {throughput}KBps meeted the requirement {DECODE_THROUGHPUT_REQUIREMENT}KBps"
    )

    logger.success("success_frame_stress_test - decoder passed")


def fail_frame_duplicate_timstamp():
    channel = 0
    for _, _, err_matched in process(dup_frames(channel)):
        check_fail(err_matched)

    logger.success("success_frame_duplicate_timestamp passed")


# channel 4 subscription time from 16 to 48
# covered cases:
# 1. frames time < 16
def fail_frame_playback_attack():
    channel = 4
    fs = frames(channel)[0:6]
    for _, _, err_matched in process(fs):
        check_fail(err_matched)

    logger.success("fail_playback_attack passed")


# channel 4 subscription time from 16 to 48
# covered cases
# 1. frames time > 48
def fail_frame_expired_attack():
    channel = 4
    fs = frames(channel)[9:12]
    for _, _, err_matched in process(fs):
        check_fail(err_matched)

    logger.success("fail_expired_attack passed")


# channel 5 -> no subscrpition
def fail_frame_no_subscription_attack():
    channel = 5
    fs = frames(channel)
    for _, _, err_matched in process(fs):
        check_fail(err_matched)

    logger.success("fail_no_subscription passed")


# covered cases
# 1. valid subscription but not for the decoder (decoder doesn't have the correct key)
def fail_frame_pirated_attack():
    channel = 3
    sec_path = "test_neighbor_secrets"
    gen_secrets(sec_path, channel)

    fs = frames(channel)
    for _, _, err_matched in process(fs, sec_path):
        check_fail(err_matched)

    logger.success("fail_pirated passed")


# PRIVATE METHOD


def check_success(raw_frame, decoded_frame, err_matched):
    assert err_matched == None, "tester ran without errors"
    assert raw_frame == decoded_frame, "host received correct frame"


def check_fail(err_matched):
    assert err_matched is not None, "tester ran with expected error"


# run encoder and decoder
def process(fs, sec_path=None):
    if sec_path == None:
        sec_path = common.SECRETS_PATH

    cmd = [
        ".venv/bin/python",
        "-m",
        "ectf25.utils.tester",
        "--port",
        common.UART_PORT,
        "--perf",
        "-s",
        sec_path,
        "stdin",
    ]
    for channel, frame, timestamp in fs:
        raw_frame = ""
        decoded_frame = ""

        process = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        process.stdin.write(f"{channel},{frame.decode()},{timestamp}")

        process.stdin.close()

        for line in iter(process.stderr.readline, ""):
            if common.VERBOSE:
                print(line)

            raw_frame_matched = raw_frame_pattern.search(line)
            if raw_frame_matched:
                raw_frame = raw_frame_matched.group(1)

            err_matched = error_pattern.search(line)

            decoded_frame_matched = decoded_frame_pattern.search(line)
            if decoded_frame_matched:
                decoded_frame = decoded_frame_matched.group(1)

            stat_matched = stat_decode_pattern.search(line)
            if stat_matched:
                decode_throughput = int(stat_matched.group(1))
                if decode_throughput > 0:
                    decode_time = len(raw_frame) / decode_throughput
                    # each decode time should less than 150 milliseconds
                    assert (decode_time) < DECODE_TIME_REQUIREMENT, (
                        f"tester - frame decode time {decode_time} less than requirement {DECODE_TIME_REQUIREMENT}"
                    )

        yield raw_frame, decoded_frame, err_matched

        process.terminate()


def process_decoder_stress_test():
    cmd = [
        "ectf25.utils.stress_test",
        "--test-size",
        str(STRESS_TEST_SIZE),
        "decode",
        common.UART_PORT,
        STRESS_TEST_DUMP,
    ]
    return common.process(cmd)


def gen_secrets(sec_path, channel):
    cmd = ["ectf25_design.gen_secrets", sec_path, str(channel)]
    common.process(cmd)


def gen_stress_test_frames():
    test_size = STRESS_TEST_SIZE
    frame_size = 64
    channels = [0, 1, 2, 3]
    sec = open(common.SECRETS_PATH, "rb").read()
    encoder = Encoder(sec)
    nframes = math.ceil(test_size / frame_size)
    logger.info(f"Generating frames ({nframes:,} {frame_size}B frames)...")
    logger.info("Running stress test...")

    encoded_frames = []
    start = time.perf_counter()
    for _ in range(nframes):
        frame = Frame(
            random.choice(channels),  # pick random channel
            random.randbytes(frame_size),  # generate random frame
            time.time_ns() // 1000,  # generate microsecond timestamp
        )
        try:
            encoded_frames.append(
                Frame(frame.channel, encoder.encode(*frame), frame.timestamp)
            )
        except Exception as e:
            logger.error(f"Errored on frame {frame}!")
            raise e
    total = time.perf_counter() - start

    logger.info("Dumping encoded frames...")
    fp = open(STRESS_TEST_DUMP, "w")
    json.dump(
        [
            [
                frame.channel,  # channel
                base64.b64encode(frame.data).decode(),  # encoded frame
                frame.timestamp,  # timestamp
            ]
            for frame in tqdm(encoded_frames)
        ],
        fp,
    )
    time.sleep(0.001)


def frames(channel):
    return [
        [
            channel,
            b"X---------------------------------------------------------------",
            0,
        ],
        [
            channel,
            b"X---------------------------------------------------------------",
            4,
        ],
        [
            channel,
            b"-X--------------------------------------------------------------",
            5,
        ],
        [
            channel,
            b"-X--------------------------------------------------------------",
            8,
        ],
        [channel, b"-X---------------------------------------", 10],
        [channel, b"", 14],
        [
            channel,
            b"--X-------------------------------------------------------------",
            16,
        ],
        [
            channel,
            b"--X-------------------------------------------------------------",
            20,
        ],
        [
            channel,
            b"--X-------------------------------------------------------------",
            48,
        ],
        [
            channel,
            b"--X-------------------------------------------------------------",
            49,
        ],
        [
            channel,
            b"--X-------------------------------------------------------------",
            60,
        ],
        [
            channel,
            b"--X-------------------------------------------------------------",
            0xFFFFFFFFFFFFFFFF,
        ],
    ]


def dup_frames(channel):
    return [
        [
            channel,
            b"X---------------------------------------------------------------",
            5,
        ],
        [
            channel,
            b"X---------------------------------------------------------------",
            5,
        ],
        [
            channel,
            b"-X--------------------------------------------------------------",
            5,
        ],
    ]
