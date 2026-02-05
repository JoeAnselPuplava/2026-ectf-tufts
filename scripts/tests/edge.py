from ectf25_design.gen_secrets import gen_secrets
from ectf25_design.encoder import Encoder
from ectf25_design.gen_subscription import gen_subscription
from ectf25.utils.flash import BootloaderIntf
from ectf25.utils import decoder

from pathlib import Path
import random
import os
from time import sleep
from copy import copy
from loguru import logger
import argparse
from typing import Self

# helpers

U32_MAX = 0xFFFF_FFFF
U64_MAX = 0xFFFF_FFFF_FFFF_FFFF


def assert_eq(a, b, msg: str):
    assert a == b, f"{msg}: {a!r} == {b!r}"


def flipbit(data: bytes) -> bytes:
    idx = random.randint(0, len(data) - 1)
    bit = random.randint(0, 7)
    arr = bytearray(data)
    arr[idx] ^= 1 << bit
    return bytes(arr)


def randts(start=0, end=U64_MAX):
    return random.randint(start, end)


class Subscription:
    def __init__(self, chan, start, end) -> None:
        if type(chan) is list:
            chan = random.choice(chan)
        self.chan = chan
        self.start = start
        self.end = end

    def frame(self, ts, len=None):
        return Frame(self.chan, ts, len)

    def list_entry(self):
        return (self.chan, self.start, self.end)

    def subscribe_inner(
        self, dec: decoder.DecoderIntf, secrets: bytes, device: int, modifier=None
    ):
        sub = gen_subscription(secrets, device, self.start, self.end, self.chan)
        if modifier is not None:
            sub = modifier(sub)
        try:
            dec.subscribe(sub)
            return True
        except decoder.DecoderError:
            return False

    def subscribe(
        self,
        dec: decoder.DecoderIntf,
        secrets: bytes,
        device: int,
        msg: str,
        modifier=None,
    ) -> Self:
        assert self.subscribe_inner(dec, secrets, device, modifier), (
            f"subscribe failed when success expected: {msg}"
        )
        return self

    def subscribe_fail(
        self,
        dec: decoder.DecoderIntf,
        secrets: bytes,
        device: int,
        msg: str,
        modifier=None,
    ) -> Self:
        assert not self.subscribe_inner(dec, secrets, device, modifier), (
            f"subscribe succeeded when failure expected: {msg}"
        )
        return self


class Frame:
    def __init__(self, chan, ts, len=None) -> None:
        self.chan = chan
        self.ts = ts
        if len is None:
            len = random.randint(0, 64)
        self.frame = random.randbytes(len)

        assert 0 <= len <= 64

    def test_inner(self, enc: Encoder, dec: decoder.DecoderIntf, modifier=None) -> bool:
        data = enc.encode(self.chan, self.frame, self.ts)
        if modifier is not None:
            data = modifier(data)
        try:
            res = dec.decode(data)
            # if decode succeeds but data differs, that's ALWAYS an error
            assert_eq(res, self.frame, "decode succeeded but frame differs")
            return True
        except decoder.DecoderError:
            return False

    def test(
        self, enc: Encoder, dec: decoder.DecoderIntf, msg: str, modifier=None
    ) -> Self:
        assert self.test_inner(enc, dec, modifier), (
            f"decode failed when success expected: {msg}"
        )
        return self

    def test_fail(
        self, enc: Encoder, dec: decoder.DecoderIntf, msg: str, modifier=None
    ) -> Self:
        assert not self.test_inner(enc, dec, modifier), (
            f"decode succeeded when failure expected: {msg}"
        )
        return self


def main():
    # parse args
    parser = argparse.ArgumentParser()

    parser.add_argument("port", type=str, help="Port of max78000 board")
    parser.add_argument(
        "--auto", "-a", action="store_true", help="Use ectf25_button to reset board"
    )

    args = parser.parse_args()

    # ensure running in root of repo
    repo_root = Path(__file__).parent.parent.parent
    os.chdir(repo_root)

    # randomize test
    seed = os.urandom(4)
    logger.debug(f"SEED: {seed}")
    random.seed(seed)

    channels = [random.randint(1, U32_MAX) for i in range(8)]
    decoder1 = random.randint(0, U32_MAX)
    decoder2 = random.randint(0, U32_MAX)  # pirate's device (not ours)

    timeslices = [randts() for i in range(1024)]
    timeslices.sort()

    def t():
        return timeslices.pop(0)

    # generate deployments
    deploy1 = gen_secrets(channels)
    logger.debug(f"deployment 1: {deploy1}")
    with open("global.secrets", "wb") as f:
        f.write(deploy1)

    deploy2 = gen_secrets(channels)  # "imposter" 2nd deployment
    logger.debug(f"deployment 2 (imposter): {deploy2}")

    # build decoder
    assert os.system(f"DECODER_ID={decoder1} decoder/build.sh build") == 0, (
        "build did not succeed"
    )

    # deploy decoder
    bl = BootloaderIntf(args.port)

    with open("decoder/build/max78000.bin", "rb") as f:
        image = f.read()

    if args.auto:
        assert os.system("ectf25_button b") == 0, "could not press button"
    else:
        input("put in bootloader mode, then press enter ")
    sleep(3)
    bl.update(image)
    sleep(3)
    # .update closes the serial port

    d = decoder.DecoderIntf(args.port)
    e = Encoder(deploy1)
    e2 = Encoder(deploy2)

    # begin actual testcases

    # test: decode frames on channel 0 fine
    for i in range(10):
        Frame(0, t()).test(e, d, "channel 0 should always work")

    oldts1 = t()
    Frame(0, oldts1).test(e, d, "channel 0 should always work")

    # test: reject frames from other deployment's channel 0
    oldts2 = t()
    Frame(0, oldts2).test_fail(e2, d, "channel 0 decodes for wrong deployment")

    # test: reject old frames
    Frame(0, oldts2).test(e, d, "valid frame")
    Frame(0, oldts2).test_fail(e, d, "frame with repeated timestamp decoded")
    Frame(0, oldts1).test_fail(e, d, "frame with old timestamp decoded")

    # test: no subscriptions listed
    assert_eq(d.list(), [], "found subscription when none should be present")

    # test: reject subscription for wrong decoder
    oldts = t()
    sub1 = Subscription(channels, t(), U64_MAX)
    sub1.subscribe_fail(d, deploy1, decoder2, "accepted subscription for wrong decoder")

    # test: still no subscriptions listed
    assert_eq(d.list(), [], "found subscription after failed subscribe")

    # test: accept valid subscription
    sub1.subscribe(d, deploy1, decoder1, "rejected valid subscription")

    # test: list subscription is correct
    assert_eq(
        d.list(), [sub1.list_entry()], "subscription list missing valid subscription"
    )

    # test: reject frame before subscription
    sub1.frame(oldts).test_fail(e, d, "accepted frame before subscription start")

    # test: reject subscription for right decoder, wrong deployment
    start = randts()
    end = randts(start, U64_MAX)
    sub2 = Subscription(sub1.chan, start, end)
    sub2.subscribe_fail(
        d, deploy2, decoder1, "accepted subscription for wrong deployment"
    )

    # test: reject valid subscription with bit flipped
    for i in range(10):
        sub2.subscribe_fail(
            d,
            deploy1,
            decoder1,
            modifier=flipbit,
            msg="accepted corrupted subscription",
        )

    # test: list subscription is still correct
    assert_eq(
        d.list(),
        [sub1.list_entry()],
        "subscription list not as expected after failed subscribes",
    )

    # test: successfully decodes frames
    for i in range(10):
        sub1.frame(t()).test(e, d, "rejected frame from valid/active subscription")

    # test: update existing subscription
    oldts = t()  # valid for sub1 but invalid for sub3
    start = t()
    t1 = t()
    t2 = t()
    t3 = t()
    end = t()
    sub3 = Subscription(sub1.chan, start, end)
    sub3.subscribe(d, deploy1, decoder1, "failed to update existing subscription")

    # test: list still only shows 1
    assert_eq(
        d.list(),
        [sub3.list_entry()],
        "subscription list doesn't show only new subscription",
    )

    # test: fail to decode updated subscription if in old range
    sub3.frame(oldts).test_fail(e, d, "decoded frame for updated subscription")

    # test: successfully decode frames at exactly start of subscription
    sub3.frame(start).test(e, d, "rejected frame from exact start of subscription")

    # test: reject frames from valid+active subscription but wrong deployment
    sub3.frame(t1).test_fail(e2, d, "accepted frame from wrong deployment")

    # test: reject valid frames with flipped bits
    for i in range(10):
        sub3.frame(t2).test_fail(e, d, modifier=flipbit, msg="accepted corrupted frame")

    # test: successfully decode frames at exactly end of subscription
    sub3.frame(end).test(e, d, "rejected frame from exact end of subscription")

    # test: make sure it can't decode the unsubscribed channels
    otherchans = copy(channels)
    otherchans.remove(sub3.chan)
    for chan in otherchans:
        Frame(chan, t3).test_fail(e, d, "accepted frame from unsubscribed channel")

    # test: reject frames after subscription
    sub3.frame(t()).test_fail(e, d, "accepted frame from expired subscription")

    # test: subscribe to the the rest of the channels (8 total)
    # test: make sure it can decode in range for all of them
    subs = [sub3]
    for chan in otherchans:
        start = t()
        t1 = t()
        end = t()
        sub = Subscription(chan, start, end)
        subs.append(sub)
        sub.frame(start).test_fail(e, d, "decoded frame on unsubscribed channel")
        sub.subscribe(d, deploy1, decoder1, "rejected valid subscription")
        sub.frame(start).test(e, d, "rejected valid/active frame")

    # test: list all channels now that all are subscribed
    l = d.list()
    for sub in subs:
        assert sub.list_entry() in l, (
            f"subscription {sub.list_entry()} is not in listing: {l}"
        )

    # encoder test: nonce is changing
    frames = []
    for i in range(10):
        f = e.encode(0, b"", U32_MAX)
        assert f not in frames, "repeated encryption yielded same data"
        frames.append(f)

    logger.success("all tests passed")


if __name__ == "__main__":
    main()
