"""
Author: Ben Janis
Date: 2026

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import argparse
import json
from pathlib import Path

from loguru import logger

import secrets
from py_ecc.bls.ciphersuites import G2ProofOfPossession


def gen_secrets(groups: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf26_design.gen_secrets,
    and the build process of the firmware

    NOTE: you should NOT write to secrets files within this function.
    All generated secrets must be contained in the returned bytes
    object.

    :param groups: List of permission groups that will be valid in this
        deployment.

    :returns: Contents of the secrets file
    """

    # Create the secrets dictionary
    glob_sec = {}

    for group in groups:
        # Generate Seeds
        e_seed = secrets.token_bytes(32)
        v_seed = secrets.token_bytes(32)

        # Generate Keys
        r_key = G2ProofOfPossession.KeyGen(e_seed)
        w_key = G2ProofOfPossession.SkToPk(r_key)
        v_key = G2ProofOfPossession.KeyGen(v_seed)
        c_key = G2ProofOfPossession.SkToPk(v_key)

        # read_key = "1"
        # write_key = "1"
        # verify_key = "1"
        # check_key = "1"

        read_key = str(r_key)
        write_key = str(w_key)
        verify_key = str(v_key)
        check_key = str(c_key)

        # Add groups and keys to dictionary 
        glob_sec[group] = {
            "read_key": read_key,
            "write_key": write_key,
            "verify_key": verify_key,
            "check_key": check_key,
        }

    return json.dumps(glob_sec).encode()


def parse_args():
    """Define and parse the command line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "groups",
        nargs="+",
        type=lambda x: int(x, 0),
        help="Supported group IDs",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.groups)

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
