"""
Author: Samuel Meyers
Date: 2026
"""

import os
import json
import argparse
from dataclasses import dataclass
import hashlib


def _c_multiline_string_literal(s: str) -> str:
    lines = s.strip("\n").splitlines()
    return "\n".join(f"\"{line}\\n\"" for line in lines) + "\n"


def _format_key_as_c_array(key_hex: str, included: bool) -> str:
    """
    Formats a hex string into a C byte array.
    If not included, returns { 0 }.
    """
    if not included or not key_hex:
        return "{ 0 }"

    # Convert hex string to bytes
    try:
        b = bytes.fromhex(key_hex)
    except ValueError:
        print(f"Error: Invalid hex string: {key_hex}")
        return "{ 0 }"
    
    hex_str = ", ".join(f"0x{x:02x}" for x in b)
    return f"{{ {hex_str} }}"


@dataclass
class Permission:
    group_id: int=None
    read: bool=False
    write: bool=False
    receive: bool=False

    @classmethod
    def deserialize(cls, perms: str):
        # Format: GID=RWC (e.g., 1234=R--)
        group_id, perm_string = perms.split('=')
        perm_obj = cls(
            int(group_id, 0), # Handle 0x prefix or decimal
            read = perm_string[0] == 'R',
            write = perm_string[1] == 'W',
            receive = perm_string[2] == 'C',
        )
        return perm_obj

    def serialize(self):
        ret = f'{self.group_id:04x}='
        ret += 'R' if self.read else '-'
        ret += 'W' if self.write else '-'
        ret += 'C' if self.receive else '-'
        return ret


class PermissionList(list):
    def __init__(self, *args):
        for item in args:
            if isinstance(item, Permission):
                self.append(item)

    @classmethod
    def deserialize(cls, perms: str):
        ret = cls()
        if not perms:
            return ret
        permissions_strings = perms.split(":")
        for entry in permissions_strings:
            perm_obj = Permission.deserialize(entry)
            ret.append(perm_obj)
        return ret

    def serialize(self):
        return ':'.join(perm.serialize() for perm in self)


def secrets_to_c_header(
    permissions: PermissionList, path: str, hsm_pin: str, secrets_data: bytes
):
    try:
        secrets_dict = json.loads(secrets_data)
    except json.JSONDecodeError:
        print("Error: Invalid secrets file format. Expecting JSON.")
        return

    # Hash the PIN
    h = hashlib.sha256(hsm_pin.encode("utf-8")).digest()
    
    # Track which groups we actually found secrets for
    found_groups = set()

    # Ensure output directory exists
    os.makedirs(path, exist_ok=True)

    with open(os.path.join(path, "secrets.h"), 'w') as f:
        f.write("#ifndef __SECRETS_H__\n")
        f.write("#define __SECRETS_H__\n\n")
        f.write('#include "security.h"\n\n')
        
        # Write HSM PIN Hash
        f.write("static const uint8_t HSM_PIN_HASH[32] = {\n    ")
        f.write(", ".join(f"0x{b:02x}" for b in h))
        f.write("\n};\n\n")

        # Write Struct Definition for SECP256R1
        f.write("// SECP256R1 Keys derived from gen_secrets.py\n")
        f.write("typedef struct {\n")
        f.write("    uint8_t read_key[32];   // Private Key (Scalar)\n")
        f.write("    uint8_t write_key[65];  // Public Key (Uncompressed)\n")
        f.write("    uint8_t verify_key[32]; // Private Key (Scalar)\n")
        f.write("    uint8_t check_key[65];  // Public Key (Uncompressed)\n")
        f.write("} group_secrets_t;\n\n")

        # Iterate permissions to generate secret definitions
        # Note: keys in secrets_dict are strings (e.g. "1234"), but permissions use ints
        # We need to normalize lookups.
        
        # Create a lookup map for secrets where keys are integers
        normalized_secrets = {int(k): v for k, v in secrets_dict.items()}

        for perm in permissions:
            gid = perm.group_id
            
            if gid not in normalized_secrets:
                print(f"Warning: Group {gid} found in permissions but not in secrets file.")
                continue
            
            # Mark group as found so we can reference it later
            found_groups.add(gid)

            keys = normalized_secrets[gid]
            # gen_secrets now returns [read_hex, write_hex, verify_hex, check_hex]
            read_key_hex = keys[0]
            write_key_hex = keys[1]
            verify_key_hex = keys[2]
            check_key_hex = keys[3]

            f.write(f"// Secrets for Group 0x{gid:04x}\n")
            f.write(f"static const group_secrets_t GROUP_{gid}_SECRETS = {{\n")
            f.write(f"    .read_key   = {_format_key_as_c_array(read_key_hex,  included=perm.read)},\n")
            f.write(f"    .write_key  = {_format_key_as_c_array(write_key_hex, included=perm.write)},\n")
            f.write(f"    .verify_key = {_format_key_as_c_array(verify_key_hex, included=perm.receive)},\n")
            f.write(f"    .check_key  = {_format_key_as_c_array(check_key_hex, included=perm.receive)}\n")
            f.write("};\n\n")

        # Create the array of pointers
        f.write(f"static const group_secrets_t* global_secrets[{len(permissions)}] = {{\n")
        for perm in permissions:
            if perm.group_id in found_groups:
                f.write(f"    &GROUP_{perm.group_id}_SECRETS,\n")
            else:
                # If secrets weren't found, put NULL (0)
                f.write(f"    0, // No secrets for group {perm.group_id}\n")
        f.write("};\n\n")

        # Write Global Permissions Array
        f.write(f"const static group_permission_t global_permissions[{len(permissions)}] = {{\n")
        for perm in permissions:
            f.write(
                (f"    {{ {hex(perm.group_id)}, {str(perm.read).lower()}, "
                 f"{str(perm.write).lower()}, {str(perm.receive).lower()} }},\n")
            )
        f.write("};\n")
        
        f.write("\n#endif  // __SECRETS_H__\n")


if __name__ == '__main__':
    def parse_args():
        parser = argparse.ArgumentParser()
        parser.add_argument("secrets", type=argparse.FileType("rb"), help="Path to secrets file")
        parser.add_argument("hsm_pin", type=str, help="User PIN for the HSM")
        parser.add_argument("permissions", type=str, help="List of colon-separated permissions.")
        return parser.parse_args()

    args = parse_args()
    
    # Handle the case where permissions string might be empty or malformed
    try:
        perms = PermissionList.deserialize(args.permissions)
    except Exception as e:
        print(f"Error parsing permissions: {e}")
        exit(1)

    secrets_to_c_header(perms, './inc/', args.hsm_pin, args.secrets.read())