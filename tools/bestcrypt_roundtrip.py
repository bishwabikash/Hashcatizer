#!/usr/bin/env python3
"""Reverse JtR's BestCrypt test vectors into DATA_BLOCK containers.

Each vector in bestcrypt_fmt_plug.c came from a real container, so rebuilding
the header from its fields and re-extracting is a genuine round-trip check of
the parser: if our converter reproduces the vector byte for byte, it is reading
the same offsets JtR's extractor wrote from.
"""
import re
import struct
import subprocess
import sys

BIN = "/home/deadlock/Desktop/Vibe-Coding/Hashcatizer/target/release/hashcatizer"
KEY_SLOT_SIZE = 256
ACTIVE_SLOT = 1


def build(keygen, wver, iterations, alg, mode, hash_id, salt, key):
    """Lay the fields back out at the offsets DATA_BLOCK_64_fmt defines."""
    blk = bytearray(1536 + 2560)

    blk[3:11] = b"LOCOS94 "
    blk[43:54] = b"BC_KeyGenID"
    struct.pack_into("<H", blk, 54, keygen)
    struct.pack_into("<H", blk, 56, wver)
    struct.pack_into("<I", blk, 58, iterations)
    struct.pack_into("<I", blk, 128, alg)
    struct.pack_into("<I", blk, 132, mode)
    struct.pack_into("<I", blk, 136, hash_id)

    # keymap: slot 0 carries the salt, slot 1 an active key, rest empty.
    struct.pack_into("<HhI", blk, 140 + 0 * 8, 0, 5, 0)
    struct.pack_into("<HhI", blk, 140 + ACTIVE_SLOT * 8, 0, 1, 0)

    keys = 1536
    blk[keys : keys + len(salt)] = salt
    off = keys + ACTIVE_SLOT * KEY_SLOT_SIZE
    blk[off : off + len(key)] = key
    return bytes(blk)


def main():
    src = open("bcv.c").read()
    vectors = re.findall(r'\{"(\$BestCrypt\$[^"]+)"\s*,\s*"([^"]*)"\}', src)

    ok = bad = 0
    for i, (expected, _pw) in enumerate(vectors):
        f = expected.split("$")
        keygen, wver, iterations = int(f[3]), int(f[4]), int(f[5])
        alg, mode, hash_id = int(f[6]), int(f[7]), int(f[8])
        salt, key = bytes.fromhex(f[10]), bytes.fromhex(f[12])

        path = f"/tmp/bcv_{i}.jbc"
        open(path, "wb").write(
            build(keygen, wver, iterations, alg, mode, hash_id, salt, key)
        )
        got = subprocess.run(
            [BIN, "bestcrypt", path], capture_output=True, text=True
        ).stdout.strip()

        if got == expected:
            print(f"  \033[32m✓\033[0m vector {i}  hash_id={hash_id:<4} mode={mode}")
            ok += 1
        else:
            print(f"  \033[31m✗\033[0m vector {i}  hash_id={hash_id} mode={mode}")
            print(f"      want: {expected[:120]}")
            print(f"      got : {got[:120] or '<nothing>'}")
            bad += 1

    print(f"\nround-trip: {ok} identical, {bad} differing")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
