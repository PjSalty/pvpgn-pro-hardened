#!/usr/bin/env python3
"""Generate the regression seed corpus for the pvpgn fuzz harnesses.

Each seed is a minimal input that drives a specific parser edge. Before the
hardening fixes several of these abort under ASan/UBSan (that is the point -
they are the reproducers). After the fixes the same inputs exercise the fixed
path cleanly, so they double as a permanent regression corpus.
"""
import os
import struct
import sys

root = os.path.join(os.path.dirname(__file__), "seeds")
pk = os.path.join(root, "packet")
tg = os.path.join(root, "tag")
for d in (pk, tg):
    os.makedirs(d, exist_ok=True)


def w(path, data):
    with open(path, "wb") as f:
        f.write(data)
    print(f"{len(data):6d}  {path}")


# packet harness input = body || off:u32le || len:u32le || ctl:u8
# body wire layout for bnet/w3route/file: [type:u16le][size:u16le][payload...]
def packet_input(body, off, length, ctl):
    return body + struct.pack("<II", off & 0xFFFFFFFF, length & 0xFFFFFFFF) + bytes([ctl])


def bnet_body(size, payload):
    return struct.pack("<HH", 0x00FF, size) + payload  # type, size, then payload


# A: packet_get_str_const end-of-buffer over-read.
# declared size 3072 (== MAX_PACKET_SIZE), no NUL from the scan offset onward ->
# the NUL scan steps pos to 3072 and reads data[3072], one past the buffer.
w(os.path.join(pk, "str_oob.bin"),
  packet_input(bnet_body(3072, b"\xff" * (3072 - 4)), off=4, length=0xFFFFFFFF, ctl=0x40))

# B: packet_get_data_const offset+len unsigned wrap-around.
# size=16, offset=0xFFFFFFFE, len=4 -> offset+len == 2 (mod 2^32) <= size, bypassed.
w(os.path.join(pk, "data_overflow.bin"),
  packet_input(bnet_body(16, b"A" * 12), off=0xFFFFFFFE, length=4, ctl=0x00))

# C: a benign well-formed bnet string packet (coverage / non-crash baseline).
w(os.path.join(pk, "str_ok.bin"),
  packet_input(bnet_body(8, b"hi\x00x"), off=4, length=64, ctl=0x40))

# tag harness input = sel:u8 || body
# D: tag_str_to_uint with a 2-byte input -> reads body[2..3] past the buffer.
w(os.path.join(tg, "short2.bin"), bytes([0x01]) + b"AB")
# E: tag_case_str_to_uint with a 2-byte NUL-terminated input -> strlen()<4 path.
w(os.path.join(tg, "case_short.bin"), bytes([0x00]) + b"AB")
# F: a normal 4-char tag (coverage / non-crash baseline).
w(os.path.join(tg, "tag_ok.bin"), bytes([0x01]) + b"3RAW")

print("done", file=sys.stderr)
