from typing import Tuple


def parse_base128_int(data: bytes) -> Tuple[int, int]:
    val = 0
    for num_consumed, byte in enumerate(data, start=1):
        if byte & 0b10000000:
            val += (byte & 0b01111111) << 7
        else:
            val += byte
            return val, num_consumed
