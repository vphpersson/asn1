from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple, List
from math import ceil

from asn1.utils import parse_base128_int


@dataclass
class OID:
    parts: Tuple[int, ...]

    @classmethod
    def from_string(cls, string: str) -> OID:
        return cls(parts=tuple(int(str_int) for str_int in string.split('.')))

    @classmethod
    def from_bytes(cls, data: bytes) -> OID:
        second_part = data[0] % 40
        parts: List[int] = [int((data[0] - second_part) / 40), second_part]

        offset = 1
        while offset < len(data):
            value, num_consumed = parse_base128_int(data=data[offset:])
            parts.append(value)
            offset += num_consumed

        return cls(parts=tuple(parts))

    def __str__(self) -> str:
        return '.'.join(str(part) for part in self.parts)

    def __bytes__(self) -> bytes:

        oid_bytes: List[int] = [self.parts[0] * 40 + self.parts[1]]
        for part in self.parts[2:]:
            # TODO: Make nice.
            if 0 <= part <= 127:
                oid_bytes.append(part)
            else:
                bits_representation = f'{part:b}'
                padded_bits_representation: str = bits_representation.rjust(
                    ceil(len(bits_representation) / 7) * 7,
                    '0'
                )
                chunks: List[int] = [
                    int(f'0b{padded_bits_representation[i:i + 7]}', 2)
                    for i in range(0, len(padded_bits_representation), 7)
                ]
                chunks[0] |= 0b10000000

                oid_bytes.extend(chunks)

        return bytes(oid_bytes)

    def __len__(self) -> int:
        return len(self.__bytes__())
