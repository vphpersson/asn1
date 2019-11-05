from __future__ import annotations
from dataclasses import dataclass
from enum import IntEnum
from typing import Tuple, List
from math import ceil, log2

from asn1.utils import parse_base128_int


class TagClass(IntEnum):
    UNIVERSAL = 0
    APPLICATION = 1
    CONTEXT_SPECIFIC = 2
    PRIVATE = 3


class TagForm(IntEnum):
    PRIMITIVE = 0
    CONSTRUCTED = 1


@dataclass(frozen=True)
class Tag:
    tag_class: TagClass
    tag_form: TagForm
    tag_number: int

    @classmethod
    def from_bytes(cls, data: bytes) -> Tag:
        # In a multi-byte tag, bits 0 to 4 of the first byte are set.
        if (data[0] & 0b00011111) == 0b00011111:
            tag_number, _ = parse_base128_int(data=data[1:])
        else:
            tag_number = data[0] & 0b00011111

        return cls(
            tag_class=TagClass((data[0] & 0b11000000) >> 6),
            tag_form=TagForm((data[0] & 0b00100000) >> 5),
            tag_number=tag_number
        )

    def __len__(self) -> int:
        return ceil(self.tag_number.bit_length() / 7) or 1

    def __bytes__(self) -> bytes:
        tag_bytes: List[int] = [0x00]
        tag_bytes[0] |= (self.tag_class.value << 6)
        tag_bytes[0] |= (self.tag_form.value << 5)

        # TODO: Make  nice. This is hacksy and silly.
        if self.__len__() > 1:
            tag_bytes[0] |= 0b00011111

            bits_representation = f'{self.tag_number:b}'
            padded_bits_representation: str = bits_representation.rjust(
                ceil(len(bits_representation) / 7) * 7,
                '0'
            )
            chunks: List[int] = [
                int(f'0b{padded_bits_representation[i:i + 7]}', 2) for i in range(0, len(padded_bits_representation), 7)
            ]

            for chunk in chunks[:-1]:
                tag_bytes.append(0b10000000 | chunk)
            tag_bytes.append(chunks[-1])
        else:
            tag_bytes[0] |= self.tag_number

        return bytes(tag_bytes)


@dataclass
class TagLengthValueTriplet:
    tag: Tag
    value: bytes

    @staticmethod
    def _extract_lengths(data: bytes) -> Tuple[int, int]:
        # In a multi-byte length field, the bit 7 of the first byte is set.
        if data[0] & 0b10000000:
            num_length_bytes = data[0] & 0b01111111
            num_value_bytes = int.from_bytes(bytes=data[1:1+num_length_bytes], byteorder='big')
        else:
            num_length_bytes = 1
            num_value_bytes = data[0] & 0b01111111

        return num_length_bytes, num_value_bytes

    @property
    def value_length(self):
        return len(self.value)

    @classmethod
    def from_bytes(cls, data: bytes):
        tag = Tag.from_bytes(data=data)
        remaining_data = data[len(tag):]
        num_length_bytes, num_value_bytes = cls._extract_lengths(data=remaining_data)

        return cls(
            tag=tag,
            value=remaining_data[num_length_bytes:num_length_bytes+num_value_bytes]
        )

    def __bytes__(self) -> bytes:
        if 0 <= self.value_length <= 127:
            length_bytes = bytes([self.value_length])
        else:
            num_value_length_bytes: int = ceil(ceil(log2(self.value_length) / 8))
            length_bytes = bytes([
                0b10000000 | num_value_length_bytes,
                *self.value_length.to_bytes(length=num_value_length_bytes, byteorder='big')
            ])

        return bytes(self.tag) + length_bytes + self.value

    def __len__(self) -> int:
        if 0 <= self.value_length <= 127:
            num_length_field_bytes = 1
        else:
            bits_representation = f'{self.value_length:b}'
            num_length_field_bytes = 1 + ceil(len(bits_representation) / 7) * 7

        return sum([
            len(self.tag),
            num_length_field_bytes,
            len(self.value)
        ])
