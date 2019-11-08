from __future__ import annotations
from typing import Tuple, List


def parse_base128_int(data: bytes) -> Tuple[int, int]:
    val = 0
    for num_consumed, byte in enumerate(data, start=1):
        if byte & 0b10000000:
            val += (byte & 0b01111111) << 7
        else:
            val += byte
            return val, num_consumed


def extract_elements(elements_data: bytes) -> List[TagLengthValueTriplet]:

    from asn1.tag_length_value_triplet import TagLengthValueTriplet

    elements: List[TagLengthValueTriplet] = []
    offset = 0

    while offset < len(elements_data):
        element_tlv_triplet = TagLengthValueTriplet.from_bytes(elements_data[offset:])
        elements.append(element_tlv_triplet)
        offset += len(element_tlv_triplet)

    return elements
