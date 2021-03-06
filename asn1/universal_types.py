from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, List, Tuple, Optional
from enum import Enum
from math import ceil, log2

from asn1.oid import OID
from asn1.asn1_type import ASN1Type, register_asn1_type
from asn1.tag_length_value_triplet import Tag, TagLengthValueTriplet
from asn1.utils import extract_elements


class ASN1UniversalTag(Enum):
    BOOLEAN = Tag.from_bytes(data=b'\x01')
    INTEGER = Tag.from_bytes(data=b'\x02')
    BIT_STRING = Tag.from_bytes(data=b'\x03')
    OCTET_STRING = Tag.from_bytes(data=b'\x04')
    NULL = Tag.from_bytes(data=b'\x05')
    OBJECT_IDENTIFIER = Tag.from_bytes(data=b'\x06')
    ENUMERATED = Tag.from_bytes(data=b'\x0A')
    UTF8String = Tag.from_bytes(data=b'\x0C')
    PrintableString = Tag.from_bytes(data=b'\x13')
    TeletexString = Tag.from_bytes(data=b'\x14')
    IA5String = Tag.from_bytes(data=b'\x16')
    BMPString = Tag.from_bytes(data=b'\x1E')
    SEQUENCE = Tag.from_bytes(data=b'\x30')
    SEQUENCE_OF = Tag.from_bytes(data=b'\x30')
    SET = Tag.from_bytes(data=b'\x31')
    SET_OF = Tag.from_bytes(data=b'\x31')


@dataclass
@register_asn1_type
class Boolean(ASN1Type):
    truth_value: bool
    tag: ClassVar[Tag] = ASN1UniversalTag.BOOLEAN.value

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> Boolean:
        return cls(truth_value=bool(tlv_triplet.value))

    def tlv_triplet(self) -> TagLengthValueTriplet:
        return TagLengthValueTriplet(tag=self.tag, value=bytes([self.truth_value]))


@dataclass
@register_asn1_type
class ObjectIdentifier(ASN1Type):
    oid: OID
    tag: ClassVar[Tag] = ASN1UniversalTag.OBJECT_IDENTIFIER.value

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> ObjectIdentifier:
        return cls(oid=OID.from_bytes(data=tlv_triplet.value))

    def tlv_triplet(self) -> TagLengthValueTriplet:
        return TagLengthValueTriplet(tag=self.tag, value=bytes(self.oid))


@dataclass
@register_asn1_type
class Sequence(ASN1Type):
    elements: Tuple[TagLengthValueTriplet, ...]
    tag: ClassVar[Tag] = ASN1UniversalTag.SEQUENCE.value

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> Sequence:
        return cls(elements=tuple(extract_elements(elements_data=tlv_triplet.value)))

    def tlv_triplet(self) -> TagLengthValueTriplet:
        return TagLengthValueTriplet(tag=self.tag, value=b''.join(bytes(element) for element in self.elements))


@dataclass
@register_asn1_type
class SequenceOf(Sequence):
    # NOTE: The `SEQUENCE_OF` tag value is identical with `SEQUENCE`s.
    tag: ClassVar[Tag] = ASN1UniversalTag.SEQUENCE_OF.value

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> SequenceOf:
        sequence_of: SequenceOf = cls._from_tlv_triplet(tlv_triplet=tlv_triplet)

        observed_tag: Optional[Tag] = None
        for element in sequence_of.elements:
            if observed_tag is None:
                observed_tag = element.tag
            if element.tag != observed_tag:
                # TODO: Use proper exception.
                raise ValueError

        return sequence_of


@dataclass
@register_asn1_type
class BitString(ASN1Type):
    tag: ClassVar[Tag] = ASN1UniversalTag.BIT_STRING.value
    data: bytes

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> BitString:

        data_bytes: List[int] = []
        num_unused_bits = tlv_triplet.value[0]
        shift_mask = 2**num_unused_bits - 1
        shifted_val = 0
        for value_byte in tlv_triplet.value[1:]:
            old_shifted_val = shifted_val
            shifted_val = value_byte & shift_mask
            new_byte_val = (value_byte >> num_unused_bits) | (old_shifted_val << (8 - num_unused_bits))
            if new_byte_val != 0:
                data_bytes.append(new_byte_val)

        return cls(data=bytes(data_bytes))

    def tlv_triplet(self) -> TagLengthValueTriplet:

        try:
            num_unused_bits = 8 - (ceil(log2(self.data[-1])) or 1)
        except ValueError:
            num_unused_bits = 0

        if num_unused_bits != 0:
            data_bytes: List[int] = []
            shifted_val = 0
            for value_byte in self.data[::-1]:
                old_shifted_val = shifted_val
                shifted_val, remaining_byte_val = int.to_bytes(value_byte << num_unused_bits, length=2, byteorder='big')
                data_bytes.append(remaining_byte_val | old_shifted_val)

            if shifted_val:
                data_bytes.append(shifted_val)

            data_bytes.reverse()
        else:
            data_bytes: List[int] = list(self.data)

        return TagLengthValueTriplet(tag=self.tag, value=bytes([num_unused_bits, *bytes(data_bytes)]))


@dataclass
@register_asn1_type
class OctetString(ASN1Type):
    tag: ClassVar[Tag] = ASN1UniversalTag.OCTET_STRING.value
    data: bytes

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> OctetString:
        return cls(data=tlv_triplet.value)

    def tlv_triplet(self) -> TagLengthValueTriplet:
        return TagLengthValueTriplet(tag=self.tag, value=self.data)


@dataclass
@register_asn1_type
class Integer(ASN1Type):
    tag: ClassVar[Tag] = ASN1UniversalTag.INTEGER.value
    int_value: int

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> Integer:
        return cls(int_value=int.from_bytes(bytes=tlv_triplet.value, byteorder='big', signed=True))

    def tlv_triplet(self) -> TagLengthValueTriplet:

        if self.int_value < 0:
            return TagLengthValueTriplet(
                tag=self.tag,
                value=self.int_value.to_bytes(
                    # NOTE: Using one more bit for rounding upwards to take signing into consideration.
                    length=(self.int_value.bit_length() + 8) // 8,
                    byteorder='big',
                    signed=True
                )
            )
        else:
            bytes_value: bytes = self.int_value.to_bytes(
                # NOTE: Using `+ 7` to round to upwards.
                length=(self.int_value.bit_length() + 7) // 8,
                byteorder='big',
            )
            if 0b10000000 & bytes_value[0]:
                bytes_value = b'\x00' + bytes_value
            return TagLengthValueTriplet(tag=self.tag, value=bytes_value)


@register_asn1_type
class Enumerated(Integer):
    tag: ClassVar[Tag] = ASN1UniversalTag.ENUMERATED.value
