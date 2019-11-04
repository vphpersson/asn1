from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, List, Tuple
from enum import Enum
from math import ceil, log2

from .oid import OID
from .asn1_type import ASN1Type
from .tag_length_value_triplet import Tag, TagLengthValueTriplet


# TODO: Add More?
#     UNIVERSAL 1 Boolean type
#     UNIVERSAL 2 Integer type
#     UNIVERSAL 3 Bitstring type
#     UNIVERSAL 4 Octetstring type
#     UNIVERSAL 5 Null type
#     UNIVERSAL 6 Object identifier type
#     UNIVERSAL 7 Object descriptor type
#     UNIVERSAL 8 External type
#     UNIVERSAL 9 Real type
#     UNIVERSAL 10 Enumerated type
#     UNIVERSAL 12 to 15 Reserved forfuture versions of this
#     Recommendation
#     UNIVERSAL 16 Sequence and Sequence-of types
#     UNIVERSAL 17 Set and Set-of types
#     UNIVERSAL 18 to 22, 25 to 27 Character string types
#     UNIVERSAL 23, 24 Time types
#     UNIVERSAL 28- . . . Reserved for future versions of this


class ASN1UniversalTag(Enum):
    BOOLEAN = Tag.from_bytes(data=b'\x01')
    INTEGER = Tag.from_bytes(data=b'\x02')
    BIT_STRING = Tag.from_bytes(data=b'\x03')
    OCTET_STRING = Tag.from_bytes(data=b'\x04')
    NULL = Tag.from_bytes(data=b'\x05')
    OBJECT_IDENTIFIER = Tag.from_bytes(data=b'\x06')
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
class Boolean(ASN1Type):
    truth_value: bool
    tag: ClassVar[Tag] = ASN1UniversalTag.BOOLEAN.value

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> Boolean:
        return cls(truth_value=bool(tlv_triplet.value))

    def tlv_triplet(self) -> TagLengthValueTriplet:
        return TagLengthValueTriplet(tag=self.tag, value=bytes([self.truth_value]))


@dataclass
class ObjectIdentifier(ASN1Type):
    oid: OID
    tag: ClassVar[Tag] = ASN1UniversalTag.OBJECT_IDENTIFIER.value

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> ObjectIdentifier:
        return cls(oid=OID.from_bytes(data=tlv_triplet.value))

    def tlv_triplet(self) -> TagLengthValueTriplet:
        return TagLengthValueTriplet(tag=self.tag, value=bytes(self.oid))


@dataclass
class Sequence(ASN1Type):
    elements: Tuple[TagLengthValueTriplet, ...]
    tag: ClassVar[Tag] = ASN1UniversalTag.SEQUENCE.value

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> Sequence:
        elements: List[TagLengthValueTriplet] = []
        offset = 0
        while offset < len(tlv_triplet.value):
            element_tlv_triplet = TagLengthValueTriplet.from_bytes(tlv_triplet.value[offset:])
            elements.append(element_tlv_triplet)
            offset += len(element_tlv_triplet)

        return cls(elements=tuple(elements))

    def tlv_triplet(self) -> TagLengthValueTriplet:
        return TagLengthValueTriplet(tag=self.tag, value=b''.join(bytes(element) for element in self.elements))


@dataclass
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
class OctetString(ASN1Type):
    tag: ClassVar[Tag] = ASN1UniversalTag.OCTET_STRING.value
    data: bytes

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> OctetString:
        return cls(data=tlv_triplet.value)

    def tlv_triplet(self) -> TagLengthValueTriplet:
        return TagLengthValueTriplet(tag=self.tag, value=self.data)


ASN1Type._tag_to_class = {
    ASN1UniversalTag.BOOLEAN.value: Boolean,
    ASN1UniversalTag.OBJECT_IDENTIFIER.value: ObjectIdentifier,
    ASN1UniversalTag.SEQUENCE.value: Sequence,
    ASN1UniversalTag.BIT_STRING.value: BitString,
    ASN1UniversalTag.OCTET_STRING: OctetString
}