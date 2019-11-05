from __future__ import annotations
from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import ClassVar, Dict, Type

from .tag_length_value_triplet import Tag, TagLengthValueTriplet


@dataclass
class ASN1Type(ABC):
    tag: ClassVar[Tag] = NotImplemented
    _tag_to_class: ClassVar[Dict[Tag, Type[ASN1Type]]] = NotImplemented

    @abstractmethod
    def tlv_triplet(self) -> TagLengthValueTriplet:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> ASN1Type:
        raise NotImplementedError

    @classmethod
    def from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> ASN1Type:
        if cls != ASN1Type:
            if cls.tag != tlv_triplet.tag:
                # TODO: Use proper exception.
                raise ValueError
            return cls._from_tlv_triplet(tlv_triplet=tlv_triplet)
        else:
            return cls._tag_to_class[tlv_triplet.tag]._from_tlv_triplet(tlv_triplet=tlv_triplet)

    @classmethod
    def from_bytes(cls, data: bytes) -> ASN1Type:
        return cls.from_tlv_triplet(tlv_triplet=TagLengthValueTriplet.from_bytes(data=data))

    def __bytes__(self) -> bytes:
        return bytes(self.tlv_triplet())

    def __len__(self) -> int:
        return len(self.tlv_triplet())
