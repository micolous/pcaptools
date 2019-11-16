#!/usr/bin/env python3
# pcap.py - writes libpcap dump files
# Copyright 2019 Michael Farrell <micolous+git@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import IntEnum
import math
from typing import BinaryIO, Text
import struct


_BIG_ENDIAN_MAGIC = 0xa1b2c3d4
_BIG_ENDIAN_NS_MAGIC = 0xa1b23c4d
_LITTLE_ENDIAN_MAGIC = 0xd4c3b2a1
_LITTLE_ENDIAN_NS_MAGIC = 0x4d3cb2a1
_BIG_ENDIAN_MAGICS = (_BIG_ENDIAN_MAGIC, _BIG_ENDIAN_NS_MAGIC)
_LITTLE_ENDIAN_MAGICS = (_LITTLE_ENDIAN_MAGIC, _LITTLE_ENDIAN_NS_MAGIC)
_NS_PRECISION_MAGICS = (_LITTLE_ENDIAN_NS_MAGIC, _BIG_ENDIAN_NS_MAGIC)
_US_PRECISION_MAGICS = (_LITTLE_ENDIAN_MAGIC, _BIG_ENDIAN_MAGIC)
_HEADER_LEN = 24


@dataclass
class PcapHeader:
    magic_number: int = _BIG_ENDIAN_MAGIC  # uint32
    version_major: int = 2                 # uint16
    version_minor: int = 4                 # uint16
    utc_offset: timedelta = timedelta(0)   # int32
    sig_figs: int = 0                      # uint32
    snap_len: int = 65535                  # uint32 (maximum packet length)
    protocol: int = 0                      # uint32 (dlt)

    @property
    def big_endian(self) -> bool:
        """If true, the file is encoded in big-endian."""
        return self.magic_number in _BIG_ENDIAN_MAGICS

    @big_endian.setter
    def big_endian(self, val: bool):
        if val:
            self.magic_number = _BIG_ENDIAN_MAGICS[int(self.ns_precision)]
        else:
            self.magic_number = _LITTLE_ENDIAN_MAGICS[int(self.ns_precision)]

    @property
    def endian(self) -> Text:
        return "!" if self.big_endian else "<"

    @property
    def ns_precision(self) -> bool:
        """If True, use nanosecond timestamps, otherwise use microseconds."""
        return self.magic_number in _NS_PRECISION_MAGICS

    @ns_precision.setter
    def ns_precision(self, val: bool):
        if val:
            self.magic_number = _NS_PRECISION_MAGICS[int(self.big_endian)]
        else:
            self.magic_number = _US_PRECISION_MAGICS[int(self.big_endian)]

    @property
    def timezone(self) -> timezone:
        return timezone(self.utc_offset)

    @classmethod
    def decode(cls, data: bytes) -> PcapHeader:
        magic_number = struct.unpack("!L", data[:4])[0]
        endian = "!" if magic_number in _BIG_ENDIAN_MAGICS else "<"

        return cls(magic_number,
                   *struct.unpack(endian + "HHlLLL", data[4:_HEADER_LEN]))

    @classmethod
    def read(cls, fh: BinaryIO) -> PcapHeader:
        d = fh.read(_HEADER_LEN)
        return cls.decode(d)

    def encode(self) -> bytes:
        return struct.pack(
            self.endian + "LHHlLLL", self.magic_number, self.version_major,
            self.version_minor, math.floor(self.utc_offset.total_seconds()),
            self.sig_figs, self.snap_len, self.protocol)

    def write(self, fh: BinaryIO) -> int:
        return fh.write(self.encode())


@dataclass
class Packet:
    ts: datetime       # (0: uint32), (1: uint32)
    packet_data: bytes
    orig_len: int = 0  # (3: uint32)
    incl_len: int = field(init=False)  # (2: uint32)

    def __post_init__(self):
        self._update_len()

    @classmethod
    def read(cls, fh: BinaryIO, hdr: PcapHeader) -> Packet:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            hdr.endian + "LLLL", fh.read(16))
        ts = datetime.utcfromtimestamp(ts_sec)
        if hdr.ns_precision:
            # TODO: Python doesn't actually support nanos
            ts = ts.replace(microsecond=ts_usec // 1000)
        else:
            ts = ts.replace(microsecond=ts_usec)

        return Packet(ts, fh.read(incl_len), orig_len)

    def _update_len(self) -> None:
        self.incl_len = len(self.packet_data)
        if self.orig_len == 0:
            self.orig_len = self.incl_len

    def encode(self, hdr: PcapHeader) -> bytes:
        self._update_len()
        if self.incl_len > hdr.snap_len:
            hdr.snap_len = self.incl_len
        ts_sec = math.floor(self.ts.timestamp())
        ts_usec = self.ts.microsecond * (1000 if hdr.ns_precision else 1)
        return struct.pack(hdr.endian + "LLLL", ts_sec, ts_usec, self.incl_len,
                           self.orig_len) + self.packet_data

    def write(self, fh: BinaryIO, hdr: PcapHeader) -> int:
        return fh.write(self.encode(hdr))


# https://www.kaiser.cx/pcap-iso14443.html
class ISO14Event(IntEnum):
    DATA_PICC_TO_PCD = 0xff  # card -> reader
    DATA_PCD_TO_PICC = 0xfe  # reader -> card
    FIELD_OFF = 0xfd
    FIELD_ON = 0xfc
    DATA_PICC_TO_PCD_CRC_DROPPED = 0xfb  # card -> reader, no CRC bytes
    DATA_PCD_TO_PICC_CRC_DROPPED = 0xfa  # reader -> card, no CRC bytes


@dataclass
class ISO14Packet:
    event: ISO14Event                 # (1: uint8)
    data: bytes                       # (3)
    version: int = 0                  # (0: uint8)
    length: int = field(init=False)   # (2: uint16); always big-endian

    def __post_init__(self):
        self._update_length()

    def _update_length(self):
        self.length = len(self.data)

    @classmethod
    def decode(cls, data: bytes) -> ISO14Packet:
        version, event, length = struct.unpack("!BBH", data[:4])
        return ISO14Packet(version=version, event=event, data=data[4:4+length])

    def encode(self) -> bytes:
        self._update_length()
        return struct.pack(
            "!BBH", self.version, self.event, self.length) + self.data
