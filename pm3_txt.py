#!/usr/bin/env python
# pm3_txt.py - convert PM3 trace text file to libpcap format
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

import argparse
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from typing import BinaryIO, Optional, Text, TextIO

import pcap

# https://www.kaiser.cx/pcap-iso14443.html
DLT_ISO_14443 = 264
HF_FREQ = 13.56  # MHz = cycles per microsecond
START_TIME = datetime(1970, 1, 1, tzinfo=timezone.utc)


class State(IntEnum):
    INITIAL = 0
    GOTO_FIRST = 1
    PACKETS = 2
    EOF = 3


class Field(IntEnum):
    START = 0
    END = 1
    SRC = 2
    DATA = 3
    CRC = 4
    ANNOTATION = 5


def decode_pm3_hex(i: Text) -> bytes:
    i = i.replace(' ', '')
    # TODO: Handle errors (! byte)
    i = i.replace('!', '')
    return binascii.a2b_hex(i)


@dataclass
class PM3TextToPCap:
    _state: State = State.INITIAL
    _start: Optional[int] = None
    # _end: Optional[int] = None
    _src: Optional[Text] = None
    _data: bytearray = field(default_factory=bytearray)
    # _crc: Optional[bool] = None

    def _reset_pkt(self) -> None:
        self._start = None
        self._src = None
        self._data = bytearray()

    def convert(self, pm3_fh: TextIO, pcap_fh: BinaryIO) -> None:
        hdr = pcap.PcapHeader(protocol=DLT_ISO_14443)
        self._state = State.INITIAL
        self._reset_pkt()

        pcap_p = pcap_fh.tell()
        hdr.write(pcap_fh)

        for line in pm3_fh.readlines():
            pkt = self._handle_line(line)

            if pkt is not None:
                pkt.write(pcap_fh, hdr)
            if self._state == State.EOF:
                break

        pkt = self._finish_packet()
        if pkt is not None:
            pkt.write(pcap_fh, hdr)

        eof = pcap_fh.tell()
        pcap_fh.seek(pcap_p)
        hdr.write(pcap_fh)
        pcap_fh.seek(eof)

    def _handle_line(self, line: Text) -> Optional[pcap.Packet]:
        if self._state == State.INITIAL:
            if 'Start | ' in line:
                self._state = State.GOTO_FIRST
            return

        if self._state == State.GOTO_FIRST:
            if ' | ' not in line:
                # no fields in line, must be the header separator
                return
            else:
                self._state = State.PACKETS
                # fall through

        if self._state == State.EOF:
            return

        # State == PACKETS
        if ' | ' not in line:
            # end of data
            out_packet = self._finish_packet()
            self._state = State.EOF
            return out_packet

        fields = [f.strip() for f in line.split('|')]
        if fields[Field.START]:
            # We have a new start of a packet.
            out_packet = self._finish_packet()

            # Start up the new packet
            self._start = int(fields[Field.START])
            self._src = fields[Field.SRC]
            self._data = bytearray(decode_pm3_hex(fields[Field.DATA]))

            return out_packet
        else:
            # Continuation of an existing packet
            self._data.extend(decode_pm3_hex(fields[Field.DATA]))

    def _finish_packet(self) -> Optional[pcap.Packet]:
        if self._start is None:
            # No packet to finish
            return

        ts = START_TIME + timedelta(microseconds=self._start // HF_FREQ)
        event = (pcap.ISO14Event.DATA_PCD_TO_PICC if self._src.lower() == 'rdr'
                 else pcap.ISO14Event.DATA_PICC_TO_PCD)

        iso14 = pcap.ISO14Packet(event, bytes(self._data))
        self._reset_pkt()
        return pcap.Packet(ts, iso14.encode())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file', type=argparse.FileType('r'), nargs=1)
    parser.add_argument('-o', '--output-file', type=argparse.FileType('wb'),
                        required=True)
    options = parser.parse_args()
    converter = PM3TextToPCap()
    try:
        converter.convert(options.input_file[0], options.output_file)
    finally:
        options.output_file.close()
        options.input_file[0].close()


if __name__ == '__main__':
    main()