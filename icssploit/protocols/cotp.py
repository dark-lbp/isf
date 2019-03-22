#! /usr/bin/env python
# coding:utf-8
# Author: WenZhe Zhu
from scapy.all import conf
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP
from icssploit.protocols.s7comm import S7Header
from icssploit.protocols.s7comm_plus import S7PlusHeader


COTP_PARAMETER_CODE = {0xc0: "tpdu-size", 0xc1: "src-tsap", 0xc2: "dst-tsap"}

COTP_PDU_TYPE = {0xe0: "CR", 0xd0: "CC", 0xf0: "DT"}


class TPKT(Packet):
    fields_desc = [
        XByteField("Version", 0x03),
        XByteField("Reserved", 0x00),
        XShortField("Length", None)
    ]

    def post_build(self, p, pay):
        if self.Length is None and pay:
            l = len(p) + len(pay)
            p = p[:2] + struct.pack("!H", l) + p[4:]
        return p + pay

    def guess_payload_class(self, payload):
        if payload[1] == '\xe0':
            return COTPCR
        elif payload[1] == '\xd0':
            return COTPCC
        elif payload[1] == '\xf0':
            return COTPDT
        else:
            return None


class COTPOption(Packet):
    fields_desc = [
        ByteEnumField("ParameterCode", 0xc0, COTP_PARAMETER_CODE),
        FieldLenField("ParameterLength", None, fmt="B", length_of="Parameter", adjust=lambda pkt, x: x),
        StrLenField("Parameter", None, length_from=lambda p: p.ParameterLength)
    ]


bind_layers(COTPOption, Padding)


class COTPCR(Packet):
    fields_desc = [
        FieldLenField("COTPLength", None, fmt="B", length_of="Parameters", adjust=lambda pkt, x: (x + 6)),
        ByteEnumField("PDUType", 0xe0, COTP_PDU_TYPE),
        XShortField("Dref", 0x0000),
        XShortField("Sref", 0x0001),
        XByteField("ClassOption", 0x00),
        PacketListField("Parameters", [], COTPOption, length_from=lambda p: p.COTPLength - 6)
    ]


class COTPCC(Packet):
    fields_desc = [
        FieldLenField("COTPLength", None, fmt="B", length_of="Parameters", adjust=lambda pkt, x: (x + 6)),
        ByteEnumField("PDUType", 0xd0, COTP_PDU_TYPE),
        XShortField("Dref", 0x0000),
        XShortField("Sref", 0x0012),
        XByteField("ClassOption", 0x00),
        PacketListField("Parameters", [], COTPOption, length_from=lambda p: p.COTPLength - 6)
    ]


class COTPDT(Packet):
    fields_desc = [
        XByteField("COTPLength", 0x02),
        ByteEnumField("PDUType", 0xf0, COTP_PDU_TYPE),
        FlagsField("EOT", 0, 1, ["End", "Not end"]),
        BitField("TPDUNR", 0, 7)
    ]

    def guess_payload_class(self, payload):
        if payload[0] == '\x32':
            return S7Header
        elif payload[0] == '\x72':
            return S7PlusHeader


bind_layers(TCP, TPKT, dport=102)
bind_layers(TCP, TPKT, sport=102)
