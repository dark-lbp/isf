#!/usr/bin/env python
# coding=utf-8
# Author: WenZhe Zhu
from scapy.all import conf
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import UDP


RPC_Message_Type = {
    0x0: 'Call (0)',
    0x1: 'Reply (1)'
}

RPC_Reply_State = {
    0x0: 'accepted (0)'
}


Credentials_Flavor_Type = {
    0x0: 'AUTH_NULL(0)'
}

Verifer_Flavor_Type = {
    0x0: 'AUTH_NULL(0)'
}

Accept_State ={
    0x0: 'RPC executed successfully(0)'
}

Wdb_Procedure_Type ={
    0x0a: 'Wdb Read Memory(0x0a)',
    0x7a: "Wdb Request Connect(0x7a)",
    0x7b: "Wdb Get Info(0x7b)"
}


class Credentials(Packet):
    name = "Credentials Packet"
    fields_desc = [
            IntEnumField("Flavor", 1, Credentials_Flavor_Type),
            IntField("Length", 0),
        ]

bind_layers(Credentials, Padding)


class Verifier(Packet):
    name = "Verifier Packet"
    fields_desc = [
            IntEnumField("Flavor", 1, Verifer_Flavor_Type),
            IntField("Length", 0),
        ]

bind_layers(Verifier, Padding)


class RPCReq(Packet):
    name = "RPCReq"
    fields_desc = [
        XIntField("XID", None),
        IntEnumField("Type", 0, RPC_Message_Type),
        XIntField("RPCVersion", 2),
        XIntField("Program", 0x55555555),
        XIntField("Version", 1),
        IntEnumField("Procedure", 0, Wdb_Procedure_Type),
        PacketField("Credentials", Credentials(), Credentials),
        PacketField("Verifier", Verifier(), Verifier),
        XIntField("Checksum", None),
        XIntField("PacketSize", None),
        XShortField("Unknown1", 0x0f58),
        XShortField("Seq", None)
    ]

    def post_build(self, p, pay):
        if self.XID is None:
            p = struct.pack("!i", random.randint(65535, 1717986918)) + p[4:]

        if self.PacketSize is None:
            l = len(p) + len(pay) - 4
            p = p[:46] + struct.pack("!H", l) + p[48:]

        if self.Checksum is None:
            data = p[4:] + pay
            p = p[:40] + '\xff\xff' + struct.pack("!H", checksum(data)) + p[44:]
        return p + pay

    def guess_payload_class(self, payload):
        if self.Procedure == 0x0a:  # 10
            return WdbMemReadReq
        elif self.Procedure == 0x0b:  # 11
            return WdbMemWriteReq
        elif self.Procedure == 0x7a:  # 122
            return WdbConnectReq
        elif self.Procedure == 0x7b:  # 123
            return WdbGetInfoReq


class WdbConnectReq(Packet):
    name = "Wdb Connect Req"
    fields_desc = [
        XIntField("Parameter1", 2),
        XIntField("Parameter2", 0),
        XIntField("Parameter3", 0),
        XIntField("Parameter4", 1),
        StrField("Data", "\x00\x00\x00\x16VxWorks debugger v0.1\x00\x00\x00", fmt="H")
    ]


class WdbGetInfoReq(Packet):
    name = "WdbGetInfoReq"
    fields_desc = [
        XIntField("Parameter1", 3),
        XIntField("Parameter2", 0),
        XIntField("Parameter3", 0),
        XIntField("Parameter4", 4),
        XIntField("Parameter5", 0)
    ]


class WdbMemReadReq(Packet):
    name = "WdbMemReadReq"
    fields_desc = [
        XIntField("Parameter1", 3),
        XIntField("Parameter2", 0xef2438),
        XIntField("Parameter3", 0),
        XIntField("Parameter4", 0x7c92da0c),
        XIntField("Parameter5", 0),
        XIntField("Offset", None),
        XIntField("Length", 0x54),
        StrField("Unknown1", '00f60eb0'.decode('hex'), fmt="H")
    ]


class WdbMemWriteReq(Packet):
    name = "WdbMemWriteReq"
    fields_desc = [
        XIntField("Parameter1", 3),
        XIntField("Parameter2", 0xeb0930),
        XIntField("Parameter3", 0),
        XIntField("Parameter4", 0x4e319b),
        XIntField("Parameter5", 0),
        XIntField("Length1", 4),
        XIntField("Offset", None),
        FieldLenField("BuffLength", None, fmt="I", length_of="Buff"),
        PadField(StrLenField("Buff", "", length_from=lambda p: p.BuffLength), align=4, padwith="\x00")
    ]


class RPCRsp(Packet):
    name = "RPCRsp"
    fields_desc = [
        XIntField("XID", None),
        IntEnumField("Type", 1, RPC_Message_Type),
        IntEnumField("ReplyState", 1, RPC_Reply_State),
        PacketField("Verifier", Verifier(), Verifier),
        IntEnumField("AcceptState", 1, Accept_State),
        XIntField("Checksum", None),
        IntField("PacketSize", None),
        IntField("WdbErrorState", 0)
    ]

    def post_build(self, p, pay):
        if self.XID is None:
            p = struct.pack("!i", random.randint(65535, 1717986918)) + p[4:]

        if self.PacketSize is None:
            l = len(p) + len(pay) - 4
            p = p[:46] + struct.pack("!H", l) + p[48:]

        if self.Checksum is None:
            data = p[4:] + pay
            p = p[:40] + '\xff\xff' + struct.pack("!H", checksum(data)) + p[44:]
        return p + pay

    # TODO: 无法根据Rsp的数据包判断到底是什么类型的数据，和请求的关联只有一个XID。

    # def guess_payload_class(self, payload):
    #     return WdbMemReadRsp


class WdbConnectRsp(Packet):
    name = "Wdb Connect Rsp"
    fields_desc = [
        XIntField("Parameter1", 2),
        XIntField("Parameter2", 0),
        XIntField("Parameter3", 0),
        XIntField("Parameter4", 1),
        StrField("Data", "\x00\x00\x00\x16VxWorks debugger v0.1\x00\x00\x00", fmt="H")
    ]


class WdbMemReadRsp(Packet):
    name = "WdbMemReadRsp"
    fields_desc = [
        XIntField("Parameter1", 0),
        XIntField("Parameter2", 0),
        XIntField("Parameter3", 0),
        FieldLenField("BuffLength", None, fmt="I", length_of="Buff"),
        PadField(StrLenField("Buff", "", length_from=lambda p: p.BuffLength), align=4, padwith="\x00")
    ]


# todo: this not work with StreamSocket
bind_layers(UDP, RPCReq, dport=17185)
bind_layers(UDP, RPCRsp, sport=17185)
