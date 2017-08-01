#! /usr/bin/env python
# coding:utf-8
# Author: WenZhe Zhu
from scapy.all import conf
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP


modbus_function_codes = {
    0x01: "Read Coils Request",
    0x02: "Read Discrete Inputs Request",
    0x03: "Read Holding Registers",
}

modbus_exceptions = {
    0x01: "Illegal Function Code",
    0x02: "Illegal Data Address",
    0x03: "Illegal Data Value",
    0x04: "Server Device Failure",
    0x05: "Acknowledge",
    0x06: "Server Device Busy",
    0x08: "Memory Parity Error",
    0x10: "Gateway Path Unavailable",
    0x11: "Gateway Target Device Failed to Respond"
}


class ModbusHeaderRequest(Packet):
    name = "Modbus Header Req"
    fields_desc = [
        ShortField("trans_id", 0x0003),
        ShortField("proto_id", 0x0000),
        ShortField("length", None),
        ByteField("unit_id", 0x00),
        ByteEnumField("func_code", 0x03, modbus_function_codes)
        ]

    def post_build(self, p, pay):
        if self.length is None:
            l = len(pay) + 2
            p = p[:4] + struct.pack(">H", l) + p[6:]
        return p + pay

    def guess_payload_class(self, payload):
        try:
            return modbus_request_classes[self.func_code]
        except KeyError:
            pass
        return None


class ModbusHeaderResponse(Packet):
    name = "Modbus Header Rsp"
    fields_desc = [
        ShortField("trans_id", 0x0003),
        ShortField("proto_id", 0x0000),
        ShortField("length", None),
        ByteField("unit_id", 0x00),
        ByteEnumField("func_code", 0x03, modbus_function_codes)
        ]

    def post_build(self, p, pay):
        if self.length is None:
            l = len(pay) + 2
            p = p[:4] + struct.pack(">H", l) + p[6:]
        return p + pay

    def guess_payload_class(self, payload):
        try:
            return modbus_response_classes[self.func_code]
        except KeyError:
            pass
        try:
            if self.func_code in modbus_error_func_codes.keys():
                return GenericError
        except KeyError:
            pass
        return None


# PDU 0x01
class ReadCoilsRequest(Packet):
    name = "Read_Coils_Req"
    fields_desc = [
        ShortField("ReferenceNumber", 0x0000),
        ShortField("BitCount", 0x0000)  # Bit count (1-2000)
        ]


class ReadCoilsResponse(Packet):
    name = "Read_Coils_Rsp"
    fields_desc = [
        BitFieldLenField("ByteCount", None, 8, count_of="CoilStatus"),
        FieldListField("CoilStatus", [0x00], ByteField("Data", 0x00), count_from=lambda pkt: pkt.ByteCount)]


# PDU 0x02
class ReadDiscreteInputsRequest(Packet):
    name = "Read Discrete Inputs"
    fields_desc = [
        ShortField("ReferenceNumber", 0x0000),
        ShortField("BitCount", 0x0000)  # Bit count (1-2000)
        ]


class ReadDiscreteInputsResponse(Packet):
    name = "Read Discrete Inputs Response"
    fields_desc = [
        BitFieldLenField("ByteCount", None, 8, count_of="InputStatus"),
        FieldListField("InputStatus", [0x00], ByteField("Data", 0x00), count_from=lambda pkt: pkt.ByteCount)]


# PDU 0x03
class ReadHoldingRegistersRequest(Packet):
    name = "Read_Holding_Registers_Req"
    fields_desc = [
        ShortField("ReferenceNumber", 0x0000),
        ShortField("WordCount", 0x0000)
        ]


class ReadHoldingRegistersResponse(Packet):
    name = "Read_Holding_Registers_Rsp"
    fields_desc = [
        FieldLenField("ByteCount", None, fmt="B", length_of="RegisterValue"),
        FieldListField("RegisterValue", None, ShortField("Data", 0x0),
                       length_from=lambda pkt: pkt.ByteCount)
        ]


# PDU 0x04
class ReadInputRegistersRequest(Packet):
    name = "Read_Input_Registers_Req"
    fields_desc = [
        ShortField("ReferenceNumber", 0x0000),
        ShortField("WordCount", 0x0000)
        ]


class ReadInputRegistersResponse(Packet):
    name = "Read Input Registers Response"
    fields_desc = [
        FieldLenField("ByteCount", None, fmt="B", length_of="RegisterValue"),
        FieldListField("RegisterValue", None, ShortField("data", 0x0),
                       length_from=lambda pkt: pkt.ByteCount)
        ]


# PDU 0x05
class WriteSingleCoilRequest(Packet):
    name = "Write_Single_Coil"
    fields_desc = [
        ShortField("ReferenceNumber", 0x0000),  # from 0x0000 to 0xFFFF
        ShortField("Value", 0x0000)             # 0x0000 == Off, 0xFF00 == On
        ]


class WriteSingleCoilResponse(Packet):  # The answer is the same as the request if successful
    name = "Write Single Coil"
    fields_desc = [
        ShortField("ReferenceNumber", 0x0000),  # from 0x0000 to 0xFFFF
        ShortField("Value", 0x0000)             # 0x0000 == Off, 0xFF00 == On
        ]


# PDU 0x06
class WriteSingleRegisterRequest(Packet):
    name = "Write Single Register Request"
    fields_desc = [
        ShortField("ReferenceNumber", 0x0000),
        ShortField("Value", 0x0000)
        ]


class WriteSingleRegisterResponse(Packet):
    name = "Write Single Register Response"
    fields_desc = [
        ShortField("ReferenceNumber", 0x0000),
        ShortField("Value", 0x0000)
        ]


# PDU 0x07
# TODO: need fix this later
# class ReadExceptionStatusRequest(Packet):
#     name = "Read Exception Status"
#     fields_desc = []
#
#
# class ReadExceptionStatusResponse(Packet):
#     name = "Read Exception Status Response"
#     fields_desc = [ByteField("startingAddr", 0x00)]


# PDU 0x0F
class WriteMultipleCoilsRequest(Packet):
    name = "Write_Multiple_Coils"
    fields_desc = [
        ShortField("ReferenceNumber", 0x0000),
        FieldLenField("BitCount", None, fmt="H", count_of="Values"),  # Bit count (1-800)
        FieldLenField("ByteCount", None, fmt="B", length_of="Values", adjust=lambda pkt, x:x / 16),
        FieldListField("Values", None, BitField("data", 0x0, size=1), count_from=lambda pkt: pkt.BitCount)
    ]


class WriteMultipleCoilsResponse(Packet):
    name = "Write_Multiple_Coils_Response"
    fields_desc = [
        ShortField("ReferenceNumber", 0x0000),
        ShortField("BitCount", 0x0001)
    ]


# PDU 0x10
class WriteMultipleRegistersRequest(Packet):
    name = "Write_Multiple_Registers"
    fields_desc = [
        ShortField("ReferenceNumber", 0x0000),
        FieldLenField("WordCount", None, fmt="H", count_of="Values"),  # Word count (1-100)
        FieldLenField("ByteCount", None, fmt="B", length_of="Values", adjust=lambda pkt, x: x),
        FieldListField("Values", [0x0000], ShortField("data", 0x0000), count_from=lambda pkt: pkt.WordCount)
    ]


class WriteMultipleRegistersResponse(Packet):
    name = "Write Multiple Registers Response"
    fields_desc = [
        ShortField("ReferenceNumber", 0x0000),
        ShortField("WordCount", 0x0001)
    ]


# PDU 0x11
# TODO: Add later


# PDU 0x14
class ReadFileSubRequest(Packet):
    name = "Sub-request of Read File Record"
    fields_desc = [ByteField("RefType", 0x06),
                   ShortField("FileNumber", 0x0001),
                   ShortField("Offset", 0x0000),
                   ShortField("Length", 0x0001)
                   ]


class ReadFileRecordRequest(Packet):
    name = "Read File Record"
    fields_desc = [
        FieldLenField("ByteCount", None, fmt="B", length_of="Groups", adjust=lambda pkt, x: x),
        PacketListField("Groups", [], ReadFileSubRequest, length_from=lambda p: p.ByteCount)
    ]


class ReadFileSubResponse(Packet):
    name = "Sub-response"
    fields_desc = [
        FieldLenField("ByteCount", None, fmt="B", length_of="Data", adjust=lambda pkt, x: x + 1),
        ByteField("RefType", 0x06),
        FieldListField("Data", [0x0000], XShortField("", 0x0000),
                       length_from=lambda pkt: (pkt.respLength - 1))
    ]


class ReadFileRecordResponse(Packet):
    name = "Read File Record Response"
    fields_desc = [
        FieldLenField("ByteCount", None, fmt="B", length_of="Values", adjust=lambda pkt, x: x),
        PacketListField("Groups", [], ReadFileSubResponse, length_from=lambda p: p.ByteCount)
    ]


# PDU 0x15
class WriteFileSubRequest(Packet):
    name = "Sub request of Write File Record"
    fields_desc = [
        ByteField("RefType", 0x06),
        ShortField("FileNumber", 0x0001),
        ShortField("Offset", 0x0000),
        FieldLenField("Length", None, fmt="H", count_of="Data"),
        FieldListField("Data", [0x0000], XShortField("", 0x0000), count_from=lambda pkt: pkt.Length)
    ]


class WriteFileRecordRequest(Packet):
    name = "Write File Record"
    fields_desc = [
        FieldLenField("ByteCount", None, fmt="B", length_of="Groups", adjust=lambda pkt, x: x),
        PacketListField("Groups", [], WriteFileSubRequest, length_from=lambda p: p.ByteCount)
    ]


class WriteFileSubResponse(Packet):
    name = "Sub response of Write File Record"
    fields_desc = [
        ByteField("RefType", 0x06),
        ShortField("FileNumber", 0x0001),
        ShortField("Offset", 0x0000),
        FieldLenField("Length", None, fmt="H", length_of="Data", adjust=lambda pkt, x: x),
        FieldListField("Data", [0x0000], XShortField("", 0x0000), length_from=lambda pkt: pkt.Length)
    ]


class WriteFileRecordResponse(Packet):
    name = "Write File Record Response"
    fields_desc = [
        FieldLenField("ByteCount", None, fmt="B", length_of="Values", adjust=lambda pkt, x: x),
        PacketListField("Groups", [], WriteFileSubResponse, length_from=lambda p: p.ByteCount)
    ]


# PDU 0x16
class MaskWriteRegisterRequest(Packet):
    # and/or to 0xFFFF/0x0000 so that nothing is changed in memory
    name = "Mask Write Register"
    fields_desc = [
        ShortField("ReferenceNumber", 0x0000),
        XShortField("AndMask", 0xffff),
        XShortField("OrMask", 0x0000)
    ]


class MaskWriteRegisterResponse(Packet):
    name = "Mask Write Register Response"
    fields_desc = [
        ShortField("ReferenceNumber", 0x0000),
        XShortField("AndMask", 0xffff),
        XShortField("OrMask", 0x0000)
    ]


# PDU 0x17
class ReadWriteMultipleRegistersRequest(Packet):
    name = "Read Write Multiple Registers"
    fields_desc = [
        ShortField("ReadReferenceNumber", 0x0000),
        ShortField("ReadWordCount", 0x0000),  # Word count for read (1-125)
        ShortField("WriteReferenceNumber", 0x0000),
        FieldLenField("WriteWordCount", None, fmt="H", count_of="RegisterValues"),  # Word count for write (1-100)
        FieldLenField("WriteByteCount", None, fmt="B", length_of="RegisterValues"),
        FieldListField("RegisterValues", [0x0000], ShortField("Data", 0x0000),
                       count_from=lambda pkt: pkt.WriteWordCount)
    ]


class ReadWriteMultipleRegistersResponse(Packet):
    name = "Read Write Multiple Registers Response"
    fields_desc = [
        FieldLenField("ByteCount", None, fmt="B", length_of="RegisterValues"),
        FieldListField("RegisterValues", None, ShortField("data", 0x0),
                       length_from=lambda pkt: pkt.ByteCount)
    ]


# PDU 0x18
class ReadFIFOQueueRequest(Packet):
    name = "Read FIFO Queue"
    fields_desc = [ShortField("ReferenceNumber", 0x0000)]


class ReadFIFOQueueResponse(Packet):
    name = "Read FIFO Queue Response"
    fields_desc = [
        FieldLenField("ByteCount", None, fmt="H", length_of="FIFOValues",
                      adjust=lambda pkt, p: p * 2 + 2),
        FieldLenField("FIFOCount", None, fmt="H", count_of="FIFOValues"),
        FieldListField("FIFOValues", None, ShortField("data", 0x0),
                       length_from=lambda pkt: pkt.ByteCount)
    ]


# Error packet
class GenericError(Packet):
    name = "Generic Error"
    fields_desc = [ByteEnumField("exceptCode", 1, modbus_exceptions)]


modbus_request_classes = {
    0x01: ReadCoilsRequest,
    0x02: ReadDiscreteInputsRequest,
    0x03: ReadHoldingRegistersRequest,
    0x04: ReadInputRegistersRequest,
    0x05: WriteSingleCoilRequest,
    0x06: WriteSingleRegisterRequest,
    # 0x07: ReadExceptionStatusRequest,  # TODO: Add later
    0x0F: WriteMultipleCoilsRequest,
    0x10: WriteMultipleRegistersRequest,
    # 0x11: ReportSlaveIdRequest,  # TODO: Add later
    0x14: ReadFileRecordRequest,
    0x15: WriteFileRecordRequest,
    0x16: MaskWriteRegisterRequest,
    0x17: ReadWriteMultipleRegistersRequest,
    0x18: ReadFIFOQueueRequest,
}

modbus_error_func_codes = {
    0x81: "ReadCoilsError",
    0x82: "ReadDiscreteInputsError",
    0x83: "ReadHoldingRegistersError",
    0x84: "ReadInputRegistersError",
    0x85: "WriteSingleCoilError",
    0x86: "WriteSingleRegisterError",
    0x87: "ReadExceptionStatusError",
    0x8F: "WriteMultipleCoilsError",
    0x90: "WriteMultipleRegistersError",
    0x91: "ReportSlaveIdError",
    0x94: "ReadFileRecordError",
    0x95: "WriteFileRecordError",
    0x96: "MaskWriteRegisterError",
    0x97: "ReadWriteMultipleRegistersError",
    0x98: "ReadFIFOQueueError",
}

modbus_response_classes = {
    0x01: ReadCoilsResponse,
    0x02: ReadDiscreteInputsResponse,
    0x03: ReadHoldingRegistersResponse,
    0x04: ReadInputRegistersResponse,
    0x05: WriteSingleCoilResponse,
    0x06: WriteSingleRegisterResponse,
    # 0x07: ReadExceptionStatusResponse,  # TODO: Add later
    0x0F: WriteMultipleCoilsResponse,
    0x10: WriteMultipleRegistersResponse,
    # 0x11: ReportSlaveIdResponse,  # TODO: Add later
    0x14: ReadFileRecordResponse,
    0x15: WriteFileRecordResponse,
    0x16: MaskWriteRegisterResponse,
    0x17: ReadWriteMultipleRegistersResponse,
    0x18: ReadFIFOQueueResponse
}


# TODO: this not work with StreamSocket
bind_layers(TCP, ModbusHeaderRequest, dport=502)
bind_layers(TCP, ModbusHeaderResponse, sport=502)
