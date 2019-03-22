#! /usr/bin/env python
# coding:utf-8
# Author: WenZhe Zhu
from scapy.all import conf
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP

S7PLUS_OPTION_CODES = {
    0x31: "Request (0x31)",
    0x32: "Response (0x32)",
}

S7PLUS_FUNCTIONS = {
    0x04ca: "CreateObject (0x04ca)",
    0x04d4: "DeleteObject (0x04d4)",
    0x0542: "SetMultiVariables (0x0542)",
    0x0586: "GetVarSubStreamed (0x0586)",

}

S7PLUS_ID_NUMBERS = {
    0x00000031: "NativeObjects.theCPUProxy_rid (0x00000031)",
    0x0000011d: "ObjectServerSessionContainer (0x0000011d)",
    0x000000e9: "ObjectVariableTypeName (0x000000e9)",
    0x00000121: "ServerSessionClientID (0x00000121)",
    0x00000128: "ServerSessionUser (0x00000128)",
    0x00000129: "ServerSessionApplication (0x00000129)",
    0x0000012a: "ServerSessionHost (0x0000012a)",
    0x0000012b: "ServerSessionRole (0x0000012b)",
    0x0000012c: "ServerSessionClientRID (0x0000012c)",
    0x0000012d: "ServerSessionClientComment (0x0000012d)",
    0x0000013b: "LID_SessionVersionSystemOMS (0x0000013b)",
    0x0000013c: "LID_SessionVersionProjectOMS (0x0000013c)",
    0x0000013d: "LID_SessionVersionSystemPAOM (0x0000013d)",
    0x0000013e: "LID_SessionVersionProjectPAOM (0x0000013e)",
    0x0000013f: "LID_SessionVersionSystemPAOMString (0x0000013f)",
    0x00000140: "LID_SessionVersionProjectPAOMString (0x00000140)",
    0x00000141: "LID_SessionVersionProjectFormat (0x00000141)",
    0x000004e8: "ObjectQualifier (0x000004e8)",

}


S7PLUS_DATA_TYPE_FLAGS = [
    "Array",
    "AddressArray",
    "SparseArray",
    "Unknown1",
]

S7PLUS_DATA_TYPE = {
    0x01: "Bool (0x01)",
    0x03: "UInt (0x03)",
    0x04: "UDInt (0x04)",
    0x09: "LInt (0x09)",
    0x12: "RID (0x12)",
    0x13: "AID (0x13)"
}

ELEMENT_TAG_IDS = {
    0xa1: "Start of object (0xa1)",
    0xa2: "Terminating Object (0xa2)",
    0xa3: "Attribute (0xa3)"
}

RELATION_IDS = {
    0xd3: "GetNewRIDOnServer (0xd3)",
}

CLASS_IDS = {
    0x821f: "ClassServerSession (0x821f)",
}


################################
#       Custom Fields          #
################################
class S7PlusDataValue(PacketField):
    def m2i(self, pkt, payload):
        return self.cls(pkt, payload)


class S7PlusDataSetField(PacketField):
    def m2i(self, pkt, payload):
        return self.cls(pkt, payload)


class S7PlusUDIntField(StrField):
    @staticmethod
    def udint_encode(value):
        output = struct.pack('B', value % 0x80)
        value = value // 0x80 * 0x80
        for i in range(4, 0, -1):
            if value >= 0x80 ** i or len(output) > 1:
                output = output[:-1] + chr(0x80 + (value / 0x80 ** i)) + output[-1:]
            value %= 0x80 ** i
        return output

    @staticmethod
    def udint_decode(value):
        output = ord(value[-1:])
        for i in range(2, len(value) + 1):
            output += (ord(value[-i]) - 0x80) * 0x80 ** (i - 1)
        return output

    def i2m(self, pkt, x):
        x = self.udint_encode(int(x))
        if x is None:
            x = b""
        elif not isinstance(x, bytes):
            x = raw(x)
        # TODO: Need handle None value later
        return x

    def getfield(self, pkt, s):
        value_string = ''
        for offset, curbyte in enumerate(s):
            value_string += curbyte
            curbyte = orb(curbyte)
            if curbyte & 128 == 0:
                break
            if offset > 5:
                raise Scapy_Exception("%s: malformed length field" % self.__class__.__name__)
        value = self.udint_decode(value_string)
        return s[len(value_string):], value

    def i2len(self, pkt, i):
        remain, value = self.getfield(pkt, i)
        return len(value)


class S7PlusUDIntLenField(S7PlusUDIntField):
    __slots__ = ["length_of", "count_of", "adjust"]

    def __init__(self, name, default, length_of=None, fmt="H", count_of=None, adjust=lambda pkt, x: x, fld=None):
        Field.__init__(self, name, default, fmt)
        self.length_of = length_of
        self.count_of = count_of
        self.adjust = adjust
        if fld is not None:
            # FIELD_LENGTH_MANAGEMENT_DEPRECATION(self.__class__.__name__)
            self.length_of = fld

    def i2m(self, pkt, x):
        if x is None:
            if self.length_of is not None:
                fld, fval = pkt.getfield_and_val(self.length_of)
                f = fld.i2len(pkt, fval)
            else:
                fld, fval = pkt.getfield_and_val(self.count_of)
                f = fld.i2count(pkt, fval)
            x = self.adjust(pkt, f)
            x = self.udint_encode(int(x))
        return x


class S7PlusUDIntEnumField(S7PlusUDIntField):
    __slots__ = ["enum"]

    def __init__(self, name, default, enum=None):
        Field.__init__(self, name, default)
        self.enum = enum

    def i2repr(self, pkt, v):
        rr = v
        if v in self.enum:
            rr = "%s (%s)" % (rr, self.enum[v])
        return rr


class S7PlusElementField(PacketListField):
    def m2i(self, pkt, payload):
            return self.cls(pkt, payload)

    def getfield(self, pkt, s):
        lst = []
        ret = b""
        remain = s
        while remain:
            try:
                p = self.m2i(pkt, remain)
            except Exception:
                if conf.debug_dissector:
                    raise
                p = conf.raw_layer(load=remain)
                remain = b""
            else:
                try:
                    if conf.padding_layer in p:
                        pad = p[conf.padding_layer]
                        remain = pad.load
                        del(pad.underlayer.payload)
                    else:
                        remain = b""
                except Exception:
                    remain = b""
                    ret = p
                    break
            lst.append(p)
        return remain + ret, lst


class S7PlusErrorCodeField(StrField):
    def i2m(self, pkt, x):
        if int(x) > 0xff:
            x = struct.pack("!Q", x)
        else:
            x = chr(x)
        if x is None:
            x = b""
        elif not isinstance(x, bytes):
            x = raw(x)
        # TODO: Need handle None value later
        return x

    def getfield(self, pkt, s):
        if s[0] & 0x40 == 0x40:
            value = struct.unpack("", s[:8])
            length = 8
        else:
            value = ord(s[0])
            length = 0
        return s[length:], value


################################
#     Custom Guess class       #
################################
def guess_s7_plus_items_class(pkt, payload):
    if payload[:2] == '\x00\xa2':
        return payload
    # TODO: need check with object qualifier
    elif payload[:4] == '\x00\x00\x00\x00':
        return payload
    else:
        return S7PlusItemValue(payload)


def guess_s7_plus_data_value_class(pkt, payload):
    if pkt.DATATypeFlags == 0x0:
        if pkt.DataType == 0x01:
            return S7PlusBoolValue(payload)
        elif pkt.DataType == 0x02:
            return S7PlusUSIntValue(payload)
        elif pkt.DataType == 0x03:
            return S7PlusUIntValue(payload)
        elif pkt.DataType == 0x04:
            return S7PlusUDIntValue(payload)
        elif pkt.DataType == 0x08:
            return S7PlusUDIntValueArray(payload)
        elif pkt.DataType == 0x09:
            return S7PlusLIntValue(payload)
        elif pkt.DataType == 0x12:
            return S7PlusRIDValue(payload)
        elif pkt.DataType == 0x13:
            return S7PlusAIDValue(payload)
        elif pkt.DataType == 0x14:
            return S7PlusBlobValue(payload)
        elif pkt.DataType == 0x15:
            return S7PlusWStringValue(payload)
        elif pkt.DataType == 0x17:
            return S7PlusStructValue(payload)
    # Array
    elif pkt.DATATypeFlags == 0x01:
        if pkt.DataType == 0x01:
            return S7PlusBoolValue(payload)
        elif pkt.DataType == 0x02:
            return S7PlusUSIntValueArray(payload)
        elif pkt.DataType == 0x03:
            return S7PlusUIntValue(payload)
        elif pkt.DataType == 0x04:
            return S7PlusUDIntValueArray(payload)
        elif pkt.DataType == 0x08:
            return S7PlusUDIntValueArray(payload)
    # Address array
    elif pkt.DATATypeFlags == 0x2:
        if pkt.DataType == 0x01:
            return S7PlusBoolValue(payload)
        elif pkt.DataType == 0x03:
            return S7PlusUIntValue(payload)
        elif pkt.DataType == 0x04:
            return S7PlusUDIntValueArray(payload)
        elif pkt.DataType == 0x08:
            return S7PlusUDIntValueArray(payload)

    return payload


def guess_s7_plus_data_set_class(pkt, payload):
    if isinstance(pkt, S7PlusData):
        # Request
        if pkt.OPCode == 0x31:
            if pkt.Function == 0x04ca:
                return S7PlusCrateObjectRequest(payload)
            elif pkt.Function == 0x04d4:
                return S7PlusDeleteObjectRequest(payload)
            elif pkt.Function == 0x04f2:
                return S7PlusSetVariableRequest(payload)
            elif pkt.Function == 0x0542:
                return S7PlusSetMultiVariablesRequest(payload)
            elif pkt.Function == 0x0586:
                return S7PlusGetVarSubStreamedRequest(payload)
        elif pkt.OPCode == 0x32:
            if pkt.Function == 0x04ca:
                return S7PlusCrateObjectResponse(payload)
            elif pkt.Function == 0x0586:
                return S7PlusGetVarSubStreamedResponse(payload)

            # elif pkt.Function == 0x04d4:
        return payload


def guess_s7_plus_element_class(pkt, payload):
    if payload[0] == '\xa3':
        return S7PlusAttributeField(payload)
    elif payload[0] == '\xa1':
        return S7PlusObjectField(payload)
    else:
        return payload


def guess_s7_plus_sub_element_class(pkt, payload):
    if payload[0] == '\xa3':
        return S7PlusAttributeField(payload)
    elif payload[0] == '\xa1':
        return S7PlusSubObjectField(payload)
    else:
        return payload


class S7PlusNullValue(Packet):
    fields_desc = [
        StrFixedLenField("Value", '', length=0)
    ]


bind_layers(S7PlusNullValue, Padding)


class S7PlusBoolValue(Packet):
    fields_desc = [
        XByteField("Value", 0)
    ]


bind_layers(S7PlusBoolValue, Padding)


class S7PlusUSIntValue(Packet):
    fields_desc = [
        ByteField("Value", 0)
    ]


bind_layers(S7PlusUSIntValue, Padding)


class S7PlusUSIntValueArray(Packet):
    fields_desc = [
        FieldLenField("ArraySize", None, fmt="B", count_of="USIntItems", adjust=lambda pkt, x: x),
        PacketListField("USIntItems", [], S7PlusUSIntValue, count_from=lambda pkt: pkt.ArraySize),
    ]


bind_layers(S7PlusUSIntValueArray, Padding)


class S7PlusUIntValue(Packet):
    """
    UInt (unsigned integer), 16 bits (2 bytes), 0 to 65,535.
    """
    fields_desc = [
        ShortField("Value", 0)
    ]


bind_layers(S7PlusUIntValue, Padding)


class S7PlusUDIntValue(Packet):
    """
    UDInt (unsigned double integer), 32 bits (4 bytes), 0 to 4,294,967,295
    """
    fields_desc = [
        S7PlusUDIntField('Value', 0)
    ]


bind_layers(S7PlusUDIntValue, Padding)


class S7PlusUDIntValueArray(Packet):
    fields_desc = [
        FieldLenField("ArraySize", None, fmt="B", count_of="UDIntItems", adjust=lambda pkt, x: x),
        PacketListField("UDIntItems", [], S7PlusUDIntValue, count_from=lambda pkt: pkt.ArraySize),
        # ByteField("ArraySize", 1)
    ]


bind_layers(S7PlusUDIntValueArray, Padding)


class S7PlusLIntValue(Packet):
    fields_desc = [
        # TODO: Find out why length is 9
        LongField('Value', 0),
        XByteField("end", 0x7a)
    ]


bind_layers(S7PlusLIntValue, Padding)


class S7PlusWStringValue(Packet):
    fields_desc = [
        # TODO: This is UDINT Field
        # FieldLenField("StringLength", None, fmt="B", length_of="Value", adjust=lambda pkt, x: x),
        S7PlusUDIntLenField("StringLength", None, length_of="Value", adjust=lambda pkt, x: x),
        StrLenField("Value", '', length_from=lambda x: x.StringLength)
    ]


bind_layers(S7PlusWStringValue, Padding)


class S7PlusRIDValue(Packet):
    fields_desc = [
        XIntField("Value", 0x002dc6c8)
    ]


bind_layers(S7PlusRIDValue, Padding)


class S7PlusAIDValue(Packet):
    fields_desc = [
        # TODO: might not UDInt
        S7PlusUDIntField('Value', 0)
        # XIntField("Value", 0x002dc6c8)
    ]


bind_layers(S7PlusAIDValue, Padding)


class S7PlusBlobValue(Packet):
    fields_desc = [
        XByteField("BlobRootID", 0),
        FieldLenField("BlobSize", None, fmt="B", length_of="Value", adjust=lambda pkt, x: x),
        StrLenField("Value", '', length_from=lambda pkt: pkt.BlobSize)
    ]


bind_layers(S7PlusBlobValue, Padding)


class S7PlusStructValue(Packet):
    fields_desc = [
        IntField("Value", 0x0),
        S7PlusElementField("Items", "", guess_s7_plus_items_class),
        XByteField("EndStruct", 0x00)
    ]


bind_layers(S7PlusStructValue, Padding)


class S7PlusObjectQualifierPacket(Packet):
    fields_desc = [
        IntEnumField("IDNumber", 0x4e8, S7PLUS_ID_NUMBERS),
        S7PlusElementField("Items", "", guess_s7_plus_items_class),
        XByteField("EndStruct", 0x00)
    ]


bind_layers(S7PlusObjectQualifierPacket, Padding)


class S7PlusItemValue(Packet):
    fields_desc = [
        S7PlusUDIntEnumField("IDNumber", 0x011d, S7PLUS_ID_NUMBERS),
        FlagsField("DATATypeFlags", 0, 4, S7PLUS_DATA_TYPE_FLAGS),
        BitField("UnusedFlags", 0, 4),
        ByteEnumField("DataType", 0x04, S7PLUS_DATA_TYPE),
        ConditionalField(
            S7PlusDataValue("DataValue", '', guess_s7_plus_data_value_class),
            lambda pkt: True if pkt.DataType != 0x00 else False
        ),
    ]


bind_layers(S7PlusItemValue, Padding)


class S7PlusAttributeField(Packet):
    fields_desc = [
        ByteEnumField("TagID", 0xa3, ELEMENT_TAG_IDS),
        # ShortEnumField("IDNumber", 0x0000d3, S7PLUS_ID_NUMBERS),
        S7PlusUDIntEnumField("IDNumber", 0x0000d3, S7PLUS_ID_NUMBERS),
        FlagsField("DATATypeFlags", 0, 4, S7PLUS_DATA_TYPE_FLAGS),
        BitField("UnusedFlags", 0, 4),
        ByteEnumField("DataType", 0x04, S7PLUS_DATA_TYPE),
        ConditionalField(
            S7PlusDataValue("DataValue", '', guess_s7_plus_data_value_class),
            lambda pkt: True if pkt.DataType != 0x00 else False
        )
    ]


bind_layers(S7PlusAttributeField, Padding)


class S7PlusSubObjectField(Packet):
    fields_desc = [
        ByteEnumField("TagID1", 0xa1, ELEMENT_TAG_IDS),
        IntEnumField("RelationID", 0xd3, RELATION_IDS),
        ShortEnumField("ClassID", 0x821f, CLASS_IDS),
        # TODO: finish flags field later.
        ShortField("ClassFlags", 0x00),
        S7PlusElementField("Elements", "", guess_s7_plus_sub_element_class),
        ByteEnumField("TagID2", 0xa2, ELEMENT_TAG_IDS),
    ]


bind_layers(S7PlusSubObjectField, Padding)


class S7PlusObjectField(Packet):
    fields_desc = [
        ByteEnumField("TagID1", 0xa1, ELEMENT_TAG_IDS),
        IntEnumField("RelationID", 0xd3, RELATION_IDS),
        ShortEnumField("ClassID", 0x821f, CLASS_IDS),
        # TODO: finish flags field later.
        ShortField("ClassFlags", 0x00),
        S7PlusElementField("Elements", "", guess_s7_plus_sub_element_class),
        ByteEnumField("TagID2", 0xa2, ELEMENT_TAG_IDS),
        XIntField("Trailer", 0x00000000),
    ]


bind_layers(S7PlusObjectField, Padding)


class S7PlusRequestSetField(PacketLenField):
    def m2i(self, pkt, payload):
        return self.cls(pkt, payload)


class S7PlusReturnValueErrorPacket(Packet):
    fields_desc = [
        # TODO: Fix this value with flags later
        XLongField("ErrorCode", 0)
    ]


class S7PlusAddressListPacket(Packet):
    fields_desc = [
        S7PlusElementField("Elements", "", guess_s7_plus_element_class)
    ]


bind_layers(S7PlusAddressListPacket, Padding)


class S7PlusValueListPacket(Packet):
    fields_desc = [
        XByteField("ItemNumber", 0x72),
        FlagsField("DATATypeFlags", 0, 4, S7PLUS_DATA_TYPE_FLAGS),
        BitField("UnusedFlags", 0, 4),
        ByteEnumField("DataType", 0x04, S7PLUS_DATA_TYPE),
        S7PlusDataValue("DataValue", '', guess_s7_plus_data_value_class)
    ]


bind_layers(S7PlusValueListPacket, Padding)


class S7PlusSetVariableRequest(Packet):
    fields_desc = [
        IntField("ObjectID", 0x0),
        FieldLenField("ItemCount", None, fmt="B", count_of="ValueList", adjust=lambda pkt, x: x),
        PacketListField("ValueList", [], S7PlusItemValue, count_from=lambda pkt: pkt.ItemCount),
        PacketField("ObjectQualifier", S7PlusObjectQualifierPacket(), S7PlusObjectQualifierPacket),
        XByteField("Unknown1", 0),
        XIntField("Trailer", 0x00000000),
    ]


class S7PlusSetMultiVariablesRequest(Packet):
    fields_desc = [
        IntField("ObjectID", 0x0),
        FieldLenField("ItemCount", None, fmt="B", count_of="ValueList", adjust=lambda pkt, x: x),
        FieldLenField("ItemAddressCount", None, fmt="B", count_of="AddressList", adjust=lambda pkt, x: x),
        PacketListField("AddressList", [], S7PlusUDIntValue, count_from=lambda pkt: pkt.ItemAddressCount),
        PacketListField("ValueList", [], S7PlusItemValue, count_from=lambda pkt: pkt.ItemCount),
        XByteField("Unknown1", 0),
        PacketField("ObjectQualifier", S7PlusObjectQualifierPacket(), S7PlusObjectQualifierPacket),
        XIntField("Trailer2", 0x00000000),
    ]


class S7PlusCrateObjectRequest(Packet):
    fields_desc = [
        IntEnumField("IDNumber", 0x0000011d, S7PLUS_ID_NUMBERS),
        FlagsField("DATATypeFlags", 0, 4, S7PLUS_DATA_TYPE_FLAGS),
        BitField("UnusedFlags", 0, 4),
        ByteEnumField("DataType", 0x04, S7PLUS_DATA_TYPE),
        S7PlusDataValue("DataValue", '', guess_s7_plus_data_value_class),
        XIntField("Trailer", 0x00000000),
        S7PlusElementField("Elements", "", guess_s7_plus_element_class)
    ]


class S7PlusCrateObjectResponse(Packet):
    fields_desc = [
        # TODO: Find out what ReturnValue format.
        # ConditionalField(
        #     ByteField("ReturnValue", 0x00),
        #     lambda pkt: False if ord(raw(pkt)[0]) & 0x31 == 0x40 else True
        # ),
        XByteField("ErrorCode", 0),
        ConditionalField(
            XLongField("ErrorDetail", 0x00),
            lambda pkt: True if pkt.ErrorCode & 0x40 == 0x40 else False
        ),
        FieldLenField("ObjectIDCount", None, fmt="B", count_of="ObjectIDs", adjust=lambda pkt, x: x),
        PacketListField("ObjectIDs", [], S7PlusUDIntValue, count_from=lambda pkt: pkt.ObjectIDCount),
        S7PlusElementField("Elements", "", guess_s7_plus_element_class)
    ]

# bind_layers(S7PlusCrateObjectRequest, Padding)


class S7PlusDeleteObjectRequest(Packet):
    fields_desc = [
        IntEnumField("IDNumber", 0x0000011d, S7PLUS_ID_NUMBERS),
        ByteField("Unknown1", 0x00),
        PacketField("ObjectQualifier", S7PlusObjectQualifierPacket(), S7PlusObjectQualifierPacket),
        XIntField("Trailer", 0x00000000),
    ]


class S7PlusGetVarSubStreamedRequest(Packet):
    fields_desc = [
        IntEnumField("IDNumber", 0x0000011d, S7PLUS_ID_NUMBERS),
        FlagsField("DATATypeFlags", 0, 4, S7PLUS_DATA_TYPE_FLAGS),
        BitField("UnusedFlags", 0, 4),
        ByteEnumField("DataType", 0x04, S7PLUS_DATA_TYPE),
        S7PlusDataValue("DataValue", '', guess_s7_plus_data_value_class),
        # Todo: Need check this two byte is in ObjectQualifier or here.
        # XShortField("Unknown1", 0x0000),
        PacketField("ObjectQualifier", S7PlusObjectQualifierPacket(), S7PlusObjectQualifierPacket),
        XShortField("Unknown2", 0x0001),
        XIntField("Trailer", 0x00000000),
    ]


bind_layers(S7PlusGetVarSubStreamedRequest, Padding)


class S7PlusGetVarSubStreamedResponse(Packet):
    fields_desc = [
        XByteField("ErrorCode", 0),
        ConditionalField(
            XLongField("ErrorDetail", 0x00),
            lambda pkt: True if pkt.ErrorCode & 0x40 == 0x40 else False
        ),
        XByteField("Unknown1", 0x00),
        FlagsField("DATATypeFlags", 0, 4, S7PLUS_DATA_TYPE_FLAGS),
        BitField("UnusedFlags", 0, 4),
        ByteEnumField("DataType", 0x04, S7PLUS_DATA_TYPE),
        ConditionalField(
            S7PlusDataValue("DataValue", '', guess_s7_plus_data_value_class),
            lambda pkt: True if pkt.DataType != 0x00 else False
        ),
        XIntField("Trailer", 0x00000000)
    ]


class S7PlusData(Packet):
    fields_desc = [
        ByteEnumField("OPCode", 0x31, S7PLUS_OPTION_CODES),
        XShortField("Reserved", 0x00),
        ShortEnumField("Function", 0x04ca, S7PLUS_FUNCTIONS),
        XShortField("Reserved1", 0x00),
        ShortField("Seq", 0x01),
        ConditionalField(
            XIntField("Session", 0x00000120),
            lambda pkt: True if pkt.OPCode == 0x31 else False
        ),
        XByteField("Unknown1", 0x36),
        S7PlusDataSetField("DataSet", "", guess_s7_plus_data_set_class)
    ]


class S7PlusHeader(Packet):
    fields_desc = [
        XByteField("ProtocolId", 0x72),
        XByteField("ProtocolVersion", 0x01),
        FieldLenField("DataLength", None, fmt="!H", length_of="Data", adjust=lambda pkt, x: x),
        PacketLenField("Data", S7PlusData(), S7PlusData, length_from=lambda x: x.DataLength),
        XIntField("Trailer", 0x72010000)
    ]
