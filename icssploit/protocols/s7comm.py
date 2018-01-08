#! /usr/bin/env python
# coding:utf-8
# Author: WenZhe Zhu
from scapy.all import conf
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import TCP


S7_BLOCK_LANG_TYPE = {
    0x00: "Not defined",
    0x01: "AWL",
    0x02: "KOP",
    0x03: "FUP",
    0x04: "SCL",
    0x05: "DB",
    0x06: "GRAPH",
    0x07: "SDB",
    0x08: "CPU-DB",
    0x11: "SDB (after overall reset)",
    0x12: "KOP",
    0x29: "ENCRYPT"
}


S7_BLOCK_TYPE = {
    0x38: "OB",
    0x41: "DB",
    0x42: "SDB",
    0x43: "FC",
    0x44: "SFC",
    0x45: "FB",
    0x46: "SFB"
}


S7_AREA_TYPE = {
    0x03: "SYSInfo",        # System info of 200 family
    0x05: "SYSFlags",       # System flags of 200 family
    0x06: "ANAIn",          # Analog inputs of 200 family
    0x07: "ANAOut",         # Analog outputs of 200 family
    0x80: "P",              # Direct peripheral access
    0x81: "Input",
    0x82: "Output",
    0x83: "Flags",
    0x84: "DB",             # Data blocks
    0x85: "DI",             # Instance data blocks
    0x86: "Local",          # Local data (should not be accessible over network) */
    0x87: "V",              # Previous (Vorgaenger) local data (should not be accessible over network)
    0x1c: "Counter",        # S7 counters
    0x1d: "Timer",          # S7 timers
    0x1e: "Counter200",     # IEC counters (200 family)
    0x1f: "Timer200"        # IEC timers (200 family)
}


S7_PDU_TYPE = {0x01: "Job", 0x02: "Ack", 0x03: "AckData", 0x07: "UserData"}


S7_ERROR_CLASS = {
    0x00: "No Error (0x00)",
    0xd602: "Incorrect password entered (0xd602)",
    0xd604: "The connection has already been enabled (0xd604)"
}


S7_RETURN_CODE = {
    0x00: "Reserved (0x00)",
    0x0a: "Object does not exist (0x0a)",
    0xff: "success (0xff)"
}


S7_TRANSPORT_SIZE_IN_PARM_ITEMS = {
    0x00: "Null (0x00)",
    # Types of 1 byte length
    0x01: "BIT (0x01)",
    0x02: "BYTE (0x02)",
    0x03: "CHAR (0x03)",
    # Types of 2 bytes length
    0x04: "WORD (0x04)",
    0x05: "INT (0x05)",
    # Types of 4 bytes length
    0x06: "DWORD (0x06)",
    0x07: "DINT (0x07)",
    0x08: "REAL (0x08)",
    # Special types
    0x09: "Str (0x09)",
    0x0a: "TOD (0x0a)",
    0x0b: "TIME (0x0b)",
    0x0c: "S5TIME (0x0c)",
    0x0f: "DATE_AND_TIME (0x0f)",
    # Timer or counter
    0x1c: "COUNTER (0x0f)",
    0x1d: "TIMER (0x0f)",
    0x1e: "IEC TIMER (0x0f)",
    0x1f: "IEC COUNTER (0x0f)",
    0x20: "HS COUNTER (0x0f)",
}


S7_TRANSPORT_SIZE_IN_DATA_ITEMS = {
    0x00: "Null (0x00)",                #
    0x03: "BIT (0x03)",                 # Bit access, len is in bits
    0x04: "BYTE/WORD/DWORD (0x04)",     # BYTE/WORD/DWORD access, len is in bits
    0x05: "INTEGER (0x05)",             # Integer access, len is in bits
    0x06: "DINTEGER (0x06)",            # Integer access, len is in bytes
    0x07: "Real (0x07)",                # Real access, len is in bytes
    0x09: "Str (0x09)"                  # Octet string, len is in bytes
}


S7_TRANSPORT_SIZE_LENGTH_IN_DATA_ITEMS = {
    0x00: 0,
    # TODO: Check bit Length calculation, only support 1 bit for now.
    0x03: 1,                            # BIT
    0x04: 8,
    0x05: 8,
    0x06: 1,
    0x07: 1,
    0x09: 1
}


S7_UD_FUNCTION_GROUP = {
    0x0: "Mode-transition",
    0x1: "Programmer commands",
    0x2: "Cyclic data",
    0x3: "Block functions",
    0x4: "CPU functions",
    0x5: "Security",
    0x6: "PBC BSEND/BRECV",
    0x7: "Time functions",
    0xf: "NC programming"
}


S7_UD_PARAMETER_TYPE = {
    0x0: "Push",
    0x4: "Request",
    0x8: "Response",
    0x3: "NC Push",                     # used only by Sinumerik NC
    0x7: "NC Request",                  # used only by Sinumerik NC
    0xb: "NC Response",                 # used only by Sinumerik NC
}


S7_UD_SUB_FUNCTION_PROG = {
    0x01: "Request diag data (Type 1) (0x01)",  # Start online block view
    0x02: "VarTab (0x02)",                      # Variable table
    0x0c: "Erase (0x0c)",
    0x0e: "Read diag data (0x0e)",              # Online block view
    0x0f: "Remove diag data (0x0f)",            # Stop online block view
    0x10: "Forces (0x10)",
    0x13: "Request diag data (Type 2) (0x13)"   # Start online block view

}


S7_UD_SUB_FUNCTION_CYCLIC = {
    0x01: "Memory (0x01)",                      # read data from memory (DB/M/etc.)
    0x04: "Unsubscribe (0x04)"                  # Unsubscribe (disable) cyclic data
}


S7_UD_SUB_FUNCTION_BLOCK = {
    0x01: "List blocks (0x01)",
    0x02: "List blocks of type (0x02)",
    0x03: "Get block info (0x03)"
}


S7_UD_SUB_FUNCTION_CPU = {
    0x01: "Read SZL (0x01)",
    0x02: "Message service (0x02)",
    0x03: "Diagnostic message (0x03)",
    0x05: "ALARM_8 indication (0x05)",
    0x06: "NOTIFY indication (0x06)",
    0x07: "ALARM_8 lock (0x07)",
    0x08: "ALARM_8 unlock (0x08)",
    0x0b: "ALARM ack (0x0b)",
    0x0c: "ALARM ack indication (0x0c)",
    0x0d: "ALARM lock indication (0x0d)",
    0x0e: "ALARM unlock indication (0x0e)",
    0x11: "ALARM_SQ indication (0x11)",
    0x12: "ALARM_S indication (0x12)",
    0x13: "ALARM query (0x13)",
    0x16: "NOTIFY_8 indication (0x16)"
}


S7_UD_SUB_FUNCTION_SEC = {
    0x01: "PLC password (0x01)",
    0x02: "Clean session (0x02)"
}


S7_UD_SUB_FUNCTION_TIME = {
    0x01: "Read clock (0x01)",
    0x02: "Set clock (0x02)",
    0x03: "Read clock (following) (0x03)",
    0x04: "Set clock (0x04)"

}


S7_SUB_FUNCTIONS = {
    # Mode-transition (0x0)
    0x00: {},
    # Programmer commands (0x01)
    0x01: S7_UD_SUB_FUNCTION_PROG,
    # Cyclic data (0x02)
    0x02: S7_UD_SUB_FUNCTION_CYCLIC,
    # Block functions (0x03)
    0x03: S7_UD_SUB_FUNCTION_BLOCK,
    # CPU functions (0x04)
    0x04: S7_UD_SUB_FUNCTION_CPU,
    # Security (0x05)
    0x05: S7_UD_SUB_FUNCTION_SEC,
    # PBC BSEND/BRECV (0x06)
    0x06: {},
    # Time functions (0x07)
    0x07: S7_UD_SUB_FUNCTION_TIME,
    # NC programming (0x0f)
    0x0f: {}
}


S7_JB_FUNCTION = {
    0x00: "CPU services (0x00)",
    0x04: "Read Var (0x04)",
    0x05: "Write Var (0x05)",
    0x1a: "Request download (0x1a)",
    0x1b: "Download block (0x1b)",
    0x1c: "Download ended (0x1c)",
    0x1d: "Start upload (0x1d)",
    0x1e: "Upload (0x1e)",
    0x1f: "End upload (0x1f)",
    0x28: "PI-Service (0x28)",
    0x29: "PLC Stop (0x29)",
    0xf0: "Setup communication (0xf0)"
}


S7_FUNCTION_STATUS = ['MoreData', 'Error']

S7_BLOCK_TYPE_IN_BLOCK = {
    0x08: 'OB',
    0x0a: 'DB',
    0x0b: 'SDB',
    0x0c: 'FC',
    0x0d: 'SFC',
    0x0e: 'FB',
    0x0f: 'SFB'
}

S7_BLOCK_TYPE_IN_FILE_NAME = {
    "08": 'OB',
    "09": 'CMOD',
    "0A": 'DB',
    "0B": 'SDB',
    "0C": 'FC',
    "0D": 'SFC',
    "0E": 'FB',
    "0F": 'SFB'
}

S7_FILE_NAME_DESTINATION_FILESYSTEM = {
    'A': "Active embedded module",
    'B': "Active as well as passive module",
    'P': "Passive (copied, but not chained) module"
}

S7_FILE_IDENTIFIER = {
    "_": "Complete Module",
    "$": "Module header for up-loading"
}

S7_SUBSCRIBED_EVENTS = [
    "Mode-transition",
    "System-diagnostics",
    "Userdefined",
    "Unknown1",
    "Unknown2",
    "Unknown3",
    "Unknown4",
    "Alarms"
]


class S7ParameterField(PacketLenField):
    def m2i(self, pkt, payload):
        return self.cls(pkt, payload)


class S7DataField(PacketLenField):
    def m2i(self, pkt, payload):
        return self.cls(pkt, payload)


class S7PIServiceParameterBlockField(PacketLenField):
    def m2i(self, pkt, payload):
        return self.cls(pkt, payload)


def guess_s7_parameters_class(pkt, payload):
    if isinstance(pkt, S7Header):
        # ROSCTR: Job (0x01)
        if pkt.ROSCTR == 0x01:
            # Function: Read Var (0x04)
            if payload[0] == '\x04':
                return S7ReadVarParameterReq(payload)
            # Function: Write Var (0x05)
            if payload[0] == '\x05':
                return S7WriteVarParameterReq(payload)
            # Function: Request download (0x1a)
            elif payload[0] == '\x1a':
                return S7RequestDownloadParameterReq(payload)
            # Function: Download block (0x1b)
            elif payload[0] == '\x1b':
                return S7DownloadParameterReq(payload)
            # Function: Download ended (0x1c)
            elif payload[0] == '\x1c':
                return S7DownloadEndParameterReq(payload)
            # Function: Start upload (0x1d)
            elif payload[0] == '\x1d':
                return S7RequestUploadBlockParameterReq(payload)
            # Function: Upload (0x1e)
            elif payload[0] == '\x1e':
                return S7UploadBlockParameterReq(payload)
            # Function: End upload (0x1f)
            elif payload[0] == '\x1f':
                return S7UploadBlockEndParameterReq(payload)
            # Function: PI-Service (0x28)
            elif payload[0] == '\x28':
                return S7PIServiceParameterReq(payload)
            # Function: PLC Stop (0x29)
            elif payload[0] == '\x29':
                return S7StopCpuParameterReq(payload)
            # Function: Setup communication (0xf0)
            elif payload[0] == '\xf0':
                return S7SetConParameter(payload)
            return payload
        # ROSCTR: Ack(0x02)
        elif pkt.ROSCTR == 0x02:
            return payload
        # ROSCTR: Ack Data (0x03)
        elif pkt.ROSCTR == 0x03:
            # Function: Read Var (0x04)
            if payload[0] == '\x04':
                return S7ReadVarParameterRsp(payload)
            # Function: Write Var (0x05)
            elif payload[0] == '\x05':
                return S7WriteVarParameterRsp(payload)
            # Function: Request download (0x1a)
            elif payload[0] == '\x1a':
                return S7RequestDownloadParameterRsp(payload)
            # Function: Download block (0x1b)
            elif payload[0] == '\x1b':
                return S7DownloadParameterRsp(payload)
            # Function: Download ended (0x1c)
            elif payload[0] == '\x1c':
                return S7DownloadEndParameterRsp(payload)
            # Function: Start upload (0x1d)
            elif payload[0] == '\x1d':
                return S7RequestUploadBlockParameterRsp(payload)
            # Function: Upload (0x1e)
            elif payload[0] == '\x1e':
                return S7UploadBlockParameterRsp(payload)
            # Function: End upload (0x1f)
            elif payload[0] == '\x1f':
                return S7UploadBlockEndParameterRsp(payload)
            # Function: PI - Service(0x28)
            elif payload[0] == '\x28':
                return S7PIServiceParameterRsp(payload)
            # Function: PLC Stop (0x29)
            elif payload[0] == '\x29':
                return S7StopCpuParameterRsp(payload)
            # Function: Setup communication (0xf0)
            elif payload[0] == '\xf0':
                return S7SetConParameter(payload)
            return payload
        # ROSCTR: User Data(0x07)
        elif pkt.ROSCTR == 0x07:
            if payload[0:3] == "\x00\x01\x12":
                # Subfunction: Forces (0x10)
                if payload[5:7] == "\x41\x10":
                    return S7ForceParameterReq(payload)
                elif payload[5:7] == "\x81\x10":
                    return S7ForceParameterRsp(payload)
                # Subfunction: List blocks (0x01)
                elif payload[5:7] == "\x43\x01":
                    return S7ListBlockParameterReq(payload)
                elif payload[5:7] == "\x83\x01":
                    return S7ListBlockParameterRsp(payload)
                # Subfunction: List blocks of type (0x02)
                elif payload[5:7] == "\x43\x02":
                    return S7ListBlockOfTypeParameterReq(payload)
                elif payload[5:7] == "\x83\x02":
                    return S7ListBlockOfTypeParameterRsp(payload)
                # Subfunction: Get block info (0x03)
                elif payload[5:7] == "\x43\x03":
                    return S7GetBlockInfoParameterReq(payload)
                elif payload[5:7] == "\x83\x03":
                    return S7GetBlockInfoParameterRsp(payload)
                # Subfunction: Read SZL (0x01)
                elif payload[5:7] == "\x44\x01":
                    return S7ReadSZLParameterReq(payload)
                elif payload[5:7] == "\x84\x01":
                    return S7ReadSZLParameterRsp(payload)
                # Subfunction: Message service (0x02)
                elif payload[5:7] == "\x44\x02":
                    return S7MessageServiceParameterReq(payload)
                elif payload[5:7] == "\x84\x02":
                    return S7MessageServiceParameterRsp(payload)
                # Subfunction: PLC password (0x01)
                elif payload[5:7] == "\x45\x01":
                    return S7PasswordParameterReq(payload)
                elif payload[5:7] == "\x85\x01":
                    return S7PasswordParameterRsp(payload)
                # Subfunction: Clean session (0x02)
                elif payload[5:7] == "\x45\x02":
                    return S7CleanSessionParameterReq(payload)
                elif payload[5:7] == "\x85\x02":
                    return S7CleanSessionParameterRsp(payload)
            return payload
    else:
        return payload


def guess_s7_data_class(pkt, payload):
    if isinstance(pkt, S7Header):
        if pkt.haslayer(S7ReadSZLParameterReq):
            return S7ReadSZLDataReq(payload)
        elif pkt.haslayer(S7ReadSZLParameterRsp):
            return S7ReadSZLDataRsp(payload)
        elif pkt.haslayer(S7MessageServiceParameterReq):
            return S7MessageServiceDataReq(payload)
        elif pkt.haslayer(S7MessageServiceParameterRsp):
            return S7MessageServiceDataRsp(payload)
        elif pkt.haslayer(S7UploadBlockParameterRsp):
            return S7UploadBlockDataRsp(payload)
        elif pkt.haslayer(S7DownloadParameterRsp):
            return S7DownloadDataRsp(payload)
        elif pkt.haslayer(S7PasswordParameterReq):
            return S7PasswordDataReq(payload)
        elif pkt.haslayer(S7PasswordParameterRsp):
            return S7PasswordDataRsp(payload)
        elif pkt.haslayer(S7CleanSessionParameterReq):
            return S7CleanSessionDataReq(payload)
        elif pkt.haslayer(S7CleanSessionParameterRsp):
            return S7CleanSessionDataRsp(payload)
        elif pkt.haslayer(S7ReadVarParameterRsp):
            return S7ReadVarDataRsp(payload)
        elif pkt.haslayer(S7WriteVarParameterReq):
            return S7WriteVarDataReq(payload)
        elif pkt.haslayer(S7WriteVarParameterRsp):
            return S7WriteVarDataRsp(payload)
        elif pkt.haslayer(S7ListBlockParameterReq):
            return S7ListBlockDataReq(payload)
        elif pkt.haslayer(S7ListBlockParameterRsp):
            return S7ListBlockDataRsp(payload)
        elif pkt.haslayer(S7ListBlockOfTypeParameterReq):
            return S7ListBlockOfTypeDataReq(payload)
        elif pkt.haslayer(S7ListBlockOfTypeParameterRsp):
            return S7ListBlockOfTypeDataRsp(payload)
        elif pkt.haslayer(S7GetBlockInfoParameterReq):
            return S7GetBlockInfoDataReq(payload)
        elif pkt.haslayer(S7GetBlockInfoParameterRsp):
            return S7GetBlockInfoDataRsp(payload)
        elif pkt.haslayer(S7ForceParameterReq):
            return S7ForceDataReq(payload)
        elif pkt.haslayer(S7ForceParameterRsp):
            return S7ForceDataRsp(payload)
        return payload


def guess_s7_pi_service_parameters_block_class(pkt, payload):
    if len(payload) == 9 * int(payload[0].encode('hex'), 16) + 1:
        return S7PIServiceParameterBlock(payload)
    else:
        return S7PIServiceParameterStringBlock(payload)


def is_s7_response_packet(pkt):
    if pkt.ROSCTR == 0x03:
        return True
    return False


class S7Header(Packet):
    fields_desc = [
        XByteField("ProtocolId", 0x32),
        ByteEnumField("ROSCTR", 0x01, S7_PDU_TYPE),
        XShortField("RedundancyId", 0x0000),
        LEShortField("PDUR", 0x0000),
        FieldLenField("ParameterLength", None, fmt="H", length_of="Parameters", adjust=lambda pkt, x: x),
        FieldLenField("DataLength", None, fmt="H", length_of="Data", adjust=lambda pkt, x: x),
        ConditionalField(
            ByteEnumField("ErrorClass", 0x00, S7_ERROR_CLASS),
            lambda pkt: True if is_s7_response_packet(pkt) is True else False
        ),
        ConditionalField(
            XByteField("ErrorCode", 0x00),
            lambda pkt: True if is_s7_response_packet(pkt) is True else False
        ),
        S7ParameterField("Parameters", '', guess_s7_parameters_class, length_from=lambda x: x.ParameterLength),
        S7DataField("Data", '', guess_s7_data_class, length_from=lambda x: x.DataLength)
    ]


class S7SetConParameter(Packet):
    fields_desc = [
        ByteEnumField("Function", 0xf0, S7_JB_FUNCTION),
        XByteField("Reserved", 0x00),
        XShortField("MaxAmQcalling", 0x0001),
        XShortField("MaxAmQcalled", 0x0001),
        XShortField("PDULength", 0x01e0)
    ]


class S7AckRsp(Packet):
    fields_desc = [
        XByteField("ProtocolId", 0x32),
        ByteEnumField("ROSCTR", 0x02, S7_PDU_TYPE),
        XShortField("RedundancyId", 0x0000),
        LEShortField("PDUR", 0x0000),
        XShortField("ParameterLength", 0x0000),
        XShortField("DataLength", 0x0000),
        ByteEnumField("ErrorClass", 0x00, S7_ERROR_CLASS),
        XByteField("ErrorCode", 0x00)
    ]


class S7ReadSZLParameterReq(Packet):
    fields_desc = [
        X3BytesField("ParameterHead", 0x000112),
        XByteField("ParameterLength", None),
        XByteField("Code", 0x11),
        BitField("Type", 4, 4),
        BitEnumField("FunctionGroup", 4, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x01, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("seq", 0x00)
    ]

    def post_build(self, p, pay):
        if self.ParameterLength is None:
            l = len(p) - 4
            p = p[:3] + struct.pack("!B", l) + p[4:]
        return p + pay


class S7ReadSZLDataReq(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0xff, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x09, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        FieldLenField("Length", None, fmt="H", length_of="SZLIndex", adjust=lambda pkt, x: x + 2),
        XShortField("SZLId", 0x001c),
        XShortField("SZLIndex", 0x0000)
    ]


class S7ReadSZLParameterRsp(Packet):
    fields_desc = [
        X3BytesField("ParameterHead", 0x000112),
        XByteField("ParameterLength", None),
        XByteField("Code", 0x11),
        BitField("Type", 8, 4),
        BitEnumField("FunctionGroup", 4, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x01, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("seq", 0x00),
        XByteField("DURN", 0x00),
        XByteField("LastUnit", 0x00),
        XShortEnumField("ErrorCode", 0x0000, S7_ERROR_CLASS)
    ]

    def post_build(self, p, pay):
        if self.ParameterLength is None:
            l = len(p) - 4
            p = p[:3] + struct.pack("!B", l) + p[4:]
        return p + pay


class S7ReadSZLDataTreeRsp(Packet):
    fields_desc = [StrField("Data", "\x00", fmt="H")]


bind_layers(S7ReadSZLDataTreeRsp, Padding)


class S7ReadSZLDataRsp(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0xff, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x09, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        XShortField("Length", None),
        XShortField("SZLId", 0x001c),
        XShortField("SZLIndex", 0x0000),
        FieldLenField("SZLLength", None, length_of="SZLDataTree", fmt="H", adjust=lambda pkt, x: x / x.SZLListCount),
        FieldLenField("SZLListCount", None, count_of="SZLDataTree", fmt="H", adjust=lambda pkt, x: x),
        PacketListField("SZLDataTree", [], S7ReadSZLDataTreeRsp, length_from=lambda x: x.SZLLength * x.SZLListCount)
    ]

    def post_build(self, p, pay):
        if self.Length is None:
            l = len(p) - 4
            p = p[:2] + struct.pack("!H", l) + p[4:]
        return p + pay


class S7MessageServiceParameterReq(Packet):
    fields_desc = [
        X3BytesField("ParameterHead", 0x000112),
        XByteField("ParameterLength", None),
        XByteField("Code", 0x11),
        BitField("Type", 4, 4),
        BitEnumField("FunctionGroup", 4, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x02, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("seq", 0x00)
    ]

    def post_build(self, p, pay):
        if self.ParameterLength is None:
            l = len(p) - 4
            p = p[:3] + struct.pack("!B", l) + p[4:]
        return p + pay


class S7MessageServiceDataReq(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0xff, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x09, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        FieldLenField("Length", None, fmt="H", length_of="UserName", adjust=lambda pkt, x: x + 2),
        FlagsField("SubscribedEvents", 0, 8, S7_SUBSCRIBED_EVENTS),
        ByteField("Unknown1", 0x0),
        StrLenField("UserName", "USER1", length_from=lambda pkt: pkt.Length - 2)
    ]


class S7MessageServiceParameterRsp(Packet):
    fields_desc = [
        X3BytesField("ParameterHead", 0x000112),
        XByteField("ParameterLength", None),
        XByteField("Code", 0x11),
        BitField("Type", 8, 4),
        BitEnumField("FunctionGroup", 4, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x02, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("seq", 0x00),
        XByteField("DURN", 0x00),
        XByteField("LastUnit", 0x00),
        XShortEnumField("ErrorCode", 0x0000, S7_ERROR_CLASS)
    ]

    def post_build(self, p, pay):
        if self.ParameterLength is None:
            l = len(p) - 4
            p = p[:3] + struct.pack("!B", l) + p[4:]
        return p + pay


class S7MessageServiceDataRsp(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0xff, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x09, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        XShortField("Length", 2),
        XByteField("Result", 0x2),
        XByteField("Reserved", 0x0)
    ]


class S7ForceDataReq(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0xff, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x09, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        FieldLenField("DataLength", None, fmt="H", length_of="Data", adjust=lambda pkt, x: x),
        StrLenField("Data", "00140004000000000001000000010001000100010001000000000000".decode('hex'),
                    length_from=lambda x: x.DataLength)
    ]


class S7ForceParameterReq(Packet):
    fields_desc = [
        StrFixedLenField("ParameterHead", "\x00\x01\x12", length=3),
        XByteField("ParameterLength", 0x08),
        XByteField("Unknown", 0x12),
        BitEnumField("Type", 4, 4, S7_UD_PARAMETER_TYPE),
        BitEnumField("FunctionGroup", 1, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x10, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("Sequence", 0x00),
        XByteField("DURN", 0x00),
        XByteField("LastUnit", 0x00),
        XShortEnumField("ErrorCode", 0x0000, S7_ERROR_CLASS)
    ]


class S7ForceDataRsp(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0xff, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x09, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        FieldLenField("DataLength", None, fmt="H", length_of="Data", adjust=lambda pkt, x: x),
        StrLenField("Data", "\x00", length_from=lambda x: x.DataLength),

    ]


class S7ForceParameterRsp(Packet):
    fields_desc = [
        StrFixedLenField("ParameterHead", "\x00\x01\x12", length=3),
        XByteField("ParameterLength", 0x08),
        XByteField("Unknown", 0x12),
        BitEnumField("Type", 4, 4, S7_UD_PARAMETER_TYPE),
        BitEnumField("FunctionGroup", 1, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x10, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("Sequence", 0x00),
        XByteField("DURN", 0x00),
        XByteField("LastUnit", 0x00),
        XShortEnumField("ErrorCode", 0x0000, S7_ERROR_CLASS)
    ]


class S7ListBlockDataReq(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0x0a, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x00, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        XShortField("Length", 0x0000)
    ]


class S7ListBlockParameterReq(Packet):
    fields_desc = [
        StrFixedLenField("ParameterHead", "\x00\x01\x12", length=3),
        XByteField("ParameterLength", 0x04),
        XByteField("Unknown", 0x11),
        BitEnumField("Type", 4, 4, S7_UD_PARAMETER_TYPE),
        BitEnumField("FunctionGroup", 3, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x01, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("Sequence", 0x00)
    ]


class S7ListBlockDataBlocksRsp(Packet):
    fields_desc = [
        XByteField("Unknow", 0x30),
        ByteEnumField("BlockType", 0x38, S7_BLOCK_TYPE),
        XShortField("BlockCount", 1)
    ]

bind_layers(S7ListBlockDataBlocksRsp, Padding)


class S7ListBlockDataRsp(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0xff, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x09, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        FieldLenField("DataLength", None, fmt="H", length_of="Blocks"),
        PacketListField("Blocks", [], S7ListBlockDataBlocksRsp, length_from=lambda p: p.DataLength)
    ]


class S7ListBlockParameterRsp(Packet):
    fields_desc = [
        StrFixedLenField("ParameterHead", "\x00\x01\x12", length=3),
        XByteField("ParameterLength", 0x04),
        XByteField("Unknown", 0x11),
        BitEnumField("Type", 4, 4, S7_UD_PARAMETER_TYPE),
        BitEnumField("FunctionGroup", 3, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x01, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("Sequence", 0x00),
        XByteField("DURN", 0x00),
        XByteField("LastUnit", 0x00),
        XShortEnumField("ErrorCode", 0x0000, S7_ERROR_CLASS)
    ]


class S7ListBlockOfTypeDataReq(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0xff, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x09, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        FieldLenField("DataLength", None, fmt="H", length_of="BlockType", adjust=lambda pkt, x: x),
        StrFixedLenEnumField("BlockType", "08", enum=S7_BLOCK_TYPE_IN_FILE_NAME, length=2),
    ]


class S7ListBlockOfTypeParameterReq(Packet):
    fields_desc = [
        StrFixedLenField("ParameterHead", "\x00\x01\x12", length=3),
        XByteField("ParameterLength", 0x04),
        XByteField("Unknown", 0x11),
        BitEnumField("Type", 4, 4, S7_UD_PARAMETER_TYPE),
        BitEnumField("FunctionGroup", 3, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x02, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("Sequence", 0x00)
    ]


class S7ListBlockOfTypeDataBlocksRsp(Packet):
    fields_desc = [
        XShortField("BlockNum", 0x0002),
        XByteField("BlockFlag", 0x12),
        ByteEnumField("BlockLang", 0x07, S7_BLOCK_LANG_TYPE)
    ]

bind_layers(S7ListBlockOfTypeDataBlocksRsp, Padding)


class S7ListBlockOfTypeDataRsp(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0xff, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x09, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        FieldLenField("DataLength", None, fmt="H", length_of="Blocks"),
        PacketListField("Blocks", [], S7ListBlockOfTypeDataBlocksRsp, length_from=lambda p:p.DataLength)
    ]


class S7ListBlockOfTypeParameterRsp(Packet):
    fields_desc = [
        StrFixedLenField("ParameterHead", "\x00\x01\x12", length=3),
        XByteField("ParameterLength", 0x08),
        XByteField("Unknown", 0x12),
        BitEnumField("Type", 8, 4, S7_UD_PARAMETER_TYPE),
        BitEnumField("FunctionGroup", 3, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x02, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("Sequence", 0x00),
        XByteField("DURN", 0x00),
        XByteField("LastUnit", 0x00),
        XShortEnumField("ErrorCode", 0x0000, S7_ERROR_CLASS)
    ]


class S7GetBlockInfoDataReq(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0xff, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x09, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        FieldLenField("DataLength", None, fmt="H", length_of="Blocks"),
        StrFixedLenEnumField("BlockType", "08", enum=S7_BLOCK_TYPE_IN_FILE_NAME, length=2),
        StrFixedLenField("BlockNum", "00000", length=5),
        StrFixedLenEnumField("DstFileSystem", "A", enum=S7_FILE_NAME_DESTINATION_FILESYSTEM, length=1)
    ]


class S7GetBlockInfoParameterReq(Packet):
    fields_desc = [
        StrFixedLenField("ParameterHead", "\x00\x01\x12", length=3),
        XByteField("ParameterLength", 0x04),
        XByteField("Unknown", 0x11),
        BitEnumField("Type", 4, 4, S7_UD_PARAMETER_TYPE),
        BitEnumField("FunctionGroup", 3, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x03, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("Sequence", 0x00)
    ]


class S7GetBlockInfoDataInfoRsp(Packet):
    fields_desc = (
        XByteField("Constant", 0x01),
        XByteField("BlockType", 0x00),
        FieldLenField("Length", None, fmt="H", length_of='Info', adjust=lambda pkt, x: x - 4),
        StrLenField("Info", "", length_from=lambda pkt: pkt.Length)
        # Todo: Finish Info field later
    )


class S7GetBlockInfoDataRsp(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0xff, S7_RETURN_CODE),
        XByteField("Size", 0x09),
        FieldLenField("Length", None, fmt="H", length_of="Info"),
        PacketField("Info", S7GetBlockInfoDataInfoRsp(), S7GetBlockInfoDataInfoRsp)
    ]


class S7GetBlockInfoParameterRsp(Packet):
    fields_desc = [
        StrFixedLenField("ParameterHead", "\x00\x01\x12", length=3),
        XByteField("ParameterLength", 0x04),
        XByteField("Unknown", 0x11),
        BitEnumField("Type", 4, 4, S7_UD_PARAMETER_TYPE),
        BitEnumField("FunctionGroup", 3, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x03, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("Sequence", 0x00),
        XByteField("DURN", 0x00),
        XByteField("LastUnit", 0x00),
        XShortEnumField("ErrorCode", 0x0000, S7_ERROR_CLASS)
    ]


class S7ReadVarItemsReq(Packet):
    fields_desc = [
        XByteField("VariableSpecification", 0x12),
        XByteField("ParameterLength", None),
        XByteField("SyntaxId", 0x10),
        ByteEnumField("TransportSize", 0x02, S7_TRANSPORT_SIZE_IN_PARM_ITEMS),
        XShortField("GetLength", 0x0016),
        XShortField("BlockNum", 0x0000),
        ByteEnumField("AREAType", 0x84, S7_AREA_TYPE),
        X3BytesField("Address", 0x000000)
    ]

    def post_build(self, p, pay):
        if self.ParameterLength is None:
            l = len(p) - 2
            p = p[:1] + struct.pack("!B", l) + p[2:]
        return p + pay


class S7ReadVarParameterReq(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x04, S7_JB_FUNCTION),
        FieldLenField("ItemCount", None, fmt="B", count_of="Items"),
        PacketListField("Items", None, S7ReadVarItemsReq)
    ]


class S7ReadVarDataItemsRsp(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0xff, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x04, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        FieldLenField("DataLength", None, fmt="H",
                      length_of="Data",
                      adjust=lambda pkt, x: x * S7_TRANSPORT_SIZE_LENGTH_IN_DATA_ITEMS[pkt.TransportSize]),
        ConditionalField(
            PadField(
                StrLenField("Data", "\x00",
                            length_from=lambda p: p[S7ReadVarDataItemsRsp].DataLength /
                                                  S7_TRANSPORT_SIZE_LENGTH_IN_DATA_ITEMS[p.TransportSize]
                            ),
                align=2, padwith="\x00"
            ),
            lambda pkt: True if pkt.ReturnCode == 0xff else False
        ),

    ]

bind_layers(S7ReadVarDataItemsRsp, Padding)


class S7ReadVarDataRsp(Packet):
    fields_desc = [PacketListField("Items", None, S7ReadVarDataItemsRsp)]


class S7ReadVarParameterRsp(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x04, S7_JB_FUNCTION),
        FieldLenField("ItemCount", None, fmt="B", count_of="Items"),
    ]


class S7WriteVarItemsReq(Packet):
    fields_desc = [
        XByteField("VariableSpecification", 0x12),
        XByteField("ParameterLength", 0x0a),
        XByteField("SyntaxId", 0x10),
        ByteEnumField("TransportSize", 0x02, S7_TRANSPORT_SIZE_IN_PARM_ITEMS),
        XShortField("ItemCount", 0x0016),
        XShortField("BlockNum", 0x0000),
        ByteEnumField("AREAType", 0x84, S7_AREA_TYPE),
        X3BytesField("BitAddress", 0x000000)
    ]

bind_layers(S7WriteVarItemsReq, Padding)


class S7WriteVarParameterReq(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x05, S7_JB_FUNCTION),
        FieldLenField("ItemCount", None, fmt="B", count_of="Items"),
        PacketListField("Items", None, S7WriteVarItemsReq, count_from=lambda p:p.ItemCount)
    ]


class S7WriteVarDataItemsReq(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0x00, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x04, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        FieldLenField("DataLength", None, fmt="H",
                      length_of="Data",
                      adjust=lambda pkt, x: x * S7_TRANSPORT_SIZE_LENGTH_IN_DATA_ITEMS[pkt.TransportSize]),
        PadField(StrLenField("Data", "\x00", length_from=lambda p: p[S7WriteVarDataItemsReq].DataLength /
                                                                S7_TRANSPORT_SIZE_LENGTH_IN_DATA_ITEMS[p.TransportSize]
                             ),
                 align=2, padwith="\x00"
                 )
    ]

bind_layers(S7WriteVarDataItemsReq, Padding)


class S7WriteVarDataReq(Packet):
    # TODO: length is from parameter packet, can't get Items length for now.
    fields_desc = [
        PacketListField("Items", None, S7WriteVarDataItemsReq)
    ]

    def post_build(self, pkt, pay):
        # Last item didn't need fill byte
        if len(self.Items[-1].Data) % 2 == 1:
            return pkt[:-1] + pay
        else:
            return pkt + pay


class S7WriteVarParameterRsp(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x05, S7_JB_FUNCTION),
        ByteField("ItemCount", 0)
    ]


class S7WriteVarDataItemsRsp(Packet):
    fields_desc = [ByteEnumField("ReturnCode", 0x00, S7_RETURN_CODE)]

bind_layers(S7WriteVarDataItemsRsp, Padding)


class S7WriteVarDataRsp(Packet):
    # TODO: length is from parameter packet, can't get Items length for now.
    fields_desc = [
        PacketListField("Items", None, S7WriteVarDataItemsRsp)
    ]


class S7RequestDownloadParameterReq(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x1a, S7_JB_FUNCTION),
        XByteField("FunctionStatus", 0x00),
        StrFixedLenField("UnKnown1", "\x01\x00\x00\x00\x00\x00", length=6),
        FieldLenField("FileNameLength", None, fmt="B", length_of="Filename", adjust=lambda pkt, x: x),
        StrLenField("Filename", "", length_from=lambda p: p.FileNameLength),
        # For download block
        ConditionalField(
            XByteField("Length2", 0x0d),
            lambda pkt: True if pkt.Filename[0] == '_' else False
        ),
        ConditionalField(
            XByteField("UnKnown3", 0x31),
            lambda pkt: True if pkt.Filename[0] == '_' else False
        ),
        ConditionalField(
            StrFixedLenField("LoadMemLength", "000256", length=6),
            lambda pkt: True if pkt.Filename[0] == '_' else False
        ),
        ConditionalField(
            StrFixedLenField("MC7Length", "000156", length=6),
            lambda pkt: True if pkt.Filename[0] == '_' else False
        )
    ]


class S7RequestDownloadParameterRsp(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x1a, S7_JB_FUNCTION)
    ]


class S7DownloadDataRsp(Packet):
    fields_desc = [
        FieldLenField("DataLength", None, length_of="Data", adjust=lambda pkt, x:x),
        XShortField("UnKnown1", 0x00fb),
        StrLenField("Data", "\x00", length_from=lambda x: x.DataLength)
    ]


class S7DownloadParameterReq(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x1b, S7_JB_FUNCTION),
        BitField("Unused", 0, 6),
        FlagsField("FunctionStatus", 0, 2, S7_FUNCTION_STATUS),
        StrFixedLenField("UnKnown1", "\x00\x00\x00\x00\x00\x00", length=6),
        FieldLenField("FileNameLength", None, fmt="B", length_of="Filename", adjust=lambda pkt, x: x),
        StrLenField("Filename", "", length_from=lambda p: p.FileNameLength),
    ]


class S7DownloadParameterRsp(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x1b, S7_JB_FUNCTION),
        BitField("Unused", 0, 6),
        FlagsField("FunctionStatus", 0, 2, S7_FUNCTION_STATUS)
    ]


class S7DownloadEndParameterReq(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x1c, S7_JB_FUNCTION),
        BitField("Unused", 0, 6),
        FlagsField("FunctionStatus", 0, 2, S7_FUNCTION_STATUS),
        XShortEnumField("ErrorCode", 0x0000, S7_ERROR_CLASS),
        StrFixedLenField("UnKnown1", "\x00\x00\x00\x00", length=4),
        FieldLenField("FileNameLength", None, fmt="B", length_of="Filename", adjust=lambda pkt, x: x),
        StrLenField("Filename", "", length_from=lambda p: p.FileNameLength),
    ]


class S7DownloadEndParameterRsp(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x1c, S7_JB_FUNCTION),
    ]


class S7DeleteBlockParameterReq(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x28, S7_JB_FUNCTION),
        StrFixedLenField("Unknown1", "\x00\x00\x00\x00\x00\x00\xfd", length=7),
        XShortField("Length1", 0x000a),
        XByteField("BlockCount", 0x01),
        XByteField("Unknown2", 0x00),
        XByteField("Unknown3", 0x30),
        ByteEnumField("BlockType", 0x43, S7_BLOCK_TYPE),
        StrFixedLenField("BlockNum", "00000", length=5),
        XByteField("DstFileSystem", 0x42),
        FieldLenField("StringLength", None, fmt="B", length_of="PI", adjust=lambda pkt, x: x),
        StrLenField("PI", "_DELE", length_from=lambda p: p.StringLength)
    ]


class S7DeleteBlockReq(Packet):
    fields_desc = [
        XByteField("ProtocolId", 0x32),
        ByteEnumField("ROSCTR", 0x01, S7_PDU_TYPE),
        XShortField("RedundancyId", 0x0000),
        XShortField("PDUR", 0x0c00),
        FieldLenField("ParameterLength", None, fmt="H", length_of="Parameters", adjust=lambda pkt, x: x),
        XShortField("DataLength", 0),
        PacketLenField(
            "Parameters",
            S7DeleteBlockParameterReq(),
            S7DeleteBlockParameterReq,
            length_from=lambda x: x.ParameterLength)
    ]


class S7FileNameBlock(Packet):
    fields_desc = [
        StrFixedLenEnumField("FileIdent", "_", enum=S7_FILE_IDENTIFIER, length=1),
        StrFixedLenEnumField("BlockType", "08", enum=S7_BLOCK_TYPE_IN_FILE_NAME, length=2),
        StrFixedLenField("BlockNum", "00000", length=5),
        StrFixedLenEnumField("DstFileSystem", "A", enum=S7_FILE_NAME_DESTINATION_FILESYSTEM, length=1)
    ]


class S7RequestUploadBlockParameterReq(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x1d, S7_JB_FUNCTION),
        BitField("Unused", 0, 6),
        FlagsField("FunctionStatus", 0, 2, S7_FUNCTION_STATUS),
        StrFixedLenField("Unknown1", "\x00\x00", length=2),
        IntField("UploadID", 0x0),
        FieldLenField("FileNameLength", None, fmt="B", length_of="Filename", adjust=lambda pkt, x: x),
        StrLenField("Filename", "", length_from=lambda p: p.FileNameLength),
    ]


class S7UploadBlockParameterReq(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x1e, S7_JB_FUNCTION),
        BitField("Unused", 0, 6),
        FlagsField("FunctionStatus", 0, 2, S7_FUNCTION_STATUS),
        XShortField("Unknown1", 0x0000),
        IntField("UploadId", 0x00000000)
    ]


class S7UploadBlockEndParameterReq(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x1f, S7_JB_FUNCTION),
        BitField("Unused", 0, 6),
        FlagsField("FunctionStatus", 0, 2, S7_FUNCTION_STATUS),
        XShortEnumField("ErrorCode", 0x0000, S7_ERROR_CLASS),
        IntField("UploadID", 0)
    ]


class S7RequestUploadBlockParameterRsp(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x1d, S7_JB_FUNCTION),
        BitField("Unused", 0, 6),
        FlagsField("FunctionStatus", 0, 2, S7_FUNCTION_STATUS),
        StrFixedLenField("Unknown1", "\x01\x00", length=2),
        IntField("UploadId", 0x00000000),
        FieldLenField("BlockLengthStringLength", None, fmt="B", length_of="BlockLength", adjust=lambda pkt, x: x),
        StrLenField(
            "BlockLength",
            "\x30\x30\x30\x30\x30\x30\x30",
            length_from=lambda x: x.BlockLengthStringLength
        )
    ]


class S7UploadBlockDataRsp(Packet):
    fields_desc = [
        FieldLenField("DataLength", None, length_of="Data", adjust=lambda pkt, x:x),
        XShortField("Unknow1", 0x00fb),
        StrLenField("Data", "\x00", length_from=lambda x: x.DataLength)
    ]


class S7UploadBlockParameterRsp(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x1e, S7_JB_FUNCTION),
        BitField("Unused", 0, 6),
        FlagsField("FunctionStatus", 0, 2, S7_FUNCTION_STATUS)
    ]


class S7UploadBlockEndParameterRsp(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x1f, S7_JB_FUNCTION)
    ]


class S7PasswordDataReq(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0xff, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x09, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        FieldLenField("DataLength", None, fmt="H", length_of="Data", adjust=lambda pkt, x: x),
        StrLenField("Data", "\x00" * 8, length_from=lambda x: x.DataLength)
    ]


class S7PasswordParameterReq(Packet):
    fields_desc = [
        StrFixedLenField("ParameterHead", "\x00\x01\x12", length=3),
        XByteField("ParameterLength", 0x04),
        XByteField("Unknow", 0x11),
        BitEnumField("Type", 4, 4, S7_UD_PARAMETER_TYPE),
        BitEnumField("FunctionGroup", 5, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x01, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("Seq", 0x00)
    ]


class S7PasswordDataRsp(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0xff, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x09, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        FieldLenField("DataLength", None, fmt="H", length_of="Data", adjust=lambda pkt, x: x),
        StrLenField("Data", None, length_from=lambda x: x.DataLength)
    ]


class S7PasswordParameterRsp(Packet):
    fields_desc = [
        X3BytesField("ParameterHead", 0x000112),
        XByteField("ParameterLength", None),
        XByteField("Unknown1", 0x12),
        BitField("Type", 8, 4),
        BitField("FunctionGroup", 5, 4),
        MultiEnumField("SubFunction", 0x01, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("seq", 0x00),
        XByteField("DURN", 0x00),
        XByteField("LastUnit", 0x00),
        XShortEnumField("ErrorCode", 0x0000, S7_ERROR_CLASS)
    ]


class S7CleanSessionDataReq(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0x0a, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x00, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        XShortField("Length", 0x0000)
    ]


class S7CleanSessionDataRsp(Packet):
    fields_desc = [
        ByteEnumField("ReturnCode", 0x0a, S7_RETURN_CODE),
        ByteEnumField("TransportSize", 0x00, S7_TRANSPORT_SIZE_IN_DATA_ITEMS),
        XShortField("Length", 0x0000)
    ]


class S7CleanSessionParameterReq(Packet):
    fields_desc = [
        StrFixedLenField("ParameterHead", "\x00\x01\x12", length=3),
        XByteField("ParameterLength", 0x04),
        XByteField("Unknown", 0x11),
        BitEnumField("Type", 4, 4, S7_UD_PARAMETER_TYPE),
        BitEnumField("FunctionGroup", 5, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x02, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("Seq", 0x00)
    ]


class S7CleanSessionParameterRsp(Packet):
    fields_desc = [
        StrFixedLenField("ParameterHead", "\x00\x01\x12", length=3),
        XByteField("ParameterLength", 0x04),
        XByteField("Unknown", 0x11),
        BitEnumField("Type", 4, 4, S7_UD_PARAMETER_TYPE),
        BitEnumField("FunctionGroup", 5, 4, S7_UD_FUNCTION_GROUP),
        MultiEnumField("SubFunction", 0x02, S7_SUB_FUNCTIONS, fmt='B', depends_on=lambda p: p.FunctionGroup),
        XByteField("Seq", 0x00),
        XByteField("DURN", 0x00),
        XByteField("LastUnit", 0x00),
        XShortEnumField("ErrorCode", 0x0000, S7_ERROR_CLASS)
    ]


class S7StopCpuParameterReq(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x29, S7_JB_FUNCTION),
        StrFixedLenField("Unknown1", "\x00\x00\x00\x00\x00", length=5),
        FieldLenField("StringLength", None, fmt="B", length_of="PI", adjust=lambda pkt, x: x),
        StrLenField("PI", "P_PROGRAM", length_from=lambda p: p.StringLength)
    ]


class S7StopCpuParameterRsp(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x29, S7_JB_FUNCTION),
        ByteField("ParameterData", None),
    ]


class S7PIServiceParameterBlock(Packet):
    fields_desc = [
        FieldLenField("NumberOfBlocks", None, fmt="B", count_of="FileNames", adjust=lambda pkt, x: x),
        FieldListField("FileNames", [], StrFixedLenField("FileName", "", length=9), count_from=lambda p: p.NumberOfBlocks)
        # PacketListField("FileNames", [], S7FileNameBlock, count_from=lambda p: p.NumberOfBlocks)
    ]


class S7PIServiceParameterStringBlock(Packet):
    fields_desc = [
        StrStopField("Argument", "C", " ", -1)
    ]


bind_layers(S7PIServiceParameterBlock, Padding)


class S7PIServiceParameterReq(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x28, S7_JB_FUNCTION),
        StrFixedLenField("Unknown1", "\x00\x00\x00\x00\x00\x00\xfd", length=7),
        FieldLenField("ParameterBlockLength", None, fmt="H", length_of="ParameterBlock", adjust=lambda pkt, x: x),
        S7PIServiceParameterBlockField("ParameterBlock", '', guess_s7_pi_service_parameters_block_class,
                                       length_from=lambda p: p.ParameterBlockLength),
        FieldLenField("StringLength", None, fmt="B", length_of="PI", adjust=lambda pkt, x: x),
        StrLenField("PI", "P_PROGRAM", length_from=lambda p: p.StringLength)
    ]


class S7PIServiceParameterRsp(Packet):
    fields_desc = [
        ByteEnumField("Function", 0x28, S7_JB_FUNCTION),
        BitField("Unused", 0, 6),
        FlagsField("FunctionStatus", 0, 2, S7_FUNCTION_STATUS)
    ]

