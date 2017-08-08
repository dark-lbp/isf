from scapy.all import conf
from scapy.packet import *
from scapy.fields import *
from scapy.layers.inet import Ether


PNIO_FRAME_IDS = {
    0x0020: "PTCP-RTSyncPDU-followup",
    0x0080: "PTCP-RTSyncPDU",
    0xFC01: "Alarm High",
    0xFE01: "Alarm Low",
    0xFEFC: "DCP-Hello-Req",
    0xFEFD: "DCP-Get-Set",
    0xFEFE: "DCP-Identify-ReqPDU",
    0xFEFF: "DCP-Identify-ResPDU",
    0xFF00: "PTCP-AnnouncePDU",
    0xFF20: "PTCP-FollowUpPDU",
    0xFF40: "PTCP-DelayReqPDU",
    0xFF41: "PTCP-DelayResPDU-followup",
    0xFF42: "PTCP-DelayFuResPDU",
    0xFF43: "PTCP-DelayResPDU",
}
for i in range(0x0100, 0x1000):
    PNIO_FRAME_IDS[i] = "RT_CLASS_3"
for i in range(0x8000, 0xC000):
    PNIO_FRAME_IDS[i] = "RT_CLASS_1"
for i in range(0xC000, 0xFC00):
    PNIO_FRAME_IDS[i] = "RT_CLASS_UDP"
for i in range(0xFF80, 0xFF90):
    PNIO_FRAME_IDS[i] = "FragmentationFrameID"

DCP_SERVICE_ID = {
    0x00: "reserved (0x00)",
    0x01: "Manufacturer specific (0x01)",
    0x02: "Manufacturer specific (0x02)",
    0x03: "Get (0x03)",
    0x04: "Set (0x04)",
    0x05: "Identify (0x05)",
    0x06: "Hello (0x06)"

}

DCP_SERVICE_TYPE = {
    0x00: "Request (0x00)",
    0x01: "Response Success (0x01)",
    0x05: "Response - Request not supported (0x05)",
}

DCP_OPTIONS = {
    0x01: "IP (0x01)",
    0x02: "Device properties (0x02)",
    0x03: "DHCP (0x03)",
    0x04: "Reserved (0x04)",
    0x05: "Control (0x05)",
    0x06: "Device Inactive (0x06)",
    0x80: "Manufacturer specific (0x80)",
    0x81: "Manufacturer specific (0x81)",
    0x82: "Manufacturer specific (0x82)",
    0x83: "Manufacturer specific (0x83)",
    0x84: "Manufacturer specific (0x84)",
    0x85: "Manufacturer specific (0x85)",
    0x86: "Manufacturer specific (0x86)",
    0xff: "All Selector (0xff)"
}

DCP_SUBOPTIONS = {
    # IP (0x01)
    0x01:
        {
            0x00: "Reserved (0x00)",
            0x01: "MAC address (0x01)",
            0x02: "IP parameter (0x02)"
        },

    # Device properties (0x02)
    0x02:
        {
            0x00: "Null (0x00)",
            0x01: "Manufacturer specific (Type of Station) (0x01)",
            0x02: "Name of Station (0x02)",
            0x03: "Device ID (0x03)",
            0x04: "Device Role (0x04)",
            0x05: "Device Options (0x05)",
            0x06: "Alias Name (0x06)",
            0x07: "Device Instance (0x07)",
            0x08: "OEM Device ID (0x08)"
        },

    # DHCP (0x03)
    0x03:
        {
            0x0c: "Host name (0x0c)",
            0x2b: "Vendor specific (0x2b)",
            0x36: "Server identifier (0x36)",
            0x37: "Parameter request list (0x37)",
            0x3c: "Class identifier (0x3c)",
            0x3d: "DHCP client identifier (0x3d)",
            0x51: "FQDN, Fully Qualified Domain Name (0x51)",
            0x61: "UUID/GUID-based Client (0x61)",
            0xff: "Control DHCP for address resolution (0xff)"
        },

    # Reserved (0x04)
    0x04: {},

    # Control (0x05)
    0x05:
        {
            0x00: "Reserved (0x00)",
            0x01: "Start Transaction (0x01)",
            0x02: "End Transaction (0x02)",
            0x03: "Signal (0x03)",
            0x04: "Response (0x04)",
            0x05: "Reset Factory Settings (0x05)",
            0x06: "Reset to Factory (0x06)"
        },

    # Device Inactive (0x06)
    0x06:
        {
            0x00: "Reserved (0x00)",
            0x01: "Device Initiative (0x01)"
        },

    # ALL Selector (0xff)
    0xff:
        {
            0xff: "ALL Selector (0xff)"
        }
}

DCP_SUBOPTION_DEFAULT_INFO = {
    0x00: "Reserved (0x00)"
}

DCP_SUBOPTION_IP_BLOCK_INFO = {
    0x00: "IP not set (0x00)",
    0x01: "IP set (0x01)",
    0x02: "IP set by DHCP (0x02)",
    0x80: "IP not set (address conflict detected) (0x80)",
    0x81: "IP set (address conflict detected) (0x81)",
    0x82: "IP set by DHCP (address conflict detected) (0x82)"
}

DCP_BLOCK_ERROR_CODE = {
    0x00: "OK (0x00)",
    0x01: "Option unsupp (0x01)",
    0x02: "Suboption unsupp. or no DataSet avail (0x02)",
    0x03: "Suboption not set (0x03)",
    0x04: "Resource Error (0x04)",
    0x05: "SET not possible by local reasons (0x05)",
    0x06: "In operation, SET not possible (0x06)"
}


class ProfinetIO(Packet):
    """Basic PROFINET IO dispatcher"""
    fields_desc = [XShortEnumField("frameID", 0, PNIO_FRAME_IDS)]

    def guess_payload_class(self, payload):
        # For frameID in the RT_CLASS_* range, use the RTC packet as payload
        if self.frameID == 0xfefe or 0xfeff or 0xfefd:
            return PNDCPHeader


class PNDCPBlockListField(PacketListField):
    def m2i(self, pkt, payload):
        return self.cls(pkt, payload)


#################
## Get Request ##
#################
class PNDCPGetRequest(Packet):
    fields_desc = [
        ByteEnumField("Option", 0x01, DCP_OPTIONS),
        MultiEnumField("SubOption", 0x01, DCP_SUBOPTIONS, fmt='B', depends_on=lambda p: p.Option),
    ]

bind_layers(PNDCPGetRequest, Padding)


def guess_dcp_get_response_block_class(pkt, payload):
    if isinstance(pkt, PNDCPGetResponse):
        # IP response (0x01)
        if pkt.Option == 0x01:
            # MAC address (0x01)
            if pkt.SubOption == 0x01:
                return PNDCPGETMACAddressResponseBlock(payload)
            # IP parameter (0x02)
            elif pkt.SubOption == 0x02:
                return PNDCPGETIPParameterResponseBlock(payload)
        # Device properties (0x02)
        elif pkt.Option == 0x02:
            # Manufacturer specific (Type of Station) (0x01)
            if pkt.SubOption == 0x01:
                return PNDCPGETDeviceManufacturerSpecificResponseBlock(payload)
            # Name of Station (0x02)
            elif pkt.SubOption == 0x02:
                return PNDCPGETDeviceNameOfStationResponseBlock(payload)
            # Device ID (0x03)
            elif pkt.SubOption == 0x03:
                return PNDCPGETDeviceIdResponseBlock(payload)
            # Device Role (0x04)
            elif pkt.SubOption == 0x04:
                return PNDCPGETDeviceRoleResponseBlock(payload)
            # Device Options (0x05)
            elif pkt.SubOption == 0x05:
                return PNDCPGETDeviceOptionsResponseBlock(payload)
        # DHCP (0x03)
        elif pkt.Option == 0x03:
            # TODO: Add later when i get some packet
            return None
        # Control (0x05)
        elif pkt.Option == 0x05:
            # (0x01)
            if pkt.SubOption == 0x01:
                return None
            # (0x04)
            elif pkt.SubOption == 0x04:
                return PNDCPGetErrorResponse(payload)
        # Device properties (0x06)
        elif pkt.Option == 0x06:
            return None


#####################
## GET IP Response ##
#####################
class PNDCPGETMACAddressResponseBlock(Packet):
    fields_desc = [
        XShortField("Unknown", 0x00),
        MACField("MacAddress", "FF:FF:FF:FF:FF:FF"),
    ]


class PNDCPGETIPParameterResponseBlock(Packet):
    fields_desc = [
        ShortEnumField("BlockInfo", 0x01, DCP_SUBOPTION_IP_BLOCK_INFO),
        IPField("IPaddress", "0.0.0.0"),
        IPField("Subnetmask", "255.255.255.0"),
        IPField("StandardGateway", "0.0.0.0")
    ]


#########################
## GET Device Response ##
#########################
class PNDCPGETDeviceManufacturerSpecificResponseBlock(Packet):
    fields_desc = [
        ShortEnumField("BlockInfo", 0x00, DCP_SUBOPTION_DEFAULT_INFO),
        StrField("DeviceVendorValue", "S7-400")
    ]


class PNDCPGETDeviceNameOfStationResponseBlock(Packet):
    fields_desc = [
        ShortEnumField("BlockInfo", 0x00, DCP_SUBOPTION_DEFAULT_INFO),
        StrField("NameOfStation", "plcxb1d0ed")
    ]


class PNDCPGETDeviceIdResponseBlock(Packet):
    fields_desc = [
        ShortEnumField("BlockInfo", 0x00, DCP_SUBOPTION_DEFAULT_INFO),
        XShortField("VendorID", 0x002a),
        XShortField("DeviceID", 0x0102)
    ]


class PNDCPGETDeviceRoleResponseBlock(Packet):
    fields_desc = [
        ShortEnumField("BlockInfo", 0x00, DCP_SUBOPTION_DEFAULT_INFO),
        ByteField("DeviceRoleDetails", 0x02),
        ByteField("Reserved", 0x00)
    ]


class PNDCPGETDeviceOptionsBlocks(Packet):
    fields_desc = [
        ByteEnumField("Option", 0x01, DCP_OPTIONS),
        MultiEnumField("SubOption", 0x01, DCP_SUBOPTIONS, fmt='B', depends_on=lambda p: p.Option),
    ]


class PNDCPGETDeviceOptionsResponseBlock(Packet):
    fields_desc = [
        ShortField("Reserved", 0x00),
        # TODO: Fix length problem later
        PacketListField("OptionBlocks", [], PNDCPGETDeviceOptionsBlocks, length_from=lambda x: x)
    ]


##########################
## GET Response Header  ##
##########################
class PNDCPGetResponse(Packet):
    fields_desc = [
        ByteEnumField("Option", 0x01, DCP_OPTIONS),
        MultiEnumField("SubOption", 0x01, DCP_SUBOPTIONS, fmt='B', depends_on=lambda p: p.Option),
        FieldLenField("DCPBlockLength", None, length_of="DCPBlock", fmt="!H", adjust=lambda pkt, x: x / x.DCPBlock),
        PNDCPBlockListField("DCPBlock", [], guess_dcp_get_response_block_class, length_from=lambda x: x.DCPBlockLength),
        PadField(StrLenField("Padding", "\x00", length_from=lambda p: p.DCPBlockLength % 2), 1, padwith="\x00")
    ]

bind_layers(PNDCPGetResponse, Padding)


class PNDCPGetErrorResponse(Packet):
    fields_desc = [
        ByteEnumField("Option", 0x03, DCP_OPTIONS),
        MultiEnumField("SubOption", 0x01, DCP_SUBOPTIONS, fmt='B', depends_on=lambda p: p.Option),
        ByteEnumField("BlockError", 0x02, DCP_BLOCK_ERROR_CODE),
    ]


def guess_dcp_block_get_class(service_type, payload):
    # Request (0)
    if service_type == 0x00:
        return PNDCPGetRequest(payload)
    # Response Success (1)
    elif service_type == 0x01:
        return PNDCPGetResponse(payload)
    elif service_type == 0x05:
        return payload
    else:
        return payload

######################
## IDENT IP Request ##
######################
class PNDCPIdentRequest(Packet):
    fields_desc = [
        ByteEnumField("Option", 0xff, DCP_OPTIONS),
        MultiEnumField("SubOption", 0xff, DCP_SUBOPTIONS, fmt='B', depends_on=lambda p: p.Option),
        ShortField("DCPBlockLength", 0x00)
    ]

#######################
## IDENT IP Response ##
#######################
class PNDCPIdentMACAddressResponseBlock(Packet):
    fields_desc = [
        XShortField("Unknown", 0x00),
        MACField("MacAddress", "FF:FF:FF:FF:FF:FF"),
    ]


class PNDCPIdentIPParameterResponseBlock(Packet):
    fields_desc = [
        ShortEnumField("BlockInfo", 0x01, DCP_SUBOPTION_IP_BLOCK_INFO),
        IPField("IPaddress", "0.0.0.0"),
        IPField("Subnetmask", "255.255.255.0"),
        IPField("StandardGateway", "0.0.0.0")
    ]


###########################
## IDENT Device Response ##
###########################
class PNDCPIdentDeviceManufacturerSpecificResponseBlock(Packet):
    fields_desc = [
        ShortEnumField("BlockInfo", 0x00, DCP_SUBOPTION_DEFAULT_INFO),
        StrField("DeviceVendorValue", "S7-400")
    ]


class PNDCPIdentDeviceNameOfStationResponseBlock(Packet):
    fields_desc = [
        ShortEnumField("BlockInfo", 0x00, DCP_SUBOPTION_DEFAULT_INFO),
        StrField("NameOfStation", "plcxb1d0ed")
    ]


class PNDCPIdentDeviceIdResponseBlock(Packet):
    fields_desc = [
        ShortEnumField("BlockInfo", 0x00, DCP_SUBOPTION_DEFAULT_INFO),
        XShortField("VendorID", 0x002a),
        XShortField("DeviceID", 0x0102)
    ]


class PNDCPIdentDeviceRoleResponseBlock(Packet):
    fields_desc = [
        ShortEnumField("BlockInfo", 0x00, DCP_SUBOPTION_DEFAULT_INFO),
        ByteField("DeviceRoleDetails", 0x02),
        ByteField("Reserved", 0x00)
    ]


class PNDCPIdentDeviceOptionsBlocks(Packet):
    fields_desc = [
        ByteEnumField("Option", 0x01, DCP_OPTIONS),
        MultiEnumField("SubOption", 0x01, DCP_SUBOPTIONS, fmt='B', depends_on=lambda p: p.Option),
    ]


class PNDCPIdentDeviceOptionsResponseBlock(Packet):
    fields_desc = [
        ShortField("Reserved", 0x00),
        # TODO: Fix length problem later
        PacketListField("OptionBlocks", [], PNDCPIdentDeviceOptionsBlocks, length_from=lambda x: x)
    ]


def guess_dcp_ident_response_block_class(pkt, payload):
    if isinstance(pkt, PNDCPIdentResponse):
        # IP response (0x01)
        if pkt.Option == 0x01:
            # MAC address (0x01)
            if pkt.SubOption == 0x01:
                return PNDCPIdentMACAddressResponseBlock(payload)
            # IP parameter (0x02)
            elif pkt.SubOption == 0x02:
                return PNDCPIdentIPParameterResponseBlock(payload)
        # Device properties (0x02)
        elif pkt.Option == 0x02:
            # Manufacturer specific (Type of Station) (0x01)
            if pkt.SubOption == 0x01:
                return PNDCPIdentDeviceManufacturerSpecificResponseBlock(payload)
            # Name of Station (0x02)
            elif pkt.SubOption == 0x02:
                return PNDCPIdentDeviceNameOfStationResponseBlock(payload)
            # Device ID (0x03)
            elif pkt.SubOption == 0x03:
                return PNDCPIdentDeviceIdResponseBlock(payload)
            # Device Role (0x04)
            elif pkt.SubOption == 0x04:
                return PNDCPIdentDeviceRoleResponseBlock(payload)
            # Device Options (0x05)
            elif pkt.SubOption == 0x05:
                return PNDCPIdentDeviceOptionsResponseBlock(payload)
        # DHCP (0x03)
        elif pkt.Option == 0x03:
            # TODO: Add later when i get some packet
            return None
        # Control (0x05)
        elif pkt.Option == 0x05:
            # (0x01)
            if pkt.SubOption == 0x01:
                return None
            # (0x04)
            elif pkt.SubOption == 0x04:
                return PNDCPIdentErrorResponse(payload)
        # Device properties (0x06)
        elif pkt.Option == 0x06:
            return None

############################
## IDENT Response Header  ##
############################
class PNDCPIdentResponse(Packet):
    fields_desc = [
        ByteEnumField("Option", 0x01, DCP_OPTIONS),
        MultiEnumField("SubOption", 0x01, DCP_SUBOPTIONS, fmt='B', depends_on=lambda p: p.Option),
        FieldLenField("DCPBlockLength", None, length_of="DCPBlock", fmt="!H", adjust=lambda pkt, x: x / x.DCPBlock),
        PNDCPBlockListField("DCPBlock", [], guess_dcp_ident_response_block_class, length_from=lambda x: x.DCPBlockLength),
        PadField(StrLenField("Padding", "\x00", length_from=lambda p: p.DCPBlockLength % 2), 1, padwith="\x00")
    ]

bind_layers(PNDCPIdentResponse, Padding)


class PNDCPIdentErrorResponse(Packet):
    fields_desc = [
        ByteEnumField("Option", 0x03, DCP_OPTIONS),
        MultiEnumField("SubOption", 0xff, DCP_SUBOPTIONS, fmt='B', depends_on=lambda p: p.Option),
        ByteEnumField("BlockError", 0x02, DCP_BLOCK_ERROR_CODE),
    ]


def guess_dcp_block_identify_class(service_type, payload):
    # Request (0)
    if service_type == 0x00:
        return PNDCPIdentRequest(payload)
    # Response Success (1)
    elif service_type == 0x01:
        return PNDCPIdentResponse(payload)
    # Response - Request not supported (5)
    elif service_type == 0x05:
        return None


def guess_dcp_block_set_class(payload):
    # TODO: Will Add when i get some packet.
    return None


def guess_dcp_block_class(pkt, payload):
    if isinstance(pkt, PNDCPHeader):
        if pkt.ServiceID == 0x03:
            return guess_dcp_block_get_class(pkt.ServiceType, payload)
        elif pkt.ServiceID == 0x04:
            # TODO: TODO: Will Add when i get some packet.
            # return guess_dcp_block_set_class(pkt.ServiceType, payload)
            return payload
        elif pkt.ServiceID == 0x05:
            return guess_dcp_block_identify_class(pkt.ServiceType, payload)
    else:
        return None


class PNDCPHeader(Packet):
    fields_desc = [
        ByteEnumField("ServiceID", 5, DCP_SERVICE_ID),
        ByteEnumField("ServiceType", 0, DCP_SERVICE_TYPE),
        IntField("XID", 0),
        ShortField("ResponseDelay", 128),
        FieldLenField("DCPDataLength", None, length_of="DCPBlocks", fmt="!H", adjust=lambda pkt, x: x),
        PNDCPBlockListField("DCPBlocks", [], guess_dcp_block_class, length_from=lambda x: x.DCPDataLength)
    ]

bind_layers(Ether, ProfinetIO, type=0x8892)
