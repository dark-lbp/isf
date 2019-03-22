#! /usr/bin/env python
# coding:utf-8
# Author: WenZhe Zhu
from icssploit.clients.base import Base
from icssploit.protocols.cotp import *
from icssploit.protocols.s7comm_plus import *
from scapy.supersocket import StreamSocket
from scapy.volatile import RandString
import socket


OBJECT_QUALIFIER_ITEMS = [S7PlusItemValue(IDNumber=0x4e9, DataType=0x12,
                                          DataValue=S7PlusRIDValue(Value=0x0)),
                          S7PlusItemValue(IDNumber=0x4ea, DataType=0x13,
                                          DataValue=S7PlusAIDValue(Value=0x0)),
                          S7PlusItemValue(IDNumber=0x4eb, DataType=0x04,
                                          DataValue=S7PlusUDIntValue(Value=0x0)),
                          ]


class S7PlusClient(Base):
    def __init__(self, name, ip, port=102, src_tsap='\x01\x00', timeout=2):
        '''

        :param name: Name of this targets
        :param ip: S7 PLC ip
        :param port: S7 PLC port (default: 102)
        :param src_tsap: src_tsap
        :param rack: cpu rack (default: 0)
        :param slot: cpu slot (default: 2)
        :param timeout: timeout of socket (default: 2)
        '''
        super(S7PlusClient, self).__init__(name=name)
        self._ip = ip
        self._port = port
        self._src_tsap = src_tsap
        self._dst_tsap = "SIMATIC-ROOT-ES"
        self._seq = 1
        self.session = 0x0120
        self._connection = None
        self._connected = False
        self._timeout = timeout
        self._pdu_length = 480
        self._info = {}
        self._server_session_version_data = None

    def connect(self):
        sock = socket.socket()
        sock.settimeout(self._timeout)
        sock.connect((self._ip, self._port))
        self._connection = StreamSocket(sock, Raw)
        packet1 = TPKT() / COTPCR()
        packet1.Parameters = [COTPOption() for i in range(3)]
        packet1.PDUType = "CR"
        packet1.Parameters[0].ParameterCode = "tpdu-size"
        packet1.Parameters[0].Parameter = "\x0a"
        packet1.Parameters[1].ParameterCode = "src-tsap"
        packet1.Parameters[2].ParameterCode = "dst-tsap"
        packet1.Parameters[1].Parameter = self._src_tsap
        packet1.Parameters[2].Parameter = self._dst_tsap
        self.send_receive_packet(packet1)
        packet2 = TPKT() / COTPDT(EOT=1) / S7PlusHeader(Data=S7PlusData(OPCode=0x31, Function=0x04ca))
        packet2[S7PlusData].DataSet = S7PlusCrateObjectRequest(IDNumber=0x0000011d,
                                                               DataType=0x04,
                                                               DataValue=S7PlusUDIntValue(Value=0)
                                                               )
        packet2[S7PlusData].DataSet.Elements = [S7PlusObjectField(RelationID=0xd3, ClassID=0x821f)]
        packet2[S7PlusData].DataSet.Elements[0].Elements = [S7PlusAttributeField(IDNumber=0x00e9,
                                                                                DataType=0x15,
                                                                                DataValue=S7PlusWStringValue(
                                                                                    Value=RandString(8))),
                                                           S7PlusAttributeField(IDNumber=0x0121,
                                                                                DataType=0x15,
                                                                                DataValue=S7PlusWStringValue(
                                                                                    Value=RandString(8))),
                                                           S7PlusAttributeField(IDNumber=0x0128,
                                                                                DataType=0x15,
                                                                                DataValue=S7PlusWStringValue(
                                                                                    Value="")),
                                                           S7PlusAttributeField(IDNumber=0x0129,
                                                                                DataType=0x15,
                                                                                DataValue=S7PlusWStringValue(
                                                                                    Value="")),
                                                           S7PlusAttributeField(IDNumber=0x012a,
                                                                                DataType=0x15,
                                                                                DataValue=S7PlusWStringValue(
                                                                                    Value=RandString(8))),
                                                           S7PlusAttributeField(IDNumber=0x012b,
                                                                                DataType=0x04,
                                                                                DataValue=S7PlusUDIntValue(Value=0)),
                                                           S7PlusAttributeField(IDNumber=0x012c,
                                                                                DataType=0x12,
                                                                                DataValue=S7PlusRIDValue(
                                                                                    Value=RandInt())),
                                                           S7PlusAttributeField(IDNumber=0x012d,
                                                                                DataType=0x15,
                                                                                DataValue=S7PlusWStringValue(
                                                                                    Value="")),
                                                           S7PlusSubObjectField(RelationID=0xd3,
                                                                                ClassID=0x817f,
                                                                                Elements=[S7PlusAttributeField(
                                                                                    IDNumber=0x00e9,
                                                                                    DataType=0x15,
                                                                                    DataValue=S7PlusWStringValue(
                                                                                        Value="SubscriptionContainer"))
                                                                                ],
                                                                                )
                                                           ]
        rsp2 = self.send_receive_s7plus_packet(packet2)
        try:
            if rsp2.haslayer(S7PlusCrateObjectResponse):
                self.session = rsp2[S7PlusCrateObjectResponse].ObjectIDs[0].Value
                # Todo: remove this when find out how get these value from get_target_info
                for elment in rsp2[S7PlusCrateObjectResponse].Elements:
                    if isinstance(elment, S7PlusObjectField):
                        for sub_elment in elment.Elements:
                            if isinstance(sub_elment, S7PlusAttributeField):
                                if sub_elment.IDNumber == 0x0132:
                                    self._server_session_version_data = sub_elment
                                    for item in sub_elment.DataValue.Items:
                                        if item.IDNumber == 0x013f:
                                            data = item.DataValue.Value
                                            self._info['HW_Version'], self._info['Order_Code'], self._info['FW_Version'] = data.split(';')
        except Exception as err:
            self.logger.error("Can't get order code and version from target")
        if self._server_session_version_data:
            packet3 = TPKT() / COTPDT(EOT=1) / S7PlusHeader(Data=S7PlusData(OPCode=0x31, Function=0x0542))
            packet3[S7PlusData].DataSet = S7PlusSetMultiVariablesRequest(ObjectID=self.session,
                                                                         AddressList=S7PlusAddressListPacket(
                                                                             Elements=[S7PlusUDIntValue(Value=0x0132)]
                                                                         ),
                                                                         ValueList=[S7PlusItemValue(
                                                                             IDNumber=0x01, DataType=0x17,
                                                                             DataValue=self._server_session_version_data.DataValue
                                                                         ),
                                                                         ],
                                                                         ObjectQualifier=S7PlusObjectQualifierPacket()
                                                                         )
            packet3[S7PlusData].DataSet.ObjectQualifier.Items = OBJECT_QUALIFIER_ITEMS
            rsp3 = self.send_receive_s7plus_packet(packet3)

    def set_var(self, id_number, item_list):
        packet = TPKT() / COTPDT(EOT=1) / S7PlusHeader(Data=S7PlusData(OPCode=0x31, Function=0x04f2, Unknown1=0x34))
        packet[S7PlusData].DataSet = S7PlusSetVariableRequest(ObjectID=id_number,
                                                              ValueList=item_list)
        packet[S7PlusData].DataSet.ObjectQualifier.Items = OBJECT_QUALIFIER_ITEMS
        packet.show2()
        self.send_s7plus_packet(packet)
        # rsp = self.send_receive_s7plus_packet(packet)

    def get_var_sub_streamed(self, id_number, data_type_flags, data_type, data_value):
        packet = TPKT() / COTPDT(EOT=1) / S7PlusHeader(Data=S7PlusData(OPCode=0x31, Function=0x0586))
        packet[S7PlusData].DataSet = S7PlusGetVarSubStreamedRequest(IDNumber=id_number,
                                                                    DATATypeFlags=data_type_flags,
                                                                    DataType=data_type,
                                                                    DataValue=data_value,
                                                                    ObjectQualifier=S7PlusObjectQualifierPacket()
                                                                    )
        packet[S7PlusData].DataSet.ObjectQualifier.Items = OBJECT_QUALIFIER_ITEMS
        rsp = self.send_receive_s7plus_packet(packet)
        try:
            if rsp.haslayer(S7PlusGetVarSubStreamedResponse):
                return rsp[S7PlusGetVarSubStreamedResponse].DataValue
        except Exception as err:
            self.logger.error("Response is not correct format")

        return None

    def get_target_info(self):
        request_items = S7PlusUDIntValueArray(UDIntItems=S7PlusUDIntValue(Value=0xea9))
        data = self.get_var_sub_streamed(0x31, 0x02, 0x04, request_items)
        try:
            info_data = data[0].Value
            self._info['Serial_Number'] = info_data.split(' ')[3]
        except Exception as err:
            self._info['Serial_Number'] = ''
            self.logger.error("Can't get serial numbertarget")
        return self._info['Order_Code'], self._info['Serial_Number'], self._info['HW_Version'], self._info['FW_Version']

    def delete_object(self, object_id):
        packet = TPKT() / COTPDT(EOT=1) / S7PlusHeader(Data=S7PlusData(OPCode=0x31, Function=0x04d4))
        packet[S7PlusData].DataSet = S7PlusDeleteObjectRequest(IDNumber=object_id,
                                                               ObjectQualifier=S7PlusObjectQualifierPacket()
                                                               )
        packet[S7PlusData].DataSet.ObjectQualifier.Items = OBJECT_QUALIFIER_ITEMS
        # packet.show2()
        self.send_s7plus_packet(packet)
        # rsp = self.send_receive_s7plus_packet(packet)

    def _fix_session(self, packet):
        if self._seq > 65535:
            self._seq = 1
        try:
            if packet.haslayer(S7PlusData):
                if packet[S7PlusData].OPCode == 0x31:
                    packet[S7PlusData].Seq = self._seq
                    packet[S7PlusData].Session = self.session
                self._seq += 1
            return packet
        except Exception as err:
            self.logger.error(err)
            return packet

    def send_packet(self, packet):
        if self._connection:
            try:
                self._connection.send(packet)

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def send_receive_packet(self, packet):
        if self._connection:
            try:
                rsp = self._connection.sr1(packet, timeout=self._timeout)
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def receive_packet(self):
        if self._connection:
            try:
                rsp = self._connection.recv()
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before receive packet!")

    def send_s7plus_packet(self, packet):
        if self._connection:
            try:
                packet = self._fix_session(packet)
                self._connection.send(packet)

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def send_receive_s7plus_packet(self, packet):
        if self._connection:
            try:
                packet = self._fix_session(packet)
                rsp = self._connection.sr1(packet, timeout=self._timeout)
                if rsp:
                    rsp = TPKT(str(rsp))
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def receive_s7plus_packet(self):
        if self._connection:
            try:
                rsp = self._connection.recv()
                if rsp:
                    rsp = TPKT(str(rsp))
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None
        else:
            self.logger.error("Please create connect before receive packet!")