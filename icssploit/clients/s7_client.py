#! /usr/bin/env python
# coding:utf-8
# Author: WenZhe Zhu
from icssploit.clients.base import Base
from icssploit.protocols.cotp import *
from icssploit.protocols.s7comm import *
from scapy.supersocket import StreamSocket
import socket


VAR_NAME_TYPES = {
    'P': 0x80,      # I/O
    'I': 0x81,      # Memory area of inputs
    'Q': 0x82,      # Memory area of outputs
    'M': 0x83,      # Memory area of bit memory
    'DB': 0x84,     # Data block
    'L': 0x86,      # Local data
    'V': 0x87       # Previous local data
}


class S7Client(Base):
    def __init__(self, name, ip, port=102, src_tsap='\x01\x00', rack=0, slot=2, timeout=2):
        '''

        :param name: Name of this targets
        :param ip: S7 PLC ip
        :param port: S7 PLC port (default: 102)
        :param src_tsap: src_tsap
        :param rack: cpu rack (default: 0)
        :param slot: cpu slot (default: 2)
        :param timeout: timeout of socket (default: 2)
        '''
        super(S7Client, self).__init__(name=name)
        self._ip = ip
        self._port = port
        self._slot = slot
        self._src_tsap = src_tsap
        self._dst_tsap = '\x01' + struct.pack('B', rack * 0x20 + slot)
        self._pdur = 1
        self.protect_level = None
        self._connection = None
        self._connected = False
        self._timeout = timeout
        self._pdu_length = 480
        self.readable = False
        self.writeable = False
        self.authorized = False
        self._password = None
        self._mmc_password = None
        self.is_running = False

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
        packet2 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job", Parameters=S7SetConParameter())
        rsp2 = self.send_receive_s7_packet(packet2)
        if rsp2:
            self._connected = True
        # Todo: Need get pdu length from rsp2

    def _get_cpu_protect_level(self):
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="UserData", Parameters=S7ReadSZLParameterReq(),
                                                    Data=S7ReadSZLDataReq(SZLId=0x0232, SZLIndex=0x0004))
        rsp = self.send_receive_s7_packet(packet1)
        self.protect_level = int(str(rsp)[48].encode('hex'))
        self.logger.info("CPU protect level is %s" % self.protect_level)

    def get_target_info(self):
        order_code = ''
        version = ''
        module_type_name = ''
        as_name = ''
        module_name = ''
        serial_number = ''
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="UserData", Parameters=S7ReadSZLParameterReq(),
                                                    Data=S7ReadSZLDataReq(SZLId=0x0011, SZLIndex=0x0000))
        rsp1 = self.send_receive_s7_packet(packet1)
        try:
            order_code_data = rsp1[S7ReadSZLDataTreeRsp].Data[:rsp1[S7ReadSZLDataRsp].SZLLength]
            order_code = order_code_data[2:-7]
            version_data = rsp1[S7ReadSZLDataTreeRsp].Data[-3:]
            version = 'V {:x}.{:x}.{:x}'.format(
                int(version_data[0].encode('hex'), 16),
                int(version_data[1].encode('hex'), 16),
                int(version_data[2].encode('hex'), 16),
            )

        except Exception as err:
            self.logger.error("Can't get order code and version from target")
            return order_code, version, module_type_name, as_name, module_name, serial_number

        packet2 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="UserData", Parameters=S7ReadSZLParameterReq(),
                                                    Data=S7ReadSZLDataReq(SZLId=0x001c, SZLIndex=0x0000))
        rsp2 = self.send_receive_s7_packet(packet2)
        try:
            module_name_data = rsp2[S7ReadSZLDataTreeRsp].Data[
                rsp2[S7ReadSZLDataRsp].SZLLength + 2:rsp2[S7ReadSZLDataRsp].SZLLength * 2]
            module_name = str(module_name_data[:module_name_data.index('\x00')])
            self.logger.debug("module_name:%s " % module_name)
            as_name_data = rsp2[S7ReadSZLDataTreeRsp].Data[2:rsp2[S7ReadSZLDataRsp].SZLLength]
            as_name = str(as_name_data[:as_name_data.index('\x00')])
            self.logger.debug("as_name:%s " % as_name)
            serial_number_data = rsp2[S7ReadSZLDataTreeRsp].Data[
                               rsp2[S7ReadSZLDataRsp].SZLLength * 4 + 2:rsp2[S7ReadSZLDataRsp].SZLLength * 5]
            serial_number = str(serial_number_data[:serial_number_data.index('\x00')])
            self.logger.debug("serial_number:%s " % serial_number)
            module_type_name_data = rsp2[S7ReadSZLDataTreeRsp].Data[
                               rsp2[S7ReadSZLDataRsp].SZLLength * 5 + 2:rsp2[S7ReadSZLDataRsp].SZLLength * 6]
            module_type_name = str(module_type_name_data[:module_type_name_data.index('\x00')])
            self.logger.debug("module_type_name:%s " % module_type_name)

        except Exception as err:
            self.logger.error("Can't get module info from target")
            return order_code, version, module_type_name, as_name, module_name, serial_number

        return order_code, version, module_type_name, as_name, module_name, serial_number

    def check_privilege(self):
        self._get_cpu_protect_level()
        if self.protect_level == 1:
            self.logger.info("You have full privilege with this targets")
            self.readable = True
            self.writeable = True
        if self.protect_level == 2:
            if self.authorized is True:
                self.logger.info("You have full privilege with this targets")
                self.readable = True
                self.writeable = True
            else:
                self.logger.info("You only have read privilege with this targets")
                self.readable = True
                self.writeable = False
        if self.protect_level == 3:
            if self.authorized is True:
                self.logger.info("You have full privilege with this targets")
                self.readable = True
                self.writeable = True
            else:
                self.logger.info("You can't read or write with this targets")
                self.readable = False
                self.writeable = False

    def auth(self, password):
        """
        
        :param password: Paintext PLC password.
        """
        self.logger.info("Start authenticate with password %s" % password)
        password_hash = self._hash_password(password)
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="UserData", Parameters=S7PasswordParameterReq(),
                                                    Data=S7PasswordDataReq(Data=password_hash))
        rsp1 = self.send_receive_s7_packet(packet1)
        if rsp1.haslayer(S7PasswordParameterRsp):
            if rsp1[S7PasswordParameterRsp].ErrorCode == 0:
                self.authorized = True
                self.logger.info("Authentication succeed")
            else:
                if self.authorized is True:
                    self.logger.info("Already authorized")
                else:
                    error_code = rsp1[S7PasswordParameterRsp].ErrorCode
                    if error_code in S7_ERROR_CLASS.keys():
                        self.logger.error("Got error code: %s" % S7_ERROR_CLASS[error_code])
                    else:
                        self.logger.error("Get error code: %s" % hex(error_code))
                    self.logger.error("Authentication failure")
            self.check_privilege()
        else:
            self.logger.info("Receive unknown format packet, authentication failure")

    def clean_session(self):
        self.logger.info("Start clean the session")
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="UserData", Parameters=S7CleanSessionParameterReq(),
                                                    Data=S7CleanSessionDataReq())
        rsp1 = self.send_receive_s7_packet(packet1)
        if rsp1.haslayer(S7CleanSessionParameterRsp):
            if rsp1[S7CleanSessionParameterRsp].ErrorCode == 0:
                self.authorized = False
                self.logger.info("session cleaned")
            else:
                error_code = rsp1[S7CleanSessionParameterRsp].ErrorCode
                if error_code in S7_ERROR_CLASS.keys():
                    self.logger.error("Got error code: %s" % S7_ERROR_CLASS[error_code])
                else:
                    self.logger.error("Get error code: %s" % hex(error_code))
        else:
            self.logger.info("Receive unknown format packet, authentication failure")

    def _hash_password(self, password):
        password_hash_new = ''
        if len(password) < 1 or len(password) > 8:
            self.logger.error("Password length must between 1 to 8")
            return None
        else:
            password += '20'.decode('hex') * (8 - len(password))
            for i in range(8):
                if i < 2:
                    temp_data = ord(password[i])
                    temp_data ^= 0x55
                    password_hash_new += str(chr(temp_data))
                else:
                    temp_data1 = ord(password[i])
                    temp_data2 = ord(password_hash_new[i - 2])
                    temp_data1 = temp_data1 ^ 0x55 ^ temp_data2
                    password_hash_new += str(chr(temp_data1))
            return password_hash_new

    def _fix_pdur(self, payload):
        if self._pdur > 65535:
            self._pdur = 1
        try:
            payload.PDUR = self._pdur
            self._pdur += 1
            return payload
        except Exception as err:
            self.logger.error(err)
            return payload

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

    def send_s7_packet(self, packet):
        if self._connection:
            packet = self._fix_pdur(packet)
            try:
                self._connection.send(packet)

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def send_receive_s7_packet(self, packet):
        if self._connection:
            packet = self._fix_pdur(packet)
            try:
                rsp = self._connection.sr1(packet, timeout=self._timeout)
                if rsp:
                    rsp = TPKT(str(rsp))
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def receive_s7_packet(self):
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

    def upload_block_from_target(self, block_type, block_num, dist='A'):
        """

        :param block_type: "08": 'OB', "09": 'CMOD', "0A": 'DB', "0B": 'SDB', "0C": 'FC',
                            "0D": 'SFC', "0E": 'FB', "0F": 'SFB'
        :param block_num: Block number.
        :param dist: 'A': "Active embedded module", 'B': "Active as well as passive module",
                     'P': "Passive (copied, but not chained) module"
        :return: Block Data
        """
        if self.readable is False:
            self.logger.info("Didn't have read privilege on targets")
            return None
        block_data = ''
        if block_type in S7_BLOCK_TYPE_IN_FILE_NAME.keys():
            file_block_type = block_type
        else:
            for key, name in S7_BLOCK_TYPE_IN_FILE_NAME.iteritems():
                if name == block_type:
                    file_block_type = key
                    break
            else:
                self.logger.error("block_type: %s is incorrect please check again" % block_type)
                return

        if type(block_num) != int:
            self.logger.error("block_num must be int format.")
            return

        file_block_num = "{0:05d}".format(block_num)
        file_name = '_' + file_block_type + file_block_num + dist
        self.logger.info("Start upload %s%s from target" % (block_type, block_num))
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job",
                                                    Parameters=S7RequestUploadBlockParameterReq(Filename=file_name))
        rsp1 = self.send_receive_s7_packet(packet1)
        # Todo: Might got some error
        if rsp1.ErrorClass != 0x0:
            self.logger.error("Can't upload %s%s from target" % (block_type, block_num))
            self.logger.error("Error Class: %s, Error Code %s" % (rsp1.ErrorClass, rsp1.ErrorCode))
            return None
        packet2 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job",
                                                    Parameters=S7UploadBlockParameterReq())
        packet2[S7UploadBlockParameterReq].UploadId = rsp1[S7RequestUploadBlockParameterRsp].UploadId
        while True:
            rsp2 = self.send_receive_s7_packet(packet2)
            if rsp2.ErrorClass != 0x0:
                self.logger.error("Can't upload %s%s from targets" % (block_type, block_num))
                self.logger.error("Error Class: %s, Error Code %s" % (rsp1.ErrorClass, rsp1.ErrorCode))
                return None
            self.logger.debug("rsp2: %s" % str(rsp2).encode('hex'))
            block_data += rsp2.Data.Data
            if rsp2.Parameters.FunctionStatus != 1:
                break
        packet3 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job", Parameters=S7UploadBlockEndParameterReq())
        self.send_receive_s7_packet(packet3)
        self.logger.info("Upload %s%s from target succeed" % (block_type, block_num))
        return block_data

    def get_info_from_block(self, block_data):
        """

        :param block_data: Block data.
        :return: mem_length, mc7_length, block_type, block_num
        """
        try:
            mem_length = struct.unpack('!i', block_data[8:12])[0]
            mc7_length = struct.unpack('!h', block_data[34:36])[0]
            block_type = S7_BLOCK_TYPE_IN_BLOCK[ord(block_data[5])]
            block_num = struct.unpack('!h', block_data[6:8])[0]
            return mem_length, mc7_length, block_type, block_num

        except Exception as err:
            self.logger.error(err)
            return None

    def download_block_to_target(self, block_data, dist='P', transfer_size=462, stop_target=False):
        """ Download block to target and active block.

        :param block_data: Block data to download.
        :param dist: 'A': "Active embedded module", 'B': "Active as well as passive module",
                     'P': "Passive (copied, but not chained) module".
        :param transfer_size: Transfer size for each packet.
        :param stop_target: Stop target PLC before download block, True or False.
        """
        if self.writeable is False:
            self.logger.info("Didn't have write privilege on targets")
            return None
        mem_length, mc7_length, block_type, block_num = self.get_info_from_block(block_data)
        self.logger.info("Start download %s%s to targets" % (block_type, block_num))
        file_block_type = None
        for key, name in S7_BLOCK_TYPE_IN_FILE_NAME.iteritems():
            if name == block_type:
                file_block_type = key
                break
        if not file_block_type:
            self.logger.error("block_type: %s is incorrect please check again" % block_type)
            return

        file_block_num = "{0:05d}".format(block_num)
        file_name = '_' + file_block_type + file_block_num + dist

        load_memory_length = '0' * (6 - len(str(mem_length))) + str(mem_length)
        mc7_length = '0' * (6 - len(str(mc7_length))) + str(mc7_length)
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job",
                                                    Parameters=S7RequestDownloadParameterReq(
                                                        Filename=file_name,
                                                        LoadMemLength=load_memory_length,
                                                        MC7Length=mc7_length)
                                                    )
        rsp1 = self.send_receive_s7_packet(packet1)
        if rsp1.ErrorClass != 0x0:
            self.logger.error("Can't Download %s%s to targets" % (block_type, block_num))
            self.logger.error("Error Class: %s, Error Code %s" % (rsp1.ErrorClass, rsp1.ErrorCode))
            return None

        if len(rsp1) > 20:
            download_req = TPKT(rsp1.load)
        else:
            download_req = self.receive_s7_packet()
        # Get pdur from download_req
        self._pdur = download_req.PDUR
        # DownloadBlock
        for i in range(0, len(block_data), transfer_size):
            if i + transfer_size <= len(block_data):
                packet2 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="AckData",
                                                            Parameters=S7DownloadParameterRsp(FunctionStatus=1),
                                                            Data=S7DownloadDataRsp(
                                                                Data=block_data[i:i + transfer_size]))
                rsp2 = self.send_receive_s7_packet(packet2)
                self._pdur = rsp2.PDUR
            else:
                packet2 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="AckData",
                                                            Parameters=S7DownloadParameterRsp(FunctionStatus=0),
                                                            Data=S7DownloadDataRsp(
                                                                Data=block_data[i:i + transfer_size]))
                self.send_s7_packet(packet2)
        # DownloadBlockEnd
        download_end_req = self.receive_s7_packet()
        self._pdur = download_end_req.PDUR
        packet3 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="AckData", Parameters=S7DownloadEndParameterRsp())
        self.send_s7_packet(packet3)
        # Insert block
        self.logger.debug("File_name:%s" % ('\x00' + file_name[1:]))
        packet4 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job",
                                                    Parameters=S7PIServiceParameterReq(
                                                        ParameterBlock=S7PIServiceParameterBlock(
                                                            FileNames=['\x00' + file_name[1:]]),
                                                        PI="_INSE")
                                                    )
        # Todo: Might have a better way to do this
        # packet4[S7PIServiceParameterReq].ParameterBlock = S7PIServiceParameterBlock(FileNames=[file_name[1:]])
        rsp4 = self.send_receive_s7_packet(packet4)
        if rsp4.ErrorClass != 0x0:
            self.logger.error("Can't insert %s%s to targets" % (block_type, block_num))
            self.logger.error("Error Class: %s, Error Code %s" % (rsp1.ErrorClass, rsp1.ErrorCode))
            return None
        self.logger.info("Download %s%s to target succeed" % (block_type, block_num))

    def download_block_to_target_only(self, block_data, dist='P', transfer_size=462, stop_target=False):
        """ Download block to target only (didn't active block).

        :param block_data: Block data to download.
        :param dist: 'A': "Active embedded module", 'B': "Active as well as passive module",
                     'P': "Passive (copied, but not chained) module".
        :param transfer_size: Transfer size for each packet.
        :param stop_target: Stop target PLC before download block, True or False.
        """
        if self.writeable is False:
            self.logger.info("Didn't have write privilege on targets")
            return None
        mem_length, mc7_length, block_type, block_num = self.get_info_from_block(block_data)
        self.logger.info("Start download %s%s to targets" % (block_type, block_num))
        file_block_type = None
        for key, name in S7_BLOCK_TYPE_IN_FILE_NAME.iteritems():
            if name == block_type:
                file_block_type = key
                break
        if not file_block_type:
            self.logger.error("block_type: %s is incorrect please check again" % block_type)
            return

        file_block_num = "{0:05d}".format(block_num)
        file_name = '_' + file_block_type + file_block_num + dist

        load_memory_length = '0' * (6 - len(str(mem_length))) + str(mem_length)
        mc7_length = '0' * (6 - len(str(mc7_length))) + str(mc7_length)
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job",
                                                    Parameters=S7RequestDownloadParameterReq(
                                                        Filename=file_name,
                                                        LoadMemLength=load_memory_length,
                                                        MC7Length=mc7_length)
                                                    )
        rsp1 = self.send_receive_s7_packet(packet1)
        if rsp1.ErrorClass != 0x0:
            self.logger.error("Can't Download %s%s to targets" % (block_type, block_num))
            self.logger.error("Error Class: %s, Error Code %s" % (rsp1.ErrorClass, rsp1.ErrorCode))
            return None

        if len(rsp1) > 20:
            download_req = TPKT(rsp1.load)
        else:
            download_req = self.receive_s7_packet()
        # Get pdur from download_req
        self._pdur = download_req.PDUR
        # DownloadBlock
        for i in range(0, len(block_data), transfer_size):
            if i + transfer_size <= len(block_data):
                packet2 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="AckData",
                                                            Parameters=S7DownloadParameterRsp(FunctionStatus=1),
                                                            Data=S7DownloadDataRsp(
                                                                Data=block_data[i:i + transfer_size]))
                rsp2 = self.send_receive_s7_packet(packet2)
                self._pdur = rsp2.PDUR
            else:
                packet2 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="AckData",
                                                            Parameters=S7DownloadParameterRsp(FunctionStatus=0),
                                                            Data=S7DownloadDataRsp(
                                                                Data=block_data[i:i + transfer_size]))
                self.send_s7_packet(packet2)
        # DownloadBlockEnd
        download_end_req = self.receive_s7_packet()
        self._pdur = download_end_req.PDUR
        packet3 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="AckData", Parameters=S7DownloadEndParameterRsp())
        self.send_s7_packet(packet3)
        self.logger.info("Download %s%s to target succeed" % (block_type, block_num))

    def get_target_status(self):
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="UserData", Parameters=S7ReadSZLParameterReq(),
                                                    Data=S7ReadSZLDataReq(SZLId=0x0424, SZLIndex=0x0000))
        rsp = self.send_receive_s7_packet(packet1)
        status = str(rsp)[44]
        if status == '\x08':
            self.logger.info("Target is in run mode")
            self.is_running = True
        elif status == '\x04':
            self.logger.info("Target is in stop mode")
            self.is_running = False
        else:
            self.logger.info("Target is in unknown mode")
            self.is_running = False

    def stop_target(self):
        self.get_target_status()
        if not self.is_running:
            self.logger.info("Target is already stop")
            return
        self.logger.info("Trying to stop targets")
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job", Parameters=S7StopCpuParameterReq())
        rsp1 = self.send_receive_s7_packet(packet1)
        if rsp1.ErrorClass != 0x0:
            self.logger.error("Can't Stop Target")
            self.logger.error("Error Class: %s, Error Code %s" % (rsp1.ErrorClass, rsp1.ErrorCode))
            return
        time.sleep(2)  # wait targets to stop
        self.get_target_status()

    def start_target(self, cold=False):
        ''' Start target PLC

        :param cold: Doing cold restart, True or False.
        '''
        self.get_target_status()
        if self.is_running:
            self.logger.info("Target is already running")
            return
        self.logger.info("Trying to start targets")

        if cold:
            packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job", Parameters=S7PIServiceParameterReq(
                ParameterBlock=S7PIServiceParameterStringBlock()))
        else:
            packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job", Parameters=S7PIServiceParameterReq())

        rsp1 = self.send_receive_s7_packet(packet1)
        if rsp1.ErrorClass != 0x0:
            self.logger.error("Can't Start Target")
            self.logger.error("Error Class: %s, Error Code %s" % (rsp1.ErrorClass, rsp1.ErrorCode))
            return
        time.sleep(2)  # wait targets to start
        self.get_target_status()

    @staticmethod
    def get_transport_size_from_data_type(data_type):
        for key, name in S7_TRANSPORT_SIZE_IN_PARM_ITEMS.iteritems():
            if isinstance(data_type, str):
                if name.startswith(data_type.upper()):
                    return key
            elif isinstance(data_type, int):
                return data_type
        return None

    def get_item_pram_from_item(self, item):
        block_num = ''
        area_type = ''
        address = ''
        transport_size = ''
        try:
            for key in VAR_NAME_TYPES:
                if isinstance(item[0], str):
                    if item[0].startswith(key):
                        area_type = VAR_NAME_TYPES[key]

                elif isinstance(item[0], int):
                    if item[0] in VAR_NAME_TYPES.keys():
                        area_type = item[0]

            # Data block
            if area_type == 0x84:
                block_num = int(item[0][2:])
            else:
                block_num = 0

            if isinstance(item[1], str):
                address_data = item[1].split('.')
                address = int(address_data[0]) * 8 + int(address_data[1])

            elif isinstance(item[1], int):
                address = item[1]

            else:
                self.logger.error("Address: %s is not string or int format, please check again" % item[1])

            transport_size = self.get_transport_size_from_data_type(item[2])

        except Exception as err:
            self.logger.error("Can't get item parameter with var_name: %s with error: \r %s" % (item, err))
            return transport_size, block_num, area_type, address

        return transport_size, block_num, area_type, address

    @staticmethod
    def bytes_to_bit_array(bytes_data):
        bit_array = ""
        for data in bytes_data:
            bit_array += '{:08b}'.format(ord(data))
        return map(int, list(bit_array))

    def _unpack_data_with_transport_size(self, req_item, rsp_item):
        # ref http://www.plcdev.com/step_7_elementary_data_types
        if isinstance(rsp_item, S7ReadVarDataItemsRsp):
            try:
                req_type = req_item.TransportSize
                if req_type not in S7_TRANSPORT_SIZE_IN_PARM_ITEMS.keys():
                    return []
                # BIT (0x01)
                elif req_type == 0x01:
                    bit_list = self.bytes_to_bit_array(rsp_item.Data)
                    return bit_list[-1:][0]
                # BYTE (0x02)
                elif req_type == 0x02:
                    byte_list = list(rsp_item.Data)
                    return map(ord, byte_list)
                # CHAR (0x03)
                elif req_type == 0x03:
                    char_list = list(rsp_item.Data)
                    return char_list
                # WORD (0x04) 2 bytes Decimal number unsigned
                elif req_type == 0x04:
                    word_data = rsp_item.Data
                    word_list = [struct.unpack('!H', word_data[i:i+2])[0] for i in range(0, len(word_data), 2)]
                    return word_list
                # INT (0x05) 2 bytes Decimal number signed
                elif req_type == 0x05:
                    int_data = rsp_item.Data
                    int_list = [struct.unpack('!h', int_data[i:i+2])[0] for i in range(0, len(int_data), 2)]
                    return int_list
                # DWORD (0x06) 4 bytes Decimal number unsigned
                elif req_type == 0x06:
                    dword_data = rsp_item.Data
                    dword_list = [struct.unpack('!I', dword_data[i:i+4])[0] for i in range(0, len(dword_data), 4)]
                    return dword_list
                # DINT (0x07) 4 bytes Decimal number signed
                elif req_type == 0x07:
                    dint_data = rsp_item.Data
                    dint_list = [struct.unpack('!i', dint_data[i:i+4])[0] for i in range(0, len(dint_data), 4)]
                    return dint_list
                # REAL (0x08) 4 bytes IEEE Floating-point number
                elif req_type == 0x08:
                    dint_data = rsp_item.Data
                    dint_list = [struct.unpack('!f', dint_data[i:i+4])[0] for i in range(0, len(dint_data), 4)]
                    return dint_list
                else:
                    return rsp_item.Data

            except Exception as err:
                return []
        return []

    @staticmethod
    def _pack_data_with_transport_size(req_item, data_list):
        # ref http://www.plcdev.com/step_7_elementary_data_types
        if isinstance(req_item, S7WriteVarItemsReq):
            try:
                req_type = req_item.TransportSize
                if req_type not in S7_TRANSPORT_SIZE_IN_PARM_ITEMS.keys():
                    return []
                # BIT (0x01)
                elif req_type == 0x01:
                    # Only support write 1 bit.
                    if isinstance(data_list, list):
                        bit_data = chr(data_list[0])
                    else:
                        bit_data = chr(data_list)
                    return bit_data
                # BYTE (0x02)
                elif req_type == 0x02:
                    byte_data = ''.join(chr(x) for x in data_list)
                    return byte_data
                # CHAR (0x03)
                elif req_type == 0x03:
                    char_data = ''.join(x for x in data_list)
                    return char_data
                # WORD (0x04) 2 bytes Decimal number unsigned
                elif req_type == 0x04:
                    word_data = ''.join(struct.pack('!H', x) for x in data_list)
                    return word_data
                # INT (0x05) 2 bytes Decimal number signed
                elif req_type == 0x05:
                    int_data = ''.join(struct.pack('!h', x) for x in data_list)
                    return int_data
                # DWORD (0x06) 4 bytes Decimal number unsigned
                elif req_type == 0x06:
                    dword_data = ''.join(struct.pack('!I', x) for x in data_list)
                    return dword_data
                # DINT (0x07) 4 bytes Decimal number signed
                elif req_type == 0x07:
                    dint_data = ''.join(struct.pack('!i', x) for x in data_list)
                    return dint_data
                # REAL (0x08) 4 bytes IEEE Floating-point number
                elif req_type == 0x08:
                    real_data = ''.join(struct.pack('!f', x) for x in data_list)
                    return real_data
                # Other data
                else:
                    other_data = ''.join(x for x in data_list)
                    return other_data

            except Exception as err:
                return ''
        return ''

    @staticmethod
    def _convert_transport_size_from_parm_to_data(parm_transport_size):
        if parm_transport_size not in S7_TRANSPORT_SIZE_IN_PARM_ITEMS.keys():
            return None
        else:
            # BIT (0x03)
            if parm_transport_size == 0x01:
                return 0x03
            # BYTE/WORD/DWORD (0x04)
            elif parm_transport_size in (0x02, 0x04, 0x06):
                return 0x04
            # INTEGER (0x05)
            elif parm_transport_size in (0x05, 0x07):
                return 0x05
            # REAL (0x07)
            elif parm_transport_size == 0x08:
                return 0x07
            # OCTET STRING (0x09)
            else:
                return 0x09

    def read_var(self, items):
        '''

        :param items:
        :return: Return data list of read_var items.
        '''
        read_items = []
        items_data = []

        if isinstance(items, list):
            for i in range(len(items)):
                try:
                    transport_size, block_num, area_type, address = self.get_item_pram_from_item(items[i])
                    length = int(items[i][3])
                    if transport_size:
                        read_items.append(S7ReadVarItemsReq(TransportSize=transport_size,
                                                            GetLength=length,
                                                            BlockNum=block_num,
                                                            AREAType=area_type,
                                                            Address=address
                                                            )
                                          )
                except Exception as err:
                    self.logger.error("Can't create read var packet because of: \r %s" % err)
                    return None
        else:
            self.logger.error("items is not list please check again")
            return None

        packet = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job", Parameters=S7ReadVarParameterReq(
            Items=read_items))
        rsp = self.send_receive_s7_packet(packet)
        if rsp.ErrorClass != 0x0:
            self.logger.error("Can't Read var from Target")
            self.logger.error("Error Class: %s, Error Code %s" % (rsp.ErrorClass, rsp.ErrorCode))
            return None
        if rsp.haslayer(S7ReadVarDataItemsRsp):
            for i in range(len(rsp[S7ReadVarDataRsp].Items)):
                req_item = read_items[i][S7ReadVarItemsReq]
                rsp_item = rsp[S7ReadVarDataRsp].Items[i]
                if rsp_item.ReturnCode == 0xff:
                    rsp_item_data = self._unpack_data_with_transport_size(req_item, rsp_item)
                    items_data.append(rsp_item_data)
                else:
                    items_data.append('')
        return items_data

    def write_var(self, items):
        """

        :param items:
        :return:
        """
        write_items = []
        items_data = []
        write_data_rsp = []
        if isinstance(items, list):
            for i in range(len(items)):
                try:
                    transport_size, block_num, area_type, address = self.get_item_pram_from_item(items[i])
                    length = len(items[i][3])
                    if transport_size:
                        write_items.append(S7WriteVarItemsReq(TransportSize=transport_size,
                                                              ItemCount=length,
                                                              BlockNum=block_num,
                                                              AREAType=area_type,
                                                              BitAddress=address
                                                              )
                                           )
                        write_data = self._pack_data_with_transport_size(write_items[i], items[i][3])
                        items_data.append(S7WriteVarDataItemsReq(
                            TransportSize=self._convert_transport_size_from_parm_to_data(transport_size),
                            Data=write_data))
                except Exception as err:
                    self.logger.error("Can't create write var packet because of: \r %s" % err)
                    return None
        else:
            self.logger.error("items is not list please check again")
            return None

        packet = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job",
                                                   Parameters=S7WriteVarParameterReq(Items=write_items),
                                                   Data=S7WriteVarDataReq(Items=items_data))
        rsp = self.send_receive_s7_packet(packet)
        if rsp.ErrorClass != 0x0:
            self.logger.error("Can't write var to Target.")
            self.logger.error("Error Class: %s, Error Code %s" % (rsp.ErrorClass, rsp.ErrorCode))
            return None
        if rsp.haslayer(S7WriteVarDataRsp):
            for rsp_items in rsp[S7WriteVarDataRsp].Items:
                write_data_rsp.append(rsp_items.ReturnCode)
            return write_data_rsp
        else:
            self.logger.error("Unknown response packet format.")
            return None
