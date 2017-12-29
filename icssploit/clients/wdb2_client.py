#! /usr/bin/env python
# coding:utf-8
# Author: WenZhe Zhu
from icssploit.clients.base import Base
from icssploit.protocols.wdbrpc2 import *
from icssploit.thirdparty import xdrlib
from scapy.supersocket import StreamSocket


class Wdb2Client(Base):
    def __init__(self, name, ip, port=17185, timeout=2, mem_buff_size=300):
        '''

        :param name: Name of this targets
        :param ip: VxWorks ip
        :param port: WDB port (default: 17185)
        :param timeout: timeout of socket (default: 2)
        :param mem_buff_size: Mem buff size for memory read or write (default: 300)
        '''
        super(Wdb2Client, self).__init__(name=name)
        self._ip = ip
        self._port = port
        self._timeout = timeout
        self._connection = None
        self._target_info = {}
        self._seq = None
        self._mem_buff_size = mem_buff_size
        self.mem_dump = ''
        self.target_info = {}

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((self._ip, self._port))
        sock.settimeout(self._timeout)
        self._connection = StreamSocket(sock, Raw)
        self._seq = 1
        connect_packet = RPCReq() / WdbConnectReq()
        connect_packet[RPCReq].Procedure = 0x7a
        connect_packet[RPCReq].Seq = self._seq
        self.send_receive_wdb_packet(connect_packet)

    def reconnect(self):
        self.connect()

    def _get_seq(self):
        if self._seq >= 65535:
            self.connect()
            return self._seq
        else:
            return self._seq

    def _fix_seq(self, payload):
        if self._seq > 65535:
            self._seq = 1
        try:
            payload.Seq = self._seq
            self._seq += 1
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

    def send_wdb_packet(self, packet):
        if self._connection:
            packet = self._fix_seq(packet)
            try:
                self._connection.send(packet)

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def send_receive_wdb_packet(self, packet):
        if self._connection:
            packet = self._fix_seq(packet)
            try:
                rsp = self._connection.sr1(packet, timeout=self._timeout)
                if rsp:
                    rsp = RPCRsp(str(rsp))
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def receive_wdb_packet(self):
        if self._connection:
            try:
                rsp = self._connection.recv()
                if rsp:
                    rsp = RPCRsp(str(rsp))
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None
        else:
            self.logger.error("Please create connect before receive packet!")

    def _unpack_info(self, info):
        self.target_info = {}
        info = xdrlib.Unpacker(info)
        self.target_info["Target_Type"] = info.unpack_string()  # 'VxWorks\x00'
        self.target_info["Vx_Version"] = info.unpack_string()  # '6.6\x00'
        self.target_info["Unknow1"] = info.unpack_uint()  # 80
        self.target_info["Unknow2"] = info.unpack_uint()  # 86
        self.target_info["CPU_Type"] = info.unpack_string()  # '86\x00'
        self.target_info["compiler"] = info.unpack_string()  # '86\x00'
        self.target_info["Unknow3"] = info.unpack_uint()  # 86
        self.target_info["Unknow4"] = info.unpack_uint()  # 86
        self.target_info["Unknow5"] = info.unpack_uint()  # 86
        self.target_info["Unknow6"] = info.unpack_uint()  # 86
        self.target_info["Unknow7"] = info.unpack_uint()  # 86
        self.target_info["CPU_Model"] = info.unpack_string()  # '86\x00'
        self.target_info["Unknow8"] = info.unpack_string()  # '86\x00'
        self.target_info["Unknow9"] = info.unpack_uint()  # 86
        self.target_info["Memory_Size"] = info.unpack_uint()  # 86
        self.target_info["Unknow10"] = info.unpack_uint()
        self.target_info["Unknow11"] = info.unpack_uint()
        self.target_info["Unknow12"] = info.unpack_uint()
        self.target_info["Unknow13"] = info.unpack_uint()
        self.target_info["Unknow14"] = info.unpack_uint()
        self.target_info["Unknow15"] = info.unpack_uint()
        return self.target_info

    def get_target_info(self):
        info_packet = RPCReq() / WdbGetInfoReq()
        info_packet[RPCReq].Procedure = 0x7b
        rsp = self.send_receive_wdb_packet(info_packet)
        info = rsp.load[4:]
        target_info = self._unpack_info(info)
        return target_info

    def _write_memory(self, address, data):
        '''

        :param address: offset of target memory
        :param data: data need to write to target
        :return: target response packet
        '''

        address = int(address)
        pkt = RPCReq() / WdbMemWriteReq(Offset=address, Buff=data)
        pkt[RPCReq].Procedure = 0xb
        print('start writing memory at 0x', struct.pack("!I", address).encode('hex'))
        return self.send_receive_wdb_packet(pkt)

    def write_target_memory(self, address, data):
        '''
        :param address: offset of memory
        :param data: data need to write
        :return: None
        '''
        address = int(address)
        if len(data) < 4:
            print("data length can't less than 4 byte")
        else:
            if len(data) % 4 != 0:
                data += '\x00' * (len(data) % 4)

        for i in range(0, len(data), 4):
            buff = data[i:i + 4]
            res = self._write_memory(address, buff)
            if res is None:
                print("can't write memory at 0x", struct.pack("!I", address).encode('hex'))
                return
            address += 4

    def _read_memory(self, address, length):
        '''

        :param address: offset of target memory
        :param length: length of memory to be read
        :return: Memory Data
        '''
        address = int(address)
        pkt = RPCReq() / WdbMemReadReq(Offset=address, Length=length)
        pkt[RPCReq].Procedure = 0xa
        rsp = self.send_receive_wdb_packet(pkt)
        if rsp.WdbErrorState != 0x0:
            self.logger.error("Can't read memory from %s with length %s" % (address, length))
            self.logger.error("Error Code %s" % rsp.WdbErrorState)
            return None
        buff_length = struct.unpack('!i', rsp.load[12:16])[0]
        buff = rsp.load[16:16 + buff_length]
        return buff

    def read_target_memory(self, address, length):
        self.mem_dump = ''
        address = int(address)
        if length < self._mem_buff_size:
            temp_length = length
        else:
            temp_length = self._mem_buff_size
        for offset in range(address, address + length, temp_length):
            self.logger.info('Dumping memory at %s / %s' % (offset, address + length))
            self.mem_dump += self._read_memory(offset, temp_length)
        return self.mem_dump


# if __name__ == '__main__':
#     conf.verb = 0
#     # target="192.168.102.88"
#     target = "192.168.102.89"
#     # target = "192.168.150.156"
#     tester = Wdb2Client(name='unit_test', ip=target)
#     tester.connect()
#     tester.get_target_info()
#     print tester.target_info