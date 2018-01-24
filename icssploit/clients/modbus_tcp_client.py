#! /usr/bin/env python
# coding:utf-8
# Author: WenZhe Zhu
from icssploit.clients.base import Base
from icssploit.protocols.modbus_tcp import *
from scapy.supersocket import StreamSocket


class ModbusClient(Base):
    def __init__(self, name, ip, port=502, timeout=2):
        '''

        :param name: Name of this targets
        :param ip: Modbus Target ip
        :param port: Modbus TCP port (default: 502)
        :param timeout: timeout of socket (default: 2)
        '''
        super(ModbusClient, self).__init__(name=name)
        self._ip = ip
        self._port = port
        self._connection = None
        self._connected = False
        self._timeout = timeout

    def connect(self):
        sock = socket.socket()
        sock.connect((self._ip, self._port))
        sock.settimeout(self._timeout)
        self._connection = StreamSocket(sock, Raw)

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

    def send_modbus_packet(self, packet):
        if self._connection:
            try:
                self._connection.send(packet)

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def send_receive_modbus_packet(self, packet):
        func_code = packet.func_code
        if self._connection:
            try:
                rsp = self._connection.sr1(packet, timeout=self._timeout)
                if rsp:
                    rsp = ModbusHeaderResponse(str(rsp))
                    if rsp.haslayer(modbus_response_classes[func_code]):
                        return rsp
                    elif rsp.haslayer(GenericError):
                        self.logger.error("Got error with error code:%s" % rsp.exceptCode)
                return None

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def receive_modbus_packet(self):
        if self._connection:
            try:
                rsp = self._connection.recv()
                if rsp:
                    rsp = ModbusHeaderResponse(str(rsp))
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None
        else:
            self.logger.error("Please create connect before receive packet!")

    @staticmethod
    def bytes_to_bit_array(coils_bytes):
        bit_array = ""
        for data in coils_bytes:
            bit_array += '{:08b}'.format(ord(data))[::-1]
        return list(bit_array)

    def read_coils(self, address, count):
        '''

        :param address: Reference Number of coils
        :param count: Bit Count for read
        :return: Coil Status in list, if got some error return None.
        '''
        packet = ModbusHeaderRequest(func_code=0x01) / ReadCoilsRequest(ReferenceNumber=address, BitCount=count)
        rsp = self.send_receive_modbus_packet(packet)
        if rsp:
            coils = rsp.CoilsStatus
            coils = self.bytes_to_bit_array(coils)
            return coils[:count]
        else:
            return None

    def read_discrete_inputs(self, address, count):
        '''

        :param address: Reference Number of discrete inputs
        :param count: Bit Count for read
        :return: InputStatus in list, if got some error return None.
        '''
        packet = ModbusHeaderRequest(func_code=0x02) / ReadDiscreteInputsRequest(ReferenceNumber=address, BitCount=count)
        rsp = self.send_receive_modbus_packet(packet)
        if rsp:
            inputStatus = rsp.InputStatus
            inputStatus = self.bytes_to_bit_array(inputStatus)
            return inputStatus[:count]
        else:
            return None

    def read_holding_registers(self, address, count):
        '''

        :param address: Reference Number of holding registers
        :param count: Word count for read
        :return: Registers in list
        '''
        packet = ModbusHeaderRequest(func_code=0x03) / \
                 ReadHoldingRegistersRequest(ReferenceNumber=address, WordCount=count)
        rsp = self.send_receive_modbus_packet(packet)
        registers = rsp.RegisterValue
        return registers

    def read_input_registers(self, address, count):
        '''

        :param address: Reference Number of input registers
        :param count: Word count for read
        :return: Registers in list
        '''
        packet = ModbusHeaderRequest(func_code=0x04) / \
                 ReadInputRegistersRequest(ReferenceNumber=address, WordCount=count)
        rsp = self.send_receive_modbus_packet(packet)
        registers = rsp.RegisterValue
        return registers

    def write_single_coil(self, address, value):
        '''

        :param address: Reference Number of coil
        :param value: coil's value(True or False)
        :return: Response packet
        '''
        # TODO: Need return only value.
        if value is True:
            data = 0xFF00
        else:
            data = 0x0000
        packet = ModbusHeaderRequest(func_code=0x05) / WriteSingleCoilRequest(ReferenceNumber=address, Value=data)
        rsp = self.send_receive_modbus_packet(packet)
        return rsp

    def write_single_register(self, address, value):
        '''

        :param address: Reference Number of register
        :param value: value of register (0x0-0xffff)
        :return: Response packet
        '''
        packet = ModbusHeaderRequest(func_code=0x06) / WriteSingleRegisterRequest(ReferenceNumber=address, Value=value)
        rsp = self.send_receive_modbus_packet(packet)
        return rsp

    def write_multiple_coils(self, address, values):
        '''

        :param address: Reference Number of coils
        :param values: values to write in list must in multiples of 8. example: values = [0, 0, 0, 0, 1, 1, 1, 1]
        :return: Response packet
        '''
        values = values[::-1]  # least significant bit = first coil
        packet = ModbusHeaderRequest(func_code=0x0F) / WriteMultipleCoilsRequest(ReferenceNumber=address, Values=values)
        rsp = self.send_receive_modbus_packet(packet)
        return rsp

    def write_multiple_registers(self, address, values):
        '''

        :param address: address: Reference Number of register
        :param values: values to write in list. example: values = [0x01, 0x02, 0x03, 0x04]
        :return: Response packet
        '''
        packet = ModbusHeaderRequest(func_code=0x10) / \
                 WriteMultipleRegistersRequest(ReferenceNumber=address, Values=values)
        rsp = self.send_receive_modbus_packet(packet)
        return rsp

    def read_file_record(self, file_number, offset, length):
        '''

        :param file_number: File number
        :param offset: offset of file
        :param length: length to read
        :return: Response packet
        '''
        packet = ModbusHeaderRequest(func_code=0x14) / ReadFileRecordRequest()
        packet[ReadFileRecordRequest].Groups = ReadFileSubRequest(FileNumber=file_number, Offset=offset, Length=length)
        rsp = self.send_receive_modbus_packet(packet)
        return rsp

    def write_file_record(self, file_number, offset, data):
        '''

        :param file_number: File number
        :param offset: offset of file
        :param data: data to write
        :return: Response packet
        '''
        data_list = []
        for i in range(0, len(data), 0x02):
            data1 = struct.unpack("!H", data[i:i+2])[0]
            data_list.append(data1)
        packet = ModbusHeaderRequest(func_code=0x15) / WriteFileRecordRequest()
        packet[WriteFileRecordRequest].Groups = WriteFileSubRequest(
            FileNumber=file_number, Offset=offset, Data=data_list)
        rsp = self.send_receive_modbus_packet(packet)
        return rsp

    def mask_write_register(self, address, and_mask=0xffff, or_mask=0x0000):
        '''

        :param address: Reference Number of register
        :param and_mask: And mask of register
        :param or_mask: Or mask of register
        :return: Response packet
        '''
        packet = ModbusHeaderRequest(func_code=0x16) / \
                 MaskWriteRegisterRequest(ReferenceNumber=address, AndMask=and_mask, OrMask=or_mask),
        rsp = self.send_receive_modbus_packet(packet)
        return rsp

    def read_write_multiple_registers(self, read_address, read_count, write_address, values):
        '''

        :param read_address: Reference Number of register to read
        :param read_count: Word count for read
        :param write_address: Reference Number of register to write
        :param values: values to write in list. example: values = [0x01, 0x02, 0x03, 0x04]
        :return: Response packet
        '''
        packet = ModbusHeaderRequest(func_code=0x17) / \
                 ReadWriteMultipleRegistersRequest(ReadReferenceNumber=read_address, ReadWordCount=read_count,
                                                   WriteReferenceNumber=write_address, RegisterValues=values)
        rsp = self.send_receive_modbus_packet(packet)
        return rsp

    def read_fifo_queue(self, address):
        '''

        :param address: Reference Number of fifo
        :return: Response packet
        '''
        packet = ModbusHeaderRequest(func_code=0x17) / ReadFIFOQueueRequest(ReferenceNumber=address)
        rsp = self.send_receive_modbus_packet(packet)
        return rsp
