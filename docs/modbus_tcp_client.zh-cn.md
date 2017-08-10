# Modbus-TCP Client

# 使用Modbus-TCP Client

## 导入module
    root@kali:~/Desktop/temp/isf# python
    Python 2.7.9 (default, Mar  1 2015, 18:22:53)
    [GCC 4.9.2] on linux2
    Type "help", "copyright", "credits" or "license" for more information.
    >>> from icssploit.clients.modbus_tcp_client import ModbusClient

## 初始化modbus客户端
    >>> target = ModbusClient(name='modbus_tcp_client', ip="172.16.99.133")
    >>> target.connect()
    
## 读取线圈(ReadCoils)
    >>> target.read_coils(address=100, count=10)
    Begin emission:
    Finished to send 1 packets.
    *
    Received 1 packets, got 1 answers, remaining 0 packets
    ['0', '0', '0', '0', '0', '0', '0', '0', '0', '0']
    >>>

## 写入线圈(WriteCoils)
    >>> target.write_multiple_coils(address=100, values=[0, 0, 0, 0, 1, 1, 1, 1])
    Begin emission:
    Finished to send 1 packets.
    *
    Received 1 packets, got 1 answers, remaining 0 packets
    <ModbusHeaderResponse  trans_id=3 proto_id=0 length=6 unit_id=0 func_code=15 |<WriteMultipleCoilsResponse  ReferenceNumber=100 BitCount=8 |>>
    >>> target.read_coils(address=100, count=8)
    Begin emission:
    Finished to send 1 packets.
    *
    Received 1 packets, got 1 answers, remaining 0 packets
    ['0', '0', '0', '0', '1', '1', '1', '1']
    >>>

## 读取保持寄存器(ReadHoldingRegisters)
    >>> target.read_holding_registers(address=100, count=10)
    Begin emission:
    Finished to send 1 packets.
    *
    Received 1 packets, got 1 answers, remaining 0 packets
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

## 写入寄存器(WriteRegisters)
    >>> target.write_multiple_registers(address=100, values=[0x01, 0x02, 0x03, 0x04])
    Begin emission:
    Finished to send 1 packets.
    *
    Received 1 packets, got 1 answers, remaining 0 packets
    <ModbusHeaderResponse  trans_id=3 proto_id=0 length=6 unit_id=0 func_code=16 |<WriteMultipleRegistersResponse  ReferenceNumber=100 WordCount=4 |>>
    >>> target.read_holding_registers(address=100, count=4)
    Begin emission:
    Finished to send 1 packets.
    *
    Received 1 packets, got 1 answers, remaining 0 packets
    [1, 2, 3, 4]
    >>>
    
## 读取输入寄存器(ReadInputRegisters)
    >>> target.read_input_registers(address=100,count=10)
    Begin emission:
    Finished to send 1 packets.
    *
    Received 1 packets, got 1 answers, remaining 0 packets
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    >>>