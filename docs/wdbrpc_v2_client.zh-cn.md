# WdbRPC V2 客户端

## 导入客户端
    root@kali:~/Desktop/temp/isf# python
    Python 2.7.9 (default, Mar  1 2015, 18:22:53)
    [GCC 4.9.2] on linux2
    Type "help", "copyright", "credits" or "license" for more information.
    >>> from icssploit.clients.wdb2_client import Wdb2Client

## 初始化客户端
    >>> target = Wdb2Client(name='Vxworks_6.6', ip="192.168.102.89")
    >>> target.connect()
    
## 读取目标内存信息
```python
>>> data = target.read_target_memory(address=0x100000, length=0x04)
[INFO    ][wdb2_client.read_target_memory] Dumping memory at 1048576 / 1048580
Begin emission:
Finished to send 1 packets.
*
Received 1 packets, got 1 answers, remaining 0 packets
>>> data.encode('hex')
'40c51800'
```


## 写入目标内存
```python
>>> target.write_target_memory(address=0x100000, data='\xff' * 4)
('start writing memory at 0x', '00100000')
Begin emission:
Finished to send 1 packets.
*
Received 1 packets, got 1 answers, remaining 0 packets
# check memory
>>> data = target.read_target_memory(address=0x100000, length=0x04)
[INFO    ][wdb2_client.read_target_memory] Dumping memory at 1048576 / 1048580
Begin emission:
Finished to send 1 packets.
*
Received 1 packets, got 1 answers, remaining 0 packets
>>> data.encode('hex')
'ffffffff'
>>>
```

## 获取目标设备信息
```python
>>> target.get_target_info()
Begin emission:
Finished to send 1 packets.
*
Received 1 packets, got 1 answers, remaining 0 packets
{'Unknow14': 1, 'Vx_Version': '6.6\x00', 'Unknow13': 8038597, 'Unknow12': 5010352, 'Unknow11': 0, 'Unknow10': 0, 'Unknow9': 1048576, 'Target_Type': 'VxWorks\x00', 'Unknow15': 0, 'CPU_Model': 'PC PENTIUM4\x00', 'Unknow7': 4321, 'Unknow6': 4096, 'Unknow5': 0,
 'Unknow4': 16777216, 'Unknow3': 0, 'CPU_Type': '86\x00', 'Unknow1': 80, 'Memory_Size': 132579328, 'Unknow8': 'host:vxWorks-6.6\x00', 'Unknow2': 86, 'compiler': 'gnu\x00'}

>>> target.target_info['Vx_Version']
'6.6\x00'
>>> target.target_info['CPU_Model']
'PC PENTIUM4\x00'
>>> target.target_info['CPU_Type']
'86\x00'
>>> target.target_info['Memory_Size']
132579328
>>> target.target_info['compiler']
'gnu\x00'
>>>

```