# S7comm Client

## 导入客户端
    root@kali:~/Desktop/temp/isf# python
    Python 2.7.9 (default, Mar  1 2015, 18:22:53)
    [GCC 4.9.2] on linux2
    Type "help", "copyright", "credits" or "license" for more information.
    >>> from icssploit.clients.s7_client import S7Client

## 初始化客户端
    >>> target = S7Client(name="test", ip="192.168.1.10", rack=0, slot=3)
    >>> target.connect()
    
## 获取目标CPU运行状态
```python
>>> target.get_target_status()
[INFO    ][s7_client.get_target_status] Target is in stop mode
```

## 获取目标PLC基础信息
```python
>>> order_code, version, module_type_name, as_name, module_name, serial_number = target.get_target_info()
>>> order_code
'6ES7 412-2EK06-0AB0'
>>> version
'V 6.0.3'
>>> module_type_name
'CPU 412-2 PN/DP'
>>> as_name
'S7-400 station_1'
>>> module_name
'PLC_1'
>>> serial_number
'SVPF126xxxx'
```

## 启动目标CPU
```python
# 如果想要使用冷启动的话，可以使用 `target.start_target(cold=True)`参数 
>>> target.start_target()
[INFO    ][s7_client.get_target_status] Target is in stop mode
[INFO    ][s7_client.start_target] Trying to start targets
[INFO    ][s7_client.get_target_status] Target is in run mode
>>> target.get_target_status()
[INFO    ][s7_client.get_target_status] Target is in run mode
```

## 停止目标CPU
```python
>>> target.stop_target()
[INFO    ][s7_client.get_target_status] Target is in run mode
[INFO    ][s7_client.stop_target] Trying to stop targets
[INFO    ][s7_client.get_target_status] Target is in stop mode
>>> target.get_target_status()
[INFO    ][s7_client.get_target_status] Target is in stop mode
```

## 查案目标CPU保护级别
```python
# 目标CPU没有启用读写保护时
>>> target.check_privilege()
[INFO    ][s7_client._get_cpu_protect_level] CPU protect level is 1
[INFO    ][s7_client.check_privilege] You have full privilege with this targets

# 目标CPU启用了写保护时
>>> target.check_privilege()
[INFO    ][s7_client._get_cpu_protect_level] CPU protect level is 2
[INFO    ][s7_client.check_privilege] You only have read privilege with this targets
```

## 使用密码对当前会话进行认证(获取目标PLC读写权限)
```python
>>> target.check_privilege()
[INFO    ][s7_client._get_cpu_protect_level] CPU protect level is 2
[INFO    ][s7_client.check_privilege] You only have read privilege with this targets

# 使用错误密码进行验证的情况
>>> target.auth("2")
[INFO    ][s7_client.auth] Start authenticate with password 2
[ERROR   ][s7_client.auth] Got error code: Incorrect password entered (0xd602)
[ERROR   ][s7_client.auth] Authentication failure
[INFO    ][s7_client._get_cpu_protect_level] CPU protect level is 2
[INFO    ][s7_client.check_privilege] You only have read privilege with this targets

# 使用正确的密码进行验证的情况
>>> target.auth("1")
[INFO    ][s7_client.auth] Start authenticate with password 1
[INFO    ][s7_client.auth] Authentication succeed
[INFO    ][s7_client._get_cpu_protect_level] CPU protect level is 2
[INFO    ][s7_client.check_privilege] You have full privilege with this targets
>>> target.check_privilege()
[INFO    ][s7_client._get_cpu_protect_level] CPU protect level is 2
[INFO    ][s7_client.check_privilege] You have full privilege with this targets
```

# 从PLC中上载Block
```python
# 从PLC中上载OB1块
>>> block_data = target.upload_block_from_target(block_type='OB', block_num=1)
[INFO    ][s7_client.upload_block_from_target] Start upload OB1 from target
[INFO    ][s7_client.upload_block_from_target] Upload OB1 from target succeed
>>>>>> block_data
'pp\x01\x01\x02\x08\x00\x01\x00\x00\x00\xb4\x00......\x00\x00\x00'
```

# 下载Block数据到PLC
```python
# 下载OB1块的数据到目标PLC(这个例子中的区块数据为示例数据，请使用正确的数据进行下载)
>>> block_data = 'pp\x01\x01\x02\x08\x00\x01\x00\x00\x00\xb4\x00......\x00\x00\x00'
>>> target.download_block_to_target(block_data)
[INFO    ][s7_client.download_block_to_target] Start download OB1 to targets
[INFO    ][s7_client.download_block_to_target] Download OB1 to target succeed
```

# 读写PLC中的数据

## 读取PLC中的数据
`read_var`指令的参数是包含了一组`read_item`的列表数据。每个`read_item` 共有四个参数`area_type`,`address`, `data_type`, `count`。

`area_type`参数定义了从哪个区块进行数据读取，目前支持的区块类型如下，可以任意选择key或者value作为参数: 
```python
{
'P': 0x80,      # I/O
'I': 0x81,      # Memory area of inputs
'Q': 0x82,      # Memory area of outputs
'M': 0x83,      # Memory area of bit memory
'DB': 0x84,     # Data block
'L': 0x86,      # Local data
'V': 0x87       # Previous local data
}
```

`address`参数定义了bit偏移量，代表了从指定区块的哪个地址开始读取数据, 目前支持两种赋值方法。
* 字节加比特位赋值(str类型) - 如"1.0"代表的是第二个字节、第0个比特。（西门子的设备地址从0开始计数）
* 比特数值(int类型) - 直接使用比特作为单位进行赋值，例如8代表的就是第9个比特。（西门子的设备地址从0开始计数）

`data_type`参数定义了读取的数据类型，目前支持的数据类型如下。参数可使用key或者value中的关键字,使用关键字时不区分大小写。
例如0x01及bit都代表了BIT类型。
```python
{
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
```

`count`参数定义了需要读取数据的格式。


下面是一些例子
```python
# 从M区偏移量1个字节处中读取1个bit
>>> read_items = [("M", "1.0", "bit", 1)]
>>> target.read_var(read_items)
[1]

# 从DB1偏移量两个字节处读取3个字节的数据 
>>> read_items = [("DB1", "2.0", "byte", 3)]
>>> target.read_var(read_items)
[[10, 20, 30]]

# 从M区偏移量10个字节处中读取2个Word
>>> read_items = [("M", "10.0", "word", 2)]
>>> target.read_var(read_items)
[[1, 2]]

# 从M区偏移量20个字节处中读取2个real
>>> read_items = [("M", "20.0", "real", 2)]
>>> target.read_var(read_items)
[[0.10000000149011612, 1.100000023841858]]

# 从M区偏移量30个字节处中读取2个int
>>> read_items = [("M", "30.0", "int", 2)]
>>> target.read_var(read_items)
[[100, -100]]

# 从PLC中读取多个不同类型的数据
>>> read_items = [("M", "1.0", "bit", 1), ("DB1", "2.0", "byte", 3), ("M", "10.0", "word", 2), ("M", "30.0", "int", 2)]
>>> target.read_var(read_items)
[1, [10, 20, 30], [1, 2], [100, -100]]
```

## 将输入写入PLC
`write_var`指令的参数是包含了一组`write_item`的列表数据。每个`write_item` 共有四个参数`area_type`,`address`, `data_type`, `data`。
其中`area_type`,`address`, `data_type`的参数与`read_item`相同。

`data`参数代表的是需要写入的数据列表，写入的数据内容应与定义的`data_type`类型相符合。


下面是一些例子
```python
# 将1个bit数据写入M区中偏移量为1个字节的位置
>>> write_items = [("M", "1.0", "bit", [1])]
# write_var 将会返回一个包含了每个write_var item所对应返回码的列表. 255(0xff) 代表写入成功.
>>> target.write_var(write_items)
[255]

# 将3个byte数据写入DB1中偏移量为2个字节的位置
>>> write_items = [("DB1", "2.0", "byte", [10, 20, 30])]
>>> target.write_var(write_items)
[255]

# 将2个word数据写入M区中偏移量为10个字节的位置
>>> write_items = [("M", "10.0", "word", [1, 2])]
>>> target.write_var(write_items)
[255]

# 将2个real数据写入M区中偏移量为20个字节的位置
>>> write_items = [("M", "20.0", "real", [0.1, 1.1])]
>>> target.write_var(write_items)
[255]

# 将2个Int数据写入M区中偏移量为20个字节的位置
>>> write_items = [("M", "30.0", "int", [100, -100])]
>>> target.write_var(write_items)
[255]

# 写入多个不同类型的数据
>>> write_items = [("M", "1.0", "bit", [1]), ("DB1", "2.0", "byte", [10, 20, 30]), ("M", "10.0", "word", [1, 2])]
# write_var 将会返回一个包含了每个write_var item所对应返回码的列表. 255(0xff) 代表写入成功.
>>> target.write_var(write_items)
[255, 255, 255]
```