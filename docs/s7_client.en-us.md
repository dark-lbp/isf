# S7comm Client

## import client
    root@kali:~/Desktop/temp/isf# python
    Python 2.7.9 (default, Mar  1 2015, 18:22:53)
    [GCC 4.9.2] on linux2
    Type "help", "copyright", "credits" or "license" for more information.
    >>> from icssploit.clients.s7_client import S7Client

## Init Client
    >>> target = S7Client(name="test", ip="192.168.1.10", rack=0, slot=3)
    >>> target.connect()

## Get Target info
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

## Get Target CPU Status
```python
>>> target.get_target_status()
[INFO    ][s7_client.get_target_status] Target is in stop mode
```

## Start Target CPU
```python
# use `target.start_target(cold=True)` if you want doing cold restart. 
>>> target.start_target()
[INFO    ][s7_client.get_target_status] Target is in stop mode
[INFO    ][s7_client.start_target] Trying to start targets
[INFO    ][s7_client.get_target_status] Target is in run mode
>>> target.get_target_status()
[INFO    ][s7_client.get_target_status] Target is in run mode
```

## Stop Target CPU
```python
>>> target.stop_target()
[INFO    ][s7_client.get_target_status] Target is in run mode
[INFO    ][s7_client.stop_target] Trying to stop targets
[INFO    ][s7_client.get_target_status] Target is in stop mode
>>> target.get_target_status()
[INFO    ][s7_client.get_target_status] Target is in stop mode
```

## Check Target CPU Protect level
```python
# When target with no protect.
>>> target.check_privilege()
[INFO    ][s7_client._get_cpu_protect_level] CPU protect level is 1
[INFO    ][s7_client.check_privilege] You have full privilege with this targets

# When target with Read protect.
>>> target.check_privilege()
[INFO    ][s7_client._get_cpu_protect_level] CPU protect level is 2
[INFO    ][s7_client.check_privilege] You only have read privilege with this targets
```

## Auth session with password
```python
>>> target.check_privilege()
[INFO    ][s7_client._get_cpu_protect_level] CPU protect level is 2
[INFO    ][s7_client.check_privilege] You only have read privilege with this targets

# auth with wrong password
>>> target.auth("2")
[INFO    ][s7_client.auth] Start authenticate with password 2
[ERROR   ][s7_client.auth] Got error code: Incorrect password entered (0xd602)
[ERROR   ][s7_client.auth] Authentication failure
[INFO    ][s7_client._get_cpu_protect_level] CPU protect level is 2
[INFO    ][s7_client.check_privilege] You only have read privilege with this targets

# auth with correct password
>>> target.auth("1")
[INFO    ][s7_client.auth] Start authenticate with password 1
[INFO    ][s7_client.auth] Authentication succeed
[INFO    ][s7_client._get_cpu_protect_level] CPU protect level is 2
[INFO    ][s7_client.check_privilege] You have full privilege with this targets
>>> target.check_privilege()
[INFO    ][s7_client._get_cpu_protect_level] CPU protect level is 2
[INFO    ][s7_client.check_privilege] You have full privilege with this targets
```

# Upload block from target
```python
# Upload OB1 block from target
>>> block_data = target.upload_block_from_target(block_type='OB', block_num=1)
[INFO    ][s7_client.upload_block_from_target] Start upload OB1 from target
[INFO    ][s7_client.upload_block_from_target] Upload OB1 from target succeed
>>>>>> block_data
'pp\x01\x01\x02\x08\x00\x01\x00\x00\x00\xb4\x00......\x00\x00\x00'
```

# Download block to target
```python
# Download OB1 block to target (this block data is example, please use correct block data to downlaod)
>>> block_data = 'pp\x01\x01\x02\x08\x00\x01\x00\x00\x00\xb4\x00......\x00\x00\x00'
>>> target.download_block_to_target(block_data)
[INFO    ][s7_client.download_block_to_target] Start download OB1 to targets
[INFO    ][s7_client.download_block_to_target] Download OB1 to target succeed
```
# Read/Write var

## Read var
The parameter of `read_var` is a list of `read_item` items, each `read_item` contain four parameter `area_type`,`address`, `data_type`, `count`.

`area_type` parameter which block(area) you want to read,: 
supported block type(you can use both key or value as parameter):
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

`address`  parameter is the bit offset of block, it's define the start bit address you want to read.
There are two method You can set address parameter.
* BYTE.BIT(str type) - For example "1.0" mean start from second byte and first bit, it's equal to 9th bit(address start with 0). 
* BIT(int type) - directly use bit count, 8 mean start from 9th bit(address start with 0)。

`data_type` parameter is the data type you want to read.
Supported data type(you can use both key or value keyword as parameter):
For example 0x01 and "bit" is also mean bit type(case insensitive)
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

`count`parameter define how many data you want to read.

examples:
```python
# Read bit from M zone at address 1
>>> read_items = [("M", "1.0", "bit", 1)]
>>> target.read_var(read_items)
[1]

# Read 3 Bytes from DB1 at address 2
>>> read_items = [("DB1", "2.0", "byte", 3)]
>>> target.read_var(read_items)
[[10, 20, 30]]

# read 2 Word from M zone at address 10
>>> read_items = [("M", "10.0", "word", 2)]
>>> target.read_var(read_items)
[[1, 2]]

# Read 2 Real from M zone at address 20
>>> read_items = [("M", "20.0", "real", 2)]
>>> target.read_var(read_items)
[[0.10000000149011612, 1.100000023841858]]

# Read 2 Int from M zone at address 30
>>> read_items = [("M", "30.0", "int", 2)]
>>> target.read_var(read_items)
[[100, -100]]

# Read multi var from plc
>>> read_items = [("M", "1.0", "bit", 1), ("DB1", "2.0", "byte", 3), ("M", "10.0", "word", 2), ("M", "30.0", "int", 2)]
>>> target.read_var(read_items)
[1, [10, 20, 30], [1, 2], [100, -100]]
```

## Write var
The parameter of `write_var` is a list of `write_item` items, each `read_item` contain four parameter `area_type`,`address`, `data_type`, `data`.
`area_type`,`address`, `data_type` is same as `read_item`。

`data` parameter contain list of data your want to write to plc，data type should matching `data_type`.

examples:
```python
# Write bit to M zone at address 1
>>> write_items = [("M", "1.0", "bit", [1])]
# write_var will return a list contain each write var item's return code. 255(0xff) mean success.
>>> target.write_var(write_items)
[255]

# Write 3 Bytes to DB1  at address 2
>>> write_items = [("DB1", "2.0", "byte", [10, 20, 30])]
>>> target.write_var(write_items)
[255]

# Write 2 Word to M zone at address 10
>>> write_items = [("M", "10.0", "word", [1, 2])]
>>> target.write_var(write_items)
[255]

# Write 2 Real to M zone at address 20
>>> write_items = [("M", "20.0", "real", [0.1, 1.1])]
>>> target.write_var(write_items)
[255]

# Write 2 Int to M zone at address 30
>>> write_items = [("M", "30.0", "int", [100, -100])]
>>> target.write_var(write_items)
[255]

# Write multi var to plc
>>> write_items = [("M", "1.0", "bit", [1]), ("DB1", "2.0", "byte", [10, 20, 30]), ("M", "10.0", "word", [1, 2])]
# write_var will return a list contain each write var item's return code. 255(0xff) mean success.
>>> target.write_var(write_items)
[255, 255, 255]
```