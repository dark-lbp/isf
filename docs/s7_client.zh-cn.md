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