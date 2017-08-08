# 从额外的目录中读取modules

# isf 命令行参数
```bash
➜  isf-public git:(master) ✗ isf.py --help
usage: isf.py [-h] [-e extra_package_path]

ICSSploit - ICS Exploitation Framework

optional arguments:
  -h, --help            show this help message and exit
  -e extra_package_path, --extra-package-path extra_package_path
                        Add extra packet(clients, modules, protocols) to isf.
```

# 使用-e命令从额外的目录中读取modules
```bash
python isf.py -e "isf_extra_package/extra_isf_package"
  _____ _____  _____ _____ _____  _      ____ _____ _______
 |_   _/ ____|/ ____/ ____|  __ \| |    / __ \_   _|__   __|
   | || |    | (___| (___ | |__) | |   | |  | || |    | |
   | || |     \___ \\___ \|  ___/| |   | |  | || |    | |
  _| || |____ ____) |___) | |    | |___| |__| || |_   | |
 |_____\_____|_____/_____/|_|    |______\____/_____|  |_|


				ICS Exploitation Framework

Note     : ICSSPOLIT is fork from routersploit at
           https://github.com/reverse-shell/routersploit
Dev Team : wenzhe zhu(dark-lbp)
Version  : 0.1.0

Exploits: 22 Scanners: 0 Creds: 13

ICS Exploits:
    PLC: 14          ICS Switch: 4
    Software: 4

# 可以通过search 命令查看到新增的modules
isf > search plc
exploits/plcs/siemens/s7_300_400_plc_control
exploits/plcs/vxworks/vxworks_rpc_dos
extra_exploits/plcs/siemens/s7_300_400_plc_control
# 使用use 命令选择module
isf > use extra_exploits/plcs/siemens/s7_300_400_plc_control
isf (S7-300/400 PLC Control) > show options

Target options:

   Name       Current settings     Description
   ----       ----------------     -----------
   target                          Target address e.g. 192.168.1.1
   port       102                  Target Port


Module options:

   Name        Current settings     Description
   ----        ----------------     -----------
   slot        2                    CPU slot number.
   command     1                    Command 0:start plc, 1:stop plc.
```

# 额外目录的格式要求
 额外目录的格式要求如下所示，二三级目录的命名(例如:extra_modules、extra_exploits)必须按照以下规范，并且每个目录中都必须要有__init__.py文件

    extra_isf_package
    ├── __init__.py
    ├── extra_clients
    │   ├── __init__.py
    ├── extra_modules
    │   ├── __init__.py
    │   ├── extra_exploits
    │   │   ├── __init__.py
    │   │   ├── ics_software
    │   │   │   ├── __init__.py
    │   │   ├── ics_switchs
    │   │   │   ├── __init__.py
    │   │   │   ├── __init__.pyc
    │   │   └── plcs
    │   │       ├── __init__.py
    │   │       ├── siemens
    │   │       │   ├── __init__.py
    │   │       │   └──s7_300_400_plc_control.py
    │   │       └── vxworks
    │   │           ├── __init__.py
    │   │           └── vxworks_rpc_dos.py
    │   └── extra_scanners
    │       └── __init__.py
    └── extra_protocols
        └──  __init__.py

# 如何在额外的modules中调用extra_clients或extra_protocols
isf在读取额外目录时会将该目录加入到python path中，因此可以在额外脚本使用如下方式引用。
```python
from icssploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    mute,
    validators,
)
from extra_clients.s7_client import S7Client
from scapy.all import conf
import socket
import time

```