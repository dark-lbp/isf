# Load modules from extra folder

# isf command line parameter
```bash
➜  isf-public git:(master) ✗ isf.py --help
usage: isf.py [-h] [-e extra_package_path]

ICSSploit - ICS Exploitation Framework

optional arguments:
  -h, --help            show this help message and exit
  -e extra_package_path, --extra-package-path extra_package_path
                        Add extra packet(clients, modules, protocols) to isf.
```

# use -e to load extra modules
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

# We can use search cmd to find new modules
isf > search plc
exploits/plcs/siemens/s7_300_400_plc_control
exploits/plcs/vxworks/vxworks_rpc_dos
extra_exploits/plcs/siemens/s7_300_400_plc_control
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

# Extra folder requirement
This is the basic directory structure of extra folder.
Second and third level directory must named as below(e.g. extra_modules、extra_exploits), and each folder must have __init__.py file.

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

# How to import module from extra_clients or extra_protocols
isf will add all second level directory to python path(e.g. `extra_clients`, `extra_protocols`),
so we can import modules like below.
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