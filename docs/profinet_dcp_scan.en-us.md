# Profinet dcp Scan

# Use Profinet dcp Scan module
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
    
    Exploits: 5 Scanners: 3 Creds: 13
    
    ICS Exploits:
        PLC: 5          ICS Switch: 0
        Software: 0
    
    isf >
    isf > search scanner
    scanners/profinet_dcp_scan
    scanners/s7comm_scan
    scanners/vxworks_6_scan
    isf > use scanners/profinet_dcp_scan
    isf (profinet device scan) >

    
# set options
    isf (profinet device scan) > show options
    Target options:
    
       Name       Current settings     Description
       ----       ----------------     -----------
       target                          Target IP address.
    
    
    Module options:
    
       Name        Current settings     Description
       ----        ----------------     -----------
       nic         eth0                 Interface Name e.g eth0, en0
       timeout     5                    Timeout for response
       verbose     0                    Scapy verbose level, 0 to 2
    
    # Because profient dcp is a ethernet protocol, the only thing we need set is interface.
    # Use set nic eth0 to define which interface we want to send and recive profinet dpc packet.
    isf (profinet device scan) > set nic eth0
    [+] {'nic': 'eth0'}

# scan
    isf (profinet device scan) > run
    [*] Running module...
    Device Name    Device Type    MAC Address        IP Address      Netmask        GateWay
    -------------  -------------  -----------------  --------------  -------------  --------------
    plcxb1d0ed     S7-400         00:1b:1b:a7:xx:xx  192.168.1.10  255.255.255.0  192.168.1.10
    isf (profinet device scan) >