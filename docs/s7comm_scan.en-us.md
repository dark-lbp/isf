# S7comm Scan

# Use S7comm Scan module
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
    
    Exploits: 6 Scanners: 3 Creds: 13
    
    ICS Exploits:
        PLC: 6          ICS Switch: 0
        Software: 0
    
    isf >
    isf > search scanner
    scanners/profinet_dcp_scan
    scanners/s7comm_scan
    scanners/vxworks_6_scan
    isf > use scanners/s7comm_scan
    isf (S7comm PLC Scan) >

    
# set options
    isf (S7comm PLC Scan) > show options

    Target options:
    
       Name       Current settings     Description
       ----       ----------------     -----------
       target                          string for hosts as nmap use it 'scanme.nmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
       port       102                  S7comm port, default is 102/TCP
    
    
    Module options:
    
       Name         Current settings     Description
       ----         ----------------     -----------
       min_slot     2                    Minimum PLC Slot number for scan, default is 2, set to 4 if you want start with slot 4
       min_rack     0                    Minimum PLC Rack number for scan, default is 0, set to 1 if you want start with rack 1
       max_rack     0                    Maximum PLC Rack number for scan, default is 0, set to 1 if you want scan up to rack 1
       max_slot     5                    Maximum PLC Slot number for scan, default is 5, set to 10 if you want scan up to slot 5
       verbose      0                    Scapy verbose level, 0 to 2
       
    isf (S7comm PLC Scan) > set target 192.168.1.0/24
    [+] {'target': '192.168.1.0/24'}

# scan
    isf (S7comm PLC Scan) > run
    [*] Running module...
    [+] Host: 192.168.1.10, port:102 is open
    [*] Tring to scan 192.168.1.10 with Rack0/Slot2
    [ERROR   ][s7_client.send_receive_packet] [Errno 54] Connection reset by peer
    [ERROR   ][s7_client.send_receive_s7_packet] [Errno 54] Connection reset by peer
    [ERROR   ][s7_client.send_receive_s7_packet] [Errno 54] Connection reset by peer
    [ERROR   ][s7_client.get_target_info] Can't get order code and version from target
    [*] Tring to scan 192.168.1.10 with Rack0/Slot3
    [*] Tring to scan 192.168.1.10 with Rack0/Slot4
    [ERROR   ][s7_client.send_receive_packet] [Errno 54] Connection reset by peer
    [ERROR   ][s7_client.send_receive_s7_packet] [Errno 54] Connection reset by peer
    [ERROR   ][s7_client.send_receive_s7_packet] [Errno 54] Connection reset by peer
    [ERROR   ][s7_client.get_target_info] Can't get order code and version from target
    [*] Tring to scan 192.168.1.10 with Rack0/Slot5
    [ERROR   ][s7_client.send_receive_packet] [Errno 54] Connection reset by peer
    [ERROR   ][s7_client.send_receive_s7_packet] [Errno 54] Connection reset by peer
    [ERROR   ][s7_client.send_receive_s7_packet] [Errno 54] Connection reset by peer
    [ERROR   ][s7_client.get_target_info] Can't get order code and version from target
    [+] Find 1 targets
    Order Code           Module Type Name    Firmware Version    Module Name    Serial Number    Rack/Slot    IP Address
    -------------------  ------------------  ------------------  -------------  ---------------  -----------  --------------
    6ES7 412-2EK06-0AB0  CPU 412-2 PN/DP     V 6.0.3                            SVPF126xxxx      0/3          192.168.1.10
