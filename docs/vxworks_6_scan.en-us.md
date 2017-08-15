# Vxworks 6.x Scan

# Use Vxworks 6.x Scan module
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
    
    Exploits: 6 Scanners: 2 Creds: 13
    
    ICS Exploits:
        PLC: 6          ICS Switch: 0
        Software: 0
    
    isf >
    isf > search scanner
    scanners/profinet_dcp_scan
    scanners/vxworks_6_scan
    isf > use scanners/vxworks_6_scan
    isf (vxworks 6.x device scan) >

    
# set options
    isf (vxworks 6.x device scan) > show options
    
    Target options:
    
       Name       Current settings     Description
       ----       ----------------     -----------
       target                          string for hosts as nmap use it 'scanme.nmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
       port       17185                WdbRPC port, default is 17185/UDP
    
    
    Module options:
    
       Name        Current settings     Description
       ----        ----------------     -----------
       verbose     0                    Scapy verbose level, 0 to 2
       
    isf (vxworks 6.x device scan) > set target 192.168.102.0/24
    [+] {'target': '192.168.102.0/24'}

# scan
    isf (vxworks 6.x device scan) > run
    [*] Running module...
    [*] UDP Scan requires root privileges will using sudo to scan target
    Password:
    [+] Host: 192.168.102.89, port:17185 is open
    Target Type    VxWorks Version    CPU Type    CPU Model    Memory Size    IP Address
    -------------  -----------------  ----------  -----------  -------------  --------------
    VxWorks        6.6                86          PC PENTIUM4  126.4MB        192.168.102.89
    isf (vxworks 6.x device scan) >