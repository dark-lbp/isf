# 框架介绍
ISF(Industrial Exploitation Framework)，是一款基于python编写的类msf工控漏洞利用框架。该框架基于开源项目[routersploit](https://github.com/reverse-shell/routersploit)修改而来。

# 当前脚本工具

## 工控协议客户端

| Name               | Path                                   | Description            |
| -------------------| ---------------------------------------|:----------------------:|  
| modbus_tcp_client  | icssploit/clients/modbus_tcp_client.py | Modbus-TCP客户端工具    |




## 漏洞利用脚本
| Name                    | Path                                                              | Description                             |
| ------------------------| ------------------------------------------------------------------|:---------------------------------------:|  
| s7_300_400_plc_control  | icssploit/modules/exploits/plcs/siemens/s7_300_400_plc_control.py | S7-300/400 PLC 启停脚本                  |
| vxworks_rpc_dos  | icssploit/modules/exploits/plcs/vxworks/vxworks_rpc_dos.py               | Vxworks RPC 远程拒绝服务（CVE-2015-7599） |