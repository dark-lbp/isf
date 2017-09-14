from icssploit.test import icssploitTestCase
from icssploit.protocols.s7comm import *


class S7commTests(icssploitTestCase):
    def setUp(self):
        super(S7commTests, self).setUp()

    def test_cotp_cr(self):
        data = '0300001611e00000000100c0010ac102' \
               '0100c2020200'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPCR), True)
        self.assertEqual(packet[TPKT].Length, 22)

    def test_cotp_cc(self):
        data = '0300001611d00001000200c0010ac102' \
               '0100c2020200'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPCC), True)
        self.assertEqual(packet[TPKT].Length, 22)

    def test_setup_comm_req(self):
        data = '0300001902f080320100000800000800' \
               '00f0000001000101e0'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7SetConParameter), True)

    def test_setup_comm_rsp(self):
        data = '0300001b02f08032030000080000080' \
               '0000000f0000001000100f0'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7SetConParameter), True)

    def test_read_szl_req(self):
        data = '0300002102f08032070000090000080' \
               '0080001120411440100ff0900040011' \
               '0000'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7ReadSZLParameterReq), True)
        self.assertEqual(packet.haslayer(S7ReadSZLDataReq), True)
        self.assertEqual(packet[S7ReadSZLDataReq].SZLId, 0x11)

    def test_read_szl_rsp(self):
        data = '0300009902f080320700000900000c00' \
               '7c000112081284010100000000ff0900' \
               '7800110000001c000400013645533720' \
               '3331352d32454831342d304142302000' \
               'c000060001000636455337203331352d' \
               '32454831342d304142302000c0000600' \
               '01000720202020202020202020202020' \
               '2020202020202000c05603020a008142' \
               '6f6f74204c6f61646572202020202020' \
               '202020000041250b0c'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7ReadSZLParameterRsp), True)
        self.assertEqual(packet.haslayer(S7ReadSZLDataRsp), True)
        self.assertEqual(packet.haslayer(S7ReadSZLDataTreeRsp), True)

    def test_start_upload_req(self):
        data = '0300002302f080320100000d00001200' \
               '001d00000000000000095f3038303030' \
               '303141'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7RequestUploadBlockParameterReq), True)
        self.assertEqual(packet[S7RequestUploadBlockParameterReq].Filename, '_0800001A')

    def test_start_upload_rsp(self):
        data = '0300002302f080320300000d00001000' \
               '0000001d000100000000070730303030' \
               '323132'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7RequestUploadBlockParameterRsp), True)
        self.assertEqual(packet[S7RequestUploadBlockParameterRsp].UploadId, 0x7)
        self.assertEqual(packet[S7RequestUploadBlockParameterRsp].BlockLength, '0000212')

    def test_upload_req(self):
        data = '0300001902f080320100000e00000800' \
               '001e00000000000007'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7UploadBlockParameterReq), True)
        self.assertEqual(packet[S7UploadBlockParameterReq].UploadId, 0x7)

    def test_upload_rsp(self):
        data = '030000ed02f080320300000e00000200' \
               'd800001e0000d400fb70700000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '0001001db20000000000000000'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7UploadBlockParameterRsp), True)
        self.assertEqual(packet.haslayer(S7UploadBlockDataRsp), True)
        self.assertEqual(packet[S7UploadBlockDataRsp].DataLength, 0xd4)

    def test_upload_end_req(self):
        data = '0300001902f080320100000f00000800' \
               '001f00000000000007'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7UploadBlockEndParameterReq), True)
        self.assertEqual(packet[S7UploadBlockEndParameterReq].UploadID, 0x07)

    def test_upload_end_rsp(self):
        data = '0300001402f080320300000f00000100' \
               '0000001f'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7UploadBlockEndParameterRsp), True)
        self.assertEqual(packet[S7UploadBlockEndParameterRsp].Function, 0x1f)

    def test_request_download_req(self):
        data = '0300003102f080320100001000002000' \
               '001a00000000000000095f3038303030' \
               '3031500d313030303231323030303130' \
               '32'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7RequestDownloadParameterReq), True)
        self.assertEqual(packet[S7RequestDownloadParameterReq].Function, 0x1a)
        self.assertEqual(packet[S7RequestDownloadParameterReq].FileNameLength, 0x09)
        self.assertEqual(packet[S7RequestDownloadParameterReq].Filename, '_0800001P')
        self.assertEqual(packet[S7RequestDownloadParameterReq].LoadMemLength, '000212')
        self.assertEqual(packet[S7RequestDownloadParameterReq].MC7Length, '000102')

    def test_request_download_rsp(self):
        data = '0300001402f080320300001000000100' \
               '0000001a'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7RequestDownloadParameterRsp), True)
        self.assertEqual(packet[S7RequestDownloadParameterRsp].Function, 0x1a)

    def test_download_req(self):
        data = '0300002302f080320100000d00001200' \
               '001b00000000000000095f3038303030' \
               '303150'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7DownloadParameterReq), True)
        self.assertEqual(packet[S7DownloadParameterReq].Function, 0x1b)
        self.assertEqual(packet[S7DownloadParameterReq].FileNameLength, 0x09)
        self.assertEqual(packet[S7DownloadParameterReq].Filename, '_0800001P')

    def test_download_rsp(self):
        data = '030000ed02f080320300000d00000200' \
               'd800001b0000d400fb095f3038707000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000000000' \
               '00000000000000000000000000'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7DownloadParameterRsp), True)
        self.assertEqual(packet[S7DownloadParameterRsp].Function, 0x1b)
        self.assertEqual(packet.haslayer(S7DownloadDataRsp), True)
        self.assertEqual(packet[S7DownloadDataRsp].DataLength, 0xd4)

    def test_download_end_req(self):
        data = '0300002302f080320100000f00001200' \
               '001c00840400000000095f3038303030' \
               '303150'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7DownloadEndParameterReq), True)
        self.assertEqual(packet[S7DownloadEndParameterReq].ErrorCode, 0x8404)
        self.assertEqual(packet[S7DownloadEndParameterReq].FileNameLength, 0x09)
        self.assertEqual(packet[S7DownloadEndParameterReq].Filename, '_0800001P')

    def test_download_end_rsp(self):
        data = '0300001402f080320300000f00000100' \
               '0000001c'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7DownloadEndParameterRsp), True)
        self.assertEqual(packet[S7DownloadEndParameterRsp].Function, 0x1c)

    def test_request_download_file_req(self):
        data = '0300002302f08032010000bf05001200' \
               '001a0000000000000009505f42455359' \
               '5f4247'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7RequestDownloadParameterReq), True)
        self.assertEqual(packet[S7RequestDownloadParameterReq].Function, 0x1a)
        self.assertEqual(packet[S7RequestDownloadParameterReq].Filename, "P_BESY_BG")

    def test_request_download_file_rsp(self):
        data = '0300001402f08032030000bf05000100' \
               '0000001a'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7RequestDownloadParameterRsp), True)

    def test_pi_service_req(self):
        data = '0300002b02f080320100001100001a00' \
               '0028000100000000fd000a0100303830' \
               '3030303150055f494e5345'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7PIServiceParameterReq), True)
        self.assertEqual(packet.haslayer(S7PIServiceParameterBlock), True)
        self.assertEqual(packet[S7PIServiceParameterBlock].NumberOfBlocks, 1)
        self.assertEqual(packet[S7PIServiceParameterBlock].FileNames, ['\x000800001P'])

    def test_pi_service_rsp(self):
        data = '0300001502f080320300001100000200' \
               '00d2092802'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7PIServiceParameterRsp), True)
        self.assertEqual(packet[S7PIServiceParameterRsp].Function, 0x28)

    def test_plc_stop_req(self):
        data = '0300002102f080320100002000001000' \
               '0029000000000009505f50524f475241' \
               '4d'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7StopCpuParameterReq), True)
        self.assertEqual(packet[S7StopCpuParameterReq].Function, 0x29)
        self.assertEqual(packet[S7StopCpuParameterReq].PI, 'P_PROGRAM')

    def test_plc_stop_rsp_1(self):
        data = '0300001402f080320300002000000100' \
               '00000029'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7StopCpuParameterRsp), True)
        self.assertEqual(packet[S7StopCpuParameterRsp].Function, 0x29)
        self.assertEqual(packet[S7StopCpuParameterRsp].ParameterData, None)

    def test_plc_stop_rsp_2(self):
        data = '0300001502f080320300002300000200' \
               '0084022907'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7StopCpuParameterRsp), True)
        self.assertEqual(packet[S7StopCpuParameterRsp].Function, 0x29)
        self.assertEqual(packet[S7StopCpuParameterRsp].ParameterData, 0x07)

    def test_plc_pass_req(self):
        data = '0300002502f080320700000d00000800' \
               '0c0001120411450100ff090008646702' \
               '0662731706'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7PasswordParameterReq), True)
        self.assertEqual(packet[S7PasswordParameterReq].FunctionGroup, 0x05)
        self.assertEqual(packet[S7PasswordParameterReq].SubFunction, 0x01)
        self.assertEqual(packet.haslayer(S7PasswordDataReq), True)
        self.assertEqual(packet[S7PasswordDataReq].TransportSize, 0x09)
        self.assertEqual(packet[S7PasswordDataReq].Data, '\x64\x67\x02\x06\x62\x73\x17\x06')

    def test_plc_pass_rsp(self):
        data = '0300002102f080320700000d00000c00' \
               '0400011208128501010000d6020a0000' \
               '00'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7PasswordParameterRsp), True)

    def test_clean_password_req(self):
        data = '0300001d02f080320700001b00000800' \
               '0400011204114502000a000000'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7CleanSessionParameterReq), True)
        self.assertEqual(packet[S7CleanSessionParameterReq].FunctionGroup, 0x05)
        self.assertEqual(packet[S7CleanSessionParameterReq].SubFunction, 0x02)
        self.assertEqual(packet.haslayer(S7CleanSessionDataReq), True)
        self.assertEqual(packet[S7CleanSessionDataReq].ReturnCode, 0x0a)

    def test_clean_password_rsp(self):
        data = '0300002102f080320700001b00000c00' \
               '0400011208128502010000d6040a0000' \
               '00'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7CleanSessionParameterRsp), True)
        self.assertEqual(packet[S7CleanSessionParameterRsp].FunctionGroup, 0x05)
        self.assertEqual(packet[S7CleanSessionParameterRsp].SubFunction, 0x02)
        self.assertEqual(packet[S7CleanSessionParameterRsp].ErrorCode, 0xd604)
        self.assertEqual(packet.haslayer(S7CleanSessionDataRsp), True)
        self.assertEqual(packet[S7CleanSessionDataRsp].ReturnCode, 0x0a)

    def test_read_var_db_req(self):
        data = '0300001f02f080320100001c00000e00' \
               '000401120a10020001000184000000'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7ReadVarItemsReq), True)
        self.assertEqual(packet[S7ReadVarItemsReq].AREAType, 0x84)
        self.assertEqual(packet[S7ReadVarItemsReq].Address, 0x00)

    def test_read_var_db_rsp(self):
        data = '0300001902f080320300001c00000200' \
               '04000004010a000000'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7ReadVarDataItemsRsp), True)
        self.assertEqual(packet[S7ReadVarDataItemsRsp].ReturnCode, 0x0a)

    def test_read_var_m_req(self):
        data = '0300001f02f080320100001d00000e00' \
               '000401120a10020001000083000000'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7ReadVarItemsReq), True)
        self.assertEqual(packet[S7ReadVarItemsReq].AREAType, 0x83)
        self.assertEqual(packet[S7ReadVarItemsReq].GetLength, 0x01)
        self.assertEqual(packet[S7ReadVarItemsReq].Address, 0x00)

    def test_read_var_m_rsp(self):
        data = '0300001a02f080320300001d00000200' \
               '0500000401ff04000800'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7ReadVarDataItemsRsp), True)
        self.assertEqual(packet[S7ReadVarDataItemsRsp].ReturnCode, 0xff)
        self.assertEqual(packet[S7ReadVarDataItemsRsp].DataLength, 0x08)
        self.assertEqual(packet[S7ReadVarDataItemsRsp].Data, '\x00')

    def test_write_var_m_req(self):
        data = '0300002402f080320100000e00000e00' \
               '050501120a1002000100008300000000' \
               '04000800'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7WriteVarParameterReq), True)
        self.assertEqual(packet.haslayer(S7WriteVarItemsReq), True)
        self.assertEqual(packet.haslayer(S7WriteVarDataReq), True)

    def test_write_var_m_rsp(self):
        data = '0300001602f080320300001200000200' \
               '0100000501ff'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7WriteVarParameterRsp), True)

    def test_write_multi_var_req(self):
        data = '030000ab02f080320100001d00003e00' \
               '5c0505120a1002000800008300000012' \
               '0a10020010000284000000120a100200' \
               '10000384000000120a10020010000484' \
               '000000120a1002001000058400000000' \
               '04004001010101010101010004008002' \
               '02020202020202020202020202020200' \
               '04008003030303030303030303030303' \
               '03030300040080040404040404040404' \
               '04040404040404000400800505050505' \
               '0505050505050505050505'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7WriteVarParameterReq), True)
        self.assertEqual(packet[S7WriteVarDataReq].Items[0].DataLength, 0x40)
        self.assertEqual(len(packet[S7WriteVarDataReq].Items), 0x05)

    def test_write_multi_var_rsp(self):
        data = '0300001a02f080320300002000000200' \
               '0500000505ff0a0a0a0a'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7WriteVarParameterRsp), True)
        self.assertEqual(packet[S7WriteVarDataRsp].Items[0].ReturnCode, 0xff)
        self.assertEqual(packet[S7WriteVarDataRsp].Items[1].ReturnCode, 0x0a)

    def test_write_multi_var_with_padding_req(self):
        data = '030000ab02f080320100001c00003e00' \
               '5c0505120a1002000700008300000012' \
               '0a10020010000284000000120a100200' \
               '10000384000000120a10020010000484' \
               '000000120a1002001000058400000000' \
               '04003801010101010101010004008002' \
               '02020202020202020202020202020200' \
               '04008003030303030303030303030303' \
               '03030300040080040404040404040404' \
               '04040404040404000400800505050505' \
               '0505050505050505050505'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7WriteVarParameterReq), True)
        self.assertEqual(packet[S7WriteVarDataReq].Items[0].DataLength, 0x38)
        self.assertEqual(len(packet[S7WriteVarDataReq].Items), 0x05)

    def test_write_multi_var_with_padding_rsp(self):
        data = '0300001a02f080320300001c00000200' \
               '0500000505ff0a0a0a0a'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7WriteVarParameterRsp), True)
        self.assertEqual(packet[S7WriteVarDataRsp].Items[0].ReturnCode, 0xff)
        self.assertEqual(packet[S7WriteVarDataRsp].Items[1].ReturnCode, 0x0a)

    def test_list_block_req(self):
        data = '0300001d02f080320700001f00000800' \
               '0400011204114301000a000000'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7ListBlockParameterReq), True)
        self.assertEqual(packet.haslayer(S7ListBlockDataReq), True)

    def test_list_block_rsp(self):
        data = '0300003d02f080320700000900000c00' \
               '20000112081283010100000000ff0900' \
               '1c303800003045000030430000304100' \
               '00304200023044005a3046001e'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7ListBlockParameterRsp), True)
        self.assertEqual(packet.haslayer(S7ListBlockDataRsp), True)

    def test_list_block_of_type_req(self):
        data = '0300001f02f080320700000b00000800' \
               '060001120411430200ff0900023046'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7ListBlockOfTypeParameterReq), True)
        self.assertEqual(packet.haslayer(S7ListBlockOfTypeDataReq), True)
        self.assertEqual(packet[S7ListBlockOfTypeDataReq].BlockType, '0F')

    def test_list_block_of_type_rsp(self):
        data = '0300009902f080320700000b00000c00' \
               '7c000112081283020100000000ff0900' \
               '78000042010001420100024201000342' \
               '01000442010005420100084201000942' \
               '01000c4201000d4201000e4201000f42' \
               '01001042010013420100144201001542' \
               '010016420100174201001f4201002042' \
               '01002142010022420100234201002442' \
               '01002542010034420100354201003642' \
               '010051420100684201'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7ListBlockOfTypeParameterRsp), True)
        self.assertEqual(packet.haslayer(S7ListBlockOfTypeDataRsp), True)
        self.assertEqual(packet.haslayer(S7ListBlockOfTypeDataBlocksRsp), True)
        self.assertEqual(len(packet[S7ListBlockOfTypeDataRsp].Blocks), 0x1e)
        self.assertEqual(packet[S7ListBlockOfTypeDataRsp].Blocks[0].BlockNum, 0x0)
        self.assertEqual(packet[S7ListBlockOfTypeDataRsp].Blocks[0].BlockFlag, 0x42)
        self.assertEqual(packet[S7ListBlockOfTypeDataRsp].Blocks[0].BlockLang, 0x01)

    def test_get_block_info_req(self):
        data = '0300002502f080320700000c00000800' \
               '0c0001120411430300ff090008304630' \
               '3030303141'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7GetBlockInfoParameterReq), True)
        self.assertEqual(packet.haslayer(S7GetBlockInfoDataReq), True)
        self.assertEqual(packet[S7GetBlockInfoDataReq].BlockType, '0F')
        self.assertEqual(packet[S7GetBlockInfoDataReq].BlockNum, '00001')
        self.assertEqual(packet[S7GetBlockInfoDataReq].DstFileSystem, 'A')

    def test_get_block_info_rsp(self):
        data = '0300006f02f080320700000c00000c00' \
               '52000112081283030100000000ff0900' \
               '4e0100004a420070700109010f000100' \
               '0000620000000001cb69d811fc01cb69' \
               'd811fc001400040000000253494d4154' \
               '4943004945435f544300004354440000' \
               '000000100000000000000000000000'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7GetBlockInfoParameterRsp), True)
        self.assertEqual(packet.haslayer(S7GetBlockInfoDataRsp), True)
        self.assertEqual(packet.haslayer(S7GetBlockInfoDataInfoRsp), True)

    def test_delete_block_req(self):
        data = '0300002b02f080320100000900001a00' \
               '0028000000000000fd000a0100303830' \
               '3030303142055f44454c45'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)

    def test_message_service_req(self):
        data = '0300002702f080320700000500000800' \
               '0e0001120411440200ff09000a010055' \
               '53455231000000'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7MessageServiceParameterReq), True)
        self.assertEqual(packet.haslayer(S7MessageServiceDataReq), True)
        self.assertEqual(packet[S7MessageServiceDataReq].SubscribedEvents, 1)

    def test_message_service_rsp(self):
        data = '0300002302f080320700000500000c00' \
               '0600011208128402ff00000000ff0900' \
               '020200'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7MessageServiceParameterRsp), True)
        self.assertEqual(packet.haslayer(S7MessageServiceDataRsp), True)

    def test_force_req(self):
        data = '0300003d02f08032070000b400000c00' \
               '20000112081241100000000000ff0900' \
               '1c001400040000000000010000000100' \
               '01000100010001000000000000'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7ForceParameterReq), True)
        self.assertEqual(packet.haslayer(S7ForceDataReq), True)

    def test_force_rsp(self):
        data = '0300002902f080320700006101000c00' \
               '0c000112081281101500000000ff0900' \
               '080004000001000001'.decode('hex')
        packet = TPKT(data)
        packet.show()
        self.assertEqual(packet.haslayer(TPKT), True)
        self.assertEqual(packet.haslayer(COTPDT), True)
        self.assertEqual(packet.haslayer(S7Header), True)
        self.assertEqual(packet.haslayer(S7ForceParameterRsp), True)
        self.assertEqual(packet.haslayer(S7ForceDataRsp), True)

    def test_s7_write_var_data_req(self):
        packet = S7WriteVarDataReq(Items=[S7WriteVarDataItemsReq(TransportSize=0x03, Data='\x01'),
                                          S7WriteVarDataItemsReq(TransportSize=0x04, Data='\x0a\x14\x1e')]
                                   )
        packet.show()
        data = str(packet).encode('hex')
        self.assertEqual(str(packet).encode('hex'), "000300010100000400180a141e")