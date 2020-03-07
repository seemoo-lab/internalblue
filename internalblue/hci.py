#!/usr/bin/env python2

# hci.py
#
# The hci.py file contains classes and functions to parse and
# craft HCI packets.
#
# HCI code was partially taken from https://github.com/joekickass/python-btsnoop
#
# Copyright (c) 2018 Dennis Mantz. (MIT License)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
# - The Software is provided "as is", without warranty of any kind, express or
#   implied, including but not limited to the warranties of merchantability,
#   fitness for a particular purpose and noninfringement. In no event shall the
#   authors or copyright holders be liable for any claim, damages or other
#   liability, whether in an action of contract, tort or otherwise, arising from,
#   out of or in connection with the Software or the use or other dealings in the
#   Software.

from __future__ import absolute_import
from builtins import hex
from builtins import range
from builtins import object

from internalblue.utils.pwnlib_wrapper import (
    p8,
    u16,
    p16,
    unbits,
    bits_str,
    u8,
    bits,
    p32,
    u32,
)
from internalblue.utils.pwnlib_wrapper import log
from pwnlib.util.packing import flat

HCI_UART_TYPE_CLASS = {}


class HCI(object):
    data: bytes
    """
    HCI Packet types for UART Transport layer
    Core specification 4.1 [vol 4] Part A (Section 2) - Protocol
    Type 0x07 is Broadcom specific for diagnostics
    """
    HCI_CMD = 0x01
    ACL_DATA = 0x02
    SCO_DATA = 0x03
    HCI_EVT = 0x04
    BCM_DIAG = 0x07

    HCI_UART_TYPE_STR = {
        HCI_CMD: "HCI_CMD",
        ACL_DATA: "ACL_DATA",
        SCO_DATA: "SCO_DATA",
        HCI_EVT: "HCI_EVT",
        BCM_DIAG: "BCM_DIAG",
    }

    @staticmethod
    def from_data(data):
        uart_type = data[0]
        return HCI_UART_TYPE_CLASS[uart_type].from_data(data[1:])

    def __init__(self, uart_type):
        self.event_code = None
        self.uart_type = uart_type

    def getRaw(self):
        return p8(self.uart_type)

    def __str__(self):
        return self.HCI_UART_TYPE_STR[self.uart_type]


class HCI_Cmd(HCI):

    HCI_CMD_STR = {
        0x0401: "COMND Inquiry",
        0x0402: "COMND Inquiry_Cancel",
        0x0403: "COMND Periodic_Inquiry_Mode",
        0x0404: "COMND Exit_Periodic_Inquiry_Mode",
        0x0405: "COMND Create_Connection",
        0x0406: "COMND Disconnect",
        0x0408: "COMND Create_Connection_Cancel",
        0x0409: "COMND Accept_Connection_Request",
        0x040A: "COMND Reject_Connection_Request",
        0x040B: "COMND Link_Key_Request_Reply",
        0x040C: "COMND Link_Key_Request_Negative_Reply",
        0x040D: "COMND PIN_Code_Request_Reply",
        0x040E: "COMND PIN_Code_Request_Negative_Reply",
        0x040F: "COMND Change_Connection_Packet_Type",
        0x0411: "COMND Authentication_Requested",
        0x0413: "COMND Set_Connection_Encryption ",
        0x0415: "COMND Change_Connection_Link_Key",
        0x0417: "COMND Master_Link_Key",
        0x0419: "COMND Remote_Name_Request",
        0x041A: "COMND Remote_Name_Request_Cancel",
        0x041B: "COMND Read_Remote_Supported_Features",
        0x041C: "COMND Read_Remote_Extended_Features",
        0x041D: "COMND Read_Remote_Version_Information",
        0x041F: "COMND Read_Clock_Offset",
        0x0420: "COMND Read_LMP_Handle",
        0x0428: "COMND Setup_Synchronous_Connection",
        0x0429: "COMND Accept_Synchronous_Connection_Request",
        0x042A: "COMND Reject_Synchronous_Connection_Request",
        0x042B: "COMND IO_Capability_Request_Reply",
        0x042C: "COMND User_Confirmation_Request_Reply",
        0x042D: "COMND User_Confirmation_Request_Negative_Reply",
        0x042E: "COMND User_Passkey_Request_Reply",
        0x042F: "COMND User_Passkey_Request_Negative_Reply",
        0x0430: "COMND Remote_OOB_Data_Request_Reply",
        0x0433: "COMND Remote_OOB_Data_Request_Negative_Reply",
        0x0434: "COMND IO_Capability_Request_Negative_Reply",
        0x0435: "COMND Create_Physical_Link",
        0x0436: "COMND Accept_Physical_Link",
        0x0437: "COMND Disconnect_Physical_Link",
        0x0438: "COMND Create_Logical_Link",
        0x0439: "COMND Accept_Logical_Link",
        0x043A: "COMND Disconnect_Logical_Link",
        0x043B: "COMND Logical_Link_Cancel",
        0x043C: "COMND Flow_Spec_Modify",
        0x043D: "COMND Enhanced_Setup_Synchronous_Connection",
        0x043E: "COMND Enhanced_Accept_Synchronous_Connection_Request",
        0x043F: "COMND Truncated_Page",
        0x0440: "COMND Truncated_Page_Cancel",
        0x0441: "COMND Set_Connectionless_Slave_Broadcast",
        0x0442: "COMND Set_Connectionless_Slave_Broadcast_Broadcast_Receive",
        0x0443: "COMND Start_Synchronization_Train",
        0x0444: "COMND Receive_Synchronization_Train",
        0x0445: "COMND Remote_OOB_Extended_Data_Request_Reply",
        0x0801: "COMND Hold_Mode",
        0x0803: "COMND Sniff_Mode",
        0x0804: "COMND Exit_Sniff_Mode",
        0x0805: "COMND Park_State",
        0x0806: "COMND Exit_Park_State",
        0x0807: "COMND QoS_Setup",
        0x0809: "COMND Role_Discovery",
        0x080B: "COMND Switch_Role",
        0x080C: "COMND Read_Link_Policy_Settings",
        0x080D: "COMND Write_Link_Policy_Settings",
        0x080E: "COMND Read_Default_Link_Policy_Settings",
        0x080F: "COMND Write_Default_Link_Policy_Settings",
        0x0810: "COMND Flow_Specification",
        0x0811: "COMND Sniff_Subrating",
        0x0C01: "COMND Set_Event_Mask",
        0x0C03: "COMND Reset",
        0x0C05: "COMND Set_Event_Filter",
        0x0C08: "COMND Flush",
        0x0C09: "COMND Read_PIN_Type",
        0x0C0A: "COMND Write_PIN_Type",
        0x0C0B: "COMND Create_New_Unit_Key",
        0x0C0D: "COMND Read_Stored_Link_Key",
        0x0C11: "COMND Write_Stored_Link_Key",
        0x0C12: "COMND Delete_Stored_Link_Key",
        0x0C13: "COMND Write_Local_Name",
        0x0C14: "COMND Read_Local_Name",
        0x0C15: "COMND Read_Connection_Accept_Timeout",
        0x0C16: "COMND Write_Connection_Accept_Timeout",
        0x0C17: "COMND Read_Page_Timeout",
        0x0C18: "COMND Write_Page_Timeout",
        0x0C19: "COMND Read_Scan_Enable",
        0x0C1A: "COMND Write_Scan_Enable",
        0x0C1B: "COMND Read_Page_Scan_Activity",
        0x0C1C: "COMND Write_Page_Scan_Activity",
        0x0C1D: "COMND Read_Inquiry_Scan_Activity",
        0x0C1E: "COMND Write_Inquiry_Scan_Activity",
        0x0C1F: "COMND Read_Authentication_Enable",
        0x0C20: "COMND Write_Authentication_Enable",
        0x0C23: "COMND Read_Class_of_Device",
        0x0C24: "COMND Write_Class_of_Device",
        0x0C25: "COMND Read_Voice_Setting",
        0x0C26: "COMND Write_Voice_Setting",
        0x0C27: "COMND Read_Automatic_Flush_Timeout",
        0x0C28: "COMND Write_Automatic_Flush_Timeout",
        0x0C29: "COMND Read_Num_Broadcast_Retransmissions",
        0x0C30: "COMND Write_Num_Broadcast_Retransmissions",
        0x0C2B: "COMND Read_Hold_Mode_Activity",
        0x0C2C: "COMND Write_Hold_Mode_Activity",
        0x0C2D: "COMND Read_Transmit_Power_Level",
        0x0C2E: "COMND Read_Synchronous_Flow_Control_Enable",
        0x0C2F: "COMND Write_Synchronous_Flow_Control_Enable",
        0x0C31: "COMND Set_Controller_To_Host_Flow_Control",
        0x0C33: "COMND Host_Buffer_Size",
        0x0C35: "COMND Host_Number_Of_Completed_Packets",
        0x0C36: "COMND Read_Link_Supervision_Timeout",
        0x0C37: "COMND Write_Link_Supervision_Timeout",
        0x0C38: "COMND Read_Number_Of_Supported_IAC",
        0x0C39: "COMND Read_Current_IAC_LAP",
        0x0C3A: "COMND Write_Current_IAC_LAP",
        0x0C3F: "COMND Set_AFH_Host_Channel_Classification",
        0x0C42: "COMND Read_Inquiry_Scan_Type",
        0x0C43: "COMND Write_Inquiry_Scan_Type",
        0x0C44: "COMND Read_Inquiry_Mode",
        0x0C45: "COMND Write_Inquiry_Mode",
        0x0C46: "COMND Read_Page_Scan_Type",
        0x0C47: "COMND Write_Page_Scan_Type",
        0x0C48: "COMND Read_AFH_Channel_Assessment_Mode",
        0x0C49: "COMND Write_AFH_Channel_Assessment_Mode",
        0x0C51: "COMND Read_Extended_Inquiry_Response",
        0x0C52: "COMND Write_Extended_Inquiry_Response",
        0x0C53: "COMND Refresh_Encryption_Key",
        0x0C55: "COMND Read_Simple_Pairing_Mode",
        0x0C56: "COMND Write_Simple_Pairing_Mode",
        0x0C57: "COMND Read_Local_OOB_Data",
        0x0C58: "COMND Read_Inquiry_Response_Transmit_Power_Level",
        0x0C59: "COMND Write_Inquiry_Response_Transmit_Power_Level",
        0x0C60: "COMND Send_Key_Press_Notification",
        0x0C5A: "COMND Read_Default_Erroneous_Data_Reporting",
        0x0C5B: "COMND Write_Default_Erroneous_Data_Reporting",
        0x0C5F: "COMND Enhanced_Flush",
        0x0C61: "COMND Read_Logical_Link_Accept_Timeout",
        0x0C62: "COMND Write_Logical_Link_Accept_Timeout",
        0x0C63: "COMND Set_Event_Mask_Page_2",
        0x0C64: "COMND Read_Location_Data",
        0x0C65: "COMND Write_Location_Data",
        0x0C66: "COMND Read_Flow_Control_Mode",
        0x0C67: "COMND Write_Flow_Control_Mode",
        0x0C68: "COMND Read_Enhance_Transmit_Power_Level",
        0x0C69: "COMND Read_Best_Effort_Flush_Timeout",
        0x0C6A: "COMND Write_Best_Effort_Flush_Timeout",
        0x0C6B: "COMND Short_Range_Mode",
        0x0C6C: "COMND Read_LE_Host_Support",
        0x0C6D: "COMND Write_LE_Host_Support",
        0x0C6E: "COMND Set_MWS_Channel_Parameters",
        0x0C6F: "COMND Set_External_Frame_Configuration",
        0x0C70: "COMND Set_MWS_Signaling",
        0x0C71: "COMND Set_MWS_Transport_Layer",
        0x0C72: "COMND Set_MWS_Scan_Frequency_Table",
        0x0C73: "COMND Set_MWS_PATTERN_Configuration",
        0x0C74: "COMND Set_Reserved_LT_ADDR",
        0x0C75: "COMND Delete_Reserved_LT_ADDR",
        0x0C76: "COMND Set_Connectionless_Slave_Broadcast_Data",
        0x0C77: "COMND Read_Synchronization_Train_Parameters",
        0x0C78: "COMND Write_Synchronization_Train_Parameters",
        0x0C79: "COMND Read_Secure_Connections_Host_Support",
        0x0C7A: "COMND Write_Secure_Connections_Host_Support",
        0x0C7B: "COMND Read_Authenticated_Payload_Timeout",
        0x0C7C: "COMND Write_Authenticated_Payload_Timeout",
        0x0C7D: "COMND Read_Local_OOB_Extended_Data",
        0x0C7E: "COMND Read_Extended_Page_Timeout",
        0x0C7F: "COMND Write_Extended_Page_Timeout",
        0x0C80: "COMND Read_Extended_Inquiry_Length",
        0x0C81: "COMND Write_Extended_Inquiry_Length",
        0x1001: "COMND Read_Local_Version_Information",
        0x1002: "COMND Read_Local_Supported_Commands",
        0x1003: "COMND Read_Local_Supported_Features",
        0x1004: "COMND Read_Local_Extended_Features",
        0x1005: "COMND Read_Buffer_Size",
        0x1009: "COMND Read_BD_ADDR",
        0x100A: "COMND Read_Data_Block_Size",
        0x100B: "COMND Read_Local_Supported_Codecs",
        0x1401: "COMND Read_Failed_Contact_Counter",
        0x1402: "COMND Reset_Failed_Contact_Counter",
        0x1403: "COMND Read_Link_Quality",
        0x1405: "COMND Read_RSSI",
        0x1406: "COMND Read_AFH_Channel_Map",
        0x1407: "COMND Read_Clock",
        0x1408: "COMND Encryption_Key_Size",
        0x1409: "COMND Read_Local_AMP_Info",
        0x140A: "COMND Read_Local_AMP_ASSOC",
        0x140B: "COMND Write_Remote_AMP_ASSOC",
        0x140C: "COMND Get_MWS_Transport_Layer_Configuration",
        0x140D: "COMND Set_Triggered_Clock_Capture",
        0x1801: "COMND Read_Loopback_Mode",
        0x1802: "COMND Write_Loopback_Mode",
        0x1803: "COMND Enable_Device_Under_Test_Mode",
        0x1804: "COMND Write_Simple_Pairing_Debug_Mode",
        0x1807: "COMND Enable_AMP_Receiver_Reports",
        0x1808: "COMND AMP_Test_End",
        0x1809: "COMND AMP_Test",
        0x180A: "COMND Write_Secure_Connection_Test_Mode",
        0x2001: "COMND LE_Set_Event_Mask",
        0x2002: "COMND LE_Read_Buffer_Size",
        0x2003: "COMND LE_Read_Local_Supported_Features",
        0x2005: "COMND LE_Set_Random_Address",
        0x2006: "COMND LE_Set_Advertising_Parameters",
        0x2007: "COMND LE_Read_Advertising_Channel_Tx_Power",
        0x2008: "COMND LE_Set_Advertising_Data",
        0x2009: "COMND LE_Set_Scan_Responce_Data",
        0x200A: "COMND LE_Set_Advertise_Enable",
        0x200B: "COMND LE_Set_Set_Scan_Parameters",
        0x200C: "COMND LE_Set_Scan_Enable",
        0x200D: "COMND LE_Create_Connection",
        0x200E: "COMND LE_Create_Connection_Cancel ",
        0x200F: "COMND LE_Read_White_List_Size",
        0x2010: "COMND LE_Clear_White_List",
        0x2011: "COMND LE_Add_Device_To_White_List",
        0x2012: "COMND LE_RemoveDevice_From_White_List",
        0x2013: "COMND LE_Connection_Update",
        0x2014: "COMND LE_Set_Host_Channel_Classification",
        0x2015: "COMND LE_Read_Channel_Map",
        0x2016: "COMND LE_Read_Remote_Used_Features",
        0x2017: "COMND LE_Encrypt",
        0x2018: "COMND LE_Rand",
        0x2019: "COMND LE_Start_Encryption",
        0x201A: "COMND LE_Long_Term_Key_Request_Reply",
        0x201B: "COMND LE_Long_Term_Key_Request_Negative_Reply",
        0x201C: "COMND LE_Read_Supported_States",
        0x201D: "COMND LE_Receiver_Test",
        0x201E: "COMND LE_Transmitter_Test",
        0x201F: "COMND LE_Test_End",
        0x2020: "COMND LE_Remote_Connection_Parameter_Request_Reply",
        0x2021: "COMND LE_Remote_Connection_Parameter_Request_Negative_Reply",
        # Function names extracted from CYW20735 / Packet Logger 9 / bluez source / BCM20703A2 Symbols
        0xFC00: "COMND VSC_CustomerExtension",
        0xFC01: "COMND VSC_WriteBdAddr",
        0xFC02: "COMND VSC_DumpSRAM",
        0xFC03: "COMND VSC_ChannelClassConfig",
        0xFC04: "COMND VSC_READ_PAGE_SCAN_REPETITION_MODE",
        0xFC05: "COMND VSC_WRITE_PAGE_SCAN_REPETITION_MODE",
        0xFC06: "COMND VSC_READ_PAGE_RESPONSE_TIMEOUT",
        0xFC07: "COMND VSC_WRITE_PAGE_RESPONSE_TIMEOUT",
        0xFC08: "COMND VSC_BTLinkQualityMode",  # VSC_READ_NEW_CONNECTION_TIMEOUT
        0xFC09: "COMND VSC_WRITE_NEW_CONNECTION_TIMEOUT",
        0xFC0A: "COMND VSC_Super_Peek_Poke",
        0xFC0B: "COMND VSC_WriteLocalSupportedFeatures",
        0xFC0C: "COMND VSC_Super_Duper_Peek_Poke",
        0xFC0D: "COMND VSC_RSSI_HISTORY",
        0xFC0E: "COMND VSC_SetLEDGlobalCtrl",
        0xFC0F: "COMND VSC_FORCE_HOLD_MODE",
        0xFC10: "COMND VSC_Commit_BDAddr",
        0xFC12: "COMND VSC_WriteHoppingChannels",
        0xFC13: "COMND VSC_SleepForeverMode",
        0xFC14: "COMND VSC_SetCarrierFrequencyArm",
        0xFC16: "COMND VSC_SetEncryptionKeySize",
        0xFC17: "COMND VSC_Invalidate_Flash_and_Reboot",
        0xFC18: "COMND VSC_Update_UART_Baud_Rate",
        0xFC19: "COMND VSC_GpioConfigAndWrite",
        0xFC1A: "COMND VSC_GpioRead",
        0xFC1B: "COMND VSC_SetTestModeType",
        0xFC1C: "COMND VSC_WriteScoPcmInterfaceParam",
        0xFC1D: "COMND VSC_ReadScoPcmIntParam",
        0xFC1E: "COMND VSC_WritePcmDataFormatParam",
        0xFC1F: "COMND VSC_ReadPcmDataFormatParam",
        0xFC20: "COMND VSC_WriteComfortNoiseParam",
        0xFC22: "COMND VSC_WriteScoTimeSlot",
        0xFC23: "COMND VSC_ReadScoTimeSlot",
        0xFC24: "COMND VSC_WritePcmLoopbackModed",
        0xFC25: "COMND VSC_ReadPcmLoopbackModed",
        0xFC26: "COMND VSC_SetTransmitPower",
        0xFC27: "COMND VSC_SetSleepMode",
        0xFC28: "COMND VSC_ReadSleepMode",
        0xFC29: "COMND VSC_SleepmodeCommand",
        0xFC2A: "COMND VSC_HandleDelayPeripheralSCOStartup",
        0xFC2B: "COMND VSC_WriteReceiveOnly",
        0xFC2D: "COMND VSC_RfConfigSettings",
        0xFC2E: "COMND VSC_HandleDownload_Minidriver",
        0xFC2F: "COMND VSC_CrystalPpm",
        0xFC32: "COMND VSC_SetAFHBehavior",
        0xFC33: "COMND VSC_ReadBtwSecurityKey",
        0xFC34: "COMND VSC_EnableRadio",
        0xFC35: "COMND VSC_Cosim_Set_Mode",
        0xFC36: "COMND VSC_GetHIDDeviceList",
        0xFC37: "COMND VSC_AddHIDDevice",
        0xFC39: "COMND VSC_RemoveHIDDevice",
        0xFC3A: "COMND VSC_EnableTca",
        0xFC3B: "COMND VSC_EnableUSBHIDEmulation",
        0xFC3C: "COMND VSC_WriteRfProgrammingTable",
        0xFC40: "COMND VSC_ReadCollaborationMode",
        0xFC41: "COMND VSC_WriteCollaborationMode",
        0xFC43: "COMND VSC_WriteRFAttenuationTable",
        0xFC44: "COMND VSC_ReadUARTClockSetting",
        0xFC45: "COMND VSC_WriteUARTClockSetting",
        0xFC46: "COMND VSC_SetSleepClockAccuratyAndSettlingTime",
        0xFC47: "COMND VSC_ConfigureSleepMode",
        0xFC48: "COMND VSC_ReadRawRssi",
        0xFC49: "COMND VSC_ChannelClassConfig",
        0xFC4C: "COMND VSC_Write_RAM",
        0xFC4D: "COMND VSC_Read_RAM",
        0xFC4E: "COMND VSC_Launch_RAM",
        0xFC4F: "COMND VSC_InstallPatches",
        0xFC51: "COMND VSC_RadioTxTest",
        0xFC52: "COMND VSC_RadioRxTest",
        0xFC54: "COMND VSC_DUT_LoopbackTest",
        0xFC56: "COMND VSC_EnhancedRadioRxTest",
        0xFC57: "COMND VSC_WriteHighPriorityConnection",
        0xFC58: "COMND VSC_SendLmpPdu",
        0xFC59: "COMND VSC_PortInformationEnable",
        0xFC5A: "COMND VSC_ReadBtPortPidVid",
        0xFC5B: "COMND VSC_Read2MBitFlashCrc",
        0xFC5C: "COMND VSC_FactoryCommitProductionTestFlag",
        0xFC5D: "COMND VSC_ReadProductionTestFlag",
        0xFC5E: "COMND VSC_WritePcmMuteParam",
        0xFC5F: "COMND VSC_ReadPcmMuteParam",
        0xFC61: "COMND VSC_WritePcmPins",
        0xFC62: "COMND VSC_ReadPcmPins",
        0xFC6D: "COMND VSC_WriteI2sPcmInterface",
        0xFC6E: "COMND VSC_ReadControllerFeatures",
        0xFC6F: "COMND VSC_WriteComfortNoiseParam",
        0xFC71: "COMND VSC_WriteRamCompressed",  # maybe .hcd only
        0xFC78: "COMND VSC_CALCULATE_CRC",
        0xFC79: "COMND VSC_ReadVerboseConfigVersionInfo",
        0xFC7A: "COMND VSC_TRANSPORT_SUSPEND",
        0xFC7B: "COMND VSC_TRANSPORT_RESUME",
        0xFC7C: "COMND VSC_BasebandFlowControlOverride",
        0xFC7D: "COMND VSC_WriteClass15PowerTable",
        0xFC7E: "COMND VSC_EnableWbs",
        0xFC7F: "COMND VSC_WriteVadMode",
        0xFC80: "COMND VSC_ReadVadMode",
        0xFC81: "COMND VSC_WriteEcsiConfig",
        0xFC82: "COMND VSC_FM_TX_COMMAND",
        0xFC83: "COMND VSC_WriteDynamicScoRoutingChange",
        0xFC84: "COMND VSC_READ_HID_BIT_ERROR_RATE",
        0xFC85: "COMND VSC_EnableHciRemoteTest",
        0xFC8A: "COMND VSC_CALIBRATE_BANDGAP",
        0xFC8B: "COMND VSC_UipcOverHci",  # Write Coexistence Tri State Enabled
        0xFC8C: "COMND VSC_READ_ADC_CHANNEL",
        0xFC90: "COMND VSC_CoexBandwidthStatistics",
        0xFC91: "COMND VSC_ReadPmuConfigFlags",
        0xFC92: "COMND VSC_WritePmuConfigFlags",
        0xFC93: "COMND VSC_ARUBA_CTRL_MAIN_STATUS_MON",
        0xFC94: "COMND VSC_CONTROL_AFH_ACL_SETUP",
        0xFC95: "COMND VSC_ARUBA_READ_WRITE_INIT_PARAM",
        0xFC96: "COMND VSC_INTERNAL_CAPACITOR_TUNING",
        0xFC97: "COMND VSC_BFC_DISCONNECT",
        0xFC98: "COMND VSC_BFC_SEND_DATA",
        0xFC9A: "COMND VSC_COEX_WRITE_WIMAX_CONFIGURATION",
        0xFC9B: "COMND VSC_BFC_POLLING_ENABLE",
        0xFC9C: "COMND VSC_BFC_RECONNECTABLE_DEVICE",
        0xFC9D: "COMND VSC_CONDITIONAL_SCAN_CONFIGURATION",
        0xFC9E: "COMND VSC_PacketErrorInjection",
        0xFCA0: "COMND VSC_WriteRfReprogrammingTableMasking",
        0xFCA1: "COMND VSC_BLPM_ENABLE",
        0xFCA2: "COMND VSC_ReadAudioRouteInfo",
        0xFCA3: "COMND VSC_EncapsulatedHciCommand",
        0xFCA4: "COMND VSC_SendEpcLmpMessage",
        0xFCA5: "COMND VSC_TransportStatistics",
        0xFCA6: "COMND VSC_BistPostGetResults",
        0xFCAD: "COMND VSC_CurrentSensorCtrlerConfig",
        0xFCAE: "COMND VSC_Pcm2Setup",
        0xFCAF: "COMND VSC_ReadBootCrystalStatus",
        0xFCB2: "COMND VSC_SniffSubratingMaximumLocalLatency",
        0xFCB4: "COMND VSC_SET_PLC_ON_OFF",
        0xFCB5: "COMND VSC_BFC_Suspend",
        0xFCB6: "COMND VSC_BFC_Resume",
        0xFCB7: "COMND VSC_3D_TV2TV_SYNC_AND_REPORTING",
        0xFCB8: "COMND VSC_WRITE_OTP",
        0xFCB9: "COMND VSC_READ_OTP",
        0xFCBA: "COMND VSC_le_read_random_address",
        0xFCBB: "COMND VSC_le_hw_setup",
        0xFCBC: "COMND VSC_LE_DVT_TXRXTEST",
        0xFCBD: "COMND VSC_LE_DVT_TESTDATAPKT",
        0xFCBE: "COMND VSC_LE_DVT_LOG_SETUP",
        0xFCBF: "COMND VSC_LE_DVT_ERRORINJECT_SCHEME",
        0xFCC0: "COMND VSC_LE_DVT_TIMING_SCHEME",
        0xFCC1: "COMND VSC_LeScanRssiThresholdSetup",
        0xFCC2: "COMND VSC_BFCSetParameters",
        0xFCC3: "COMND VSC_BFCReadParameters",
        0xFCC4: "COMND VSC_TurnOffDynamicPowerControl",
        0xFCC5: "COMND VSC_IncreaseDecreasePowerLevel",
        0xFCC6: "COMND VSC_ReadRawRssiValue",
        0xFCC7: "COMND VSC_SetProximityTable",
        0xFCC8: "COMND VSC_SetProximityTrigger",
        0xFCCD: "COMND VSC_SET_SUB_SNIFF_INTERVAL",
        0xFCCE: "COMND VSC_ENABLE_REPEATER_FUNCTIONALITY",
        0xFCCF: "COMND VSC_UPDATE_CONFIG_ITEM",
        0xFCD0: "COMND VSC_BFCCreateConnection",
        0xFCD1: "COMND VSC_WBS_BEC_PARAMS",
        0xFCD2: "COMND VSC_ReadGoldenRange",
        0xFCD3: "COMND VSC_INITIATE_MULTICAST_BEACON_LOCK",
        0xFCD4: "COMND VSC_TERMINATE_MULTICAST",
        0xFCD7: "COMND VSC_ENABLE_H4IBSS",
        0xFCD8: "COMND VSC_BLUEBRIDGE_SPI_NEGOTIATION_REQUEST",
        0xFCD9: "COMND VSC_BLUEBRIDGE_SPI_SLEEPTHRESHOLD_REQUEST",
        0xFCDA: "COMND VSC_ACCESSORY_PROTOCOL_COMMAND_GROUP",
        0xFCDB: "COMND VSC_HandleWriteOtp_AuxData",
        0xFCDC: "COMND VSC_InitMcastIndPoll",
        0xFCDD: "COMND VSC_EnterMcastIndPoll",
        0xFCDE: "COMND VSC_DisconnectMcastIndPoll",
        0xFCE0: "COMND VSC_ExtendedInquiryHandshake",
        0xFCE1: "COMND VSC_UARTBRIDGE_ROUTE_HCI_CMD_TO_UART_BRIDGE",
        0xFCE2: "COMND VSC_Olympic",
        0xFCE4: "COMND VSC_CONFIG_HID_LHL_GPIO",
        0xFCE5: "COMND VSC_READ_HID_LHL_GPIO",
        0xFCE6: "COMND VSC_LeTxTest",
        0xFCE7: "COMND VSC_UARTBRIDGE_SET_UART_BRIDGE_PARAMETER",
        0xFCE8: "COMND VSC_BIST_BER",
        0xFCE9: "COMND VSC_HandleLeMetaVsc1",
        0xFCEA: "COMND VSC_BFC_SET_PRIORITY",
        0xFCEB: "COMND VSC_BFC_READ_PRIORITY",
        0xFCEC: "COMND VSC_ANT_COMMAND",
        0xFCED: "COMND VSC_LinkQualityStats",
        0xFCEE: "COMND VSC_READ_NATIVE_CLOCK",
        0xFCEF: "COMND VSC_BfcSetWakeupFlags",
        0xFCF2: "COMND VSC_START_DVT_TINYDRIVER",
        0xFCF4: "COMND VSC_SET_3DTV_DUAL_MODE_VIEW",
        0xFCF5: "COMND VSC_BFCReadRemoeBPCSFeatures",
        0xFCF7: "COMND VSC_IgnoreUSBReset",
        0xFCF8: "COMND VSC_SNIFF_RECONNECT_TRAIN",
        0xFCF9: "COMND VSC_AudioIPCommand",
        0xFCFA: "COMND VSC_BFCWriteScanEnable",
        0xFCFE: "COMND VSC_ReadLocalFirmwareInfo",
        0xFCFF: "COMND VSC_RSSIMeasurements",
        0xFD01: "COMND VSC_BFCReadScanEnable",
        0xFD02: "COMND VSC_EnableWbsModified",
        0xFD03: "COMND VSC_SetVsEventMask",
        0xFD04: "COMND VSC_BFCIsConnectionTBFCSuspended",
        0xFD05: "COMND VSC_SetUSBAutoResume",
        0xFD06: "COMND VSC_SetDirectionFindingParameters",
        0xFD08: "COMND VSC_ChangeLNAGainCoexECI",
        0xFD0C: "COMND VSC_LTELinkQualityMode",  # LTECoexLinkQualityMetric
        0xFD0D: "COMND VSC_LTETriggerWCI2Message",
        0xFD0E: "COMND VSC_LTEEnableWCI2Messages",
        0xFD0F: "COMND VSC_LTEEnableWCI2LoopbackTesting",
        0xFD10: "COMND VSC_ScoDiagStat",
        0xFD11: "COMND VSC_SetStreamingConnectionlessBroadcast",
        0xFD12: "COMND VSC_ReceiveStreamingConnectonlessBroadcast",
        0xFD13: "COMND VSC_WriteConnectionlessBroadcastStreamingData",
        0xFD14: "COMND VSC_FlushStreamingConnectionlessBroadcastData",
        0xFD15: "COMND VSC_FactoryCalSetTxPower",
        0xFD16: "COMND VSC_FactoryCalTrimTxPower",
        0xFD17: "COMND VSC_FactoryCalReadTempSettings",
        0xFD18: "COMND VSC_FactoryCalUpdateTableSettings",
        0xFD1A: "COMND VSC_WriteA2DPConnection",
        0xFD1B: "COMND VSC_Factory_Cal_Read_Table_Settings",
        0xFD1C: "COMND VSC_DBFW",
        0xFD1D: "COMND VSC_FactoryCalibrationRxRSSITest",
        0xFD1E: "COMND VSC_FactoryCalibrationRxRSSITest",
        0xFD1F: "COMND VSC_LTECoexTimingAdvance",
        0xFD23: "COMND VSC_HandleLeMetaVsc2",
        0xFD28: "COMND VSC_WriteLocalSupportedExtendedFeatures",
        0xFD29: "COMND VSC_PiconetClockAdjustment",
        0xFD2A: "COMND VSC_ReadRetransmissionStatus",
        0xFD2F: "COMND VSC_SetTransmitPowerRange",
        0xFD33: "COMND VSC_PageInquiryTxSuppression",
        0xFD35: "COMND VSC_RandomizeNativeClock",
        0xFD36: "COMND VSC_StoreFactoryCalibrationData",
        0xFD3B: "COMND VSC_ReadSupportedVSCs",
        0xFD3C: "COMND VSC_LEWriteLocalSupportedFeatures",
        0xFD3E: "COMND VSC_LEReadRemoteSupportedBRCMFeatures",
        0xFD40: "COMND VSC_BcsTimeline",
        0xFD41: "COMND VSC_BcsTimelineBroadcastReceive",
        0xFD42: "COMND VSC_ReadDynamicMemoryPoolStatistics",
        0xFD43: "COMND VSC_HandleIop3dtvTesterConfig",
        0xFD45: "COMND VSC_HandleAdcCapture",
        0xFD47: "COMND VSC_LEExtendedDuplicateFilter",
        0xFD48: "COMND VSC_LECreateExtendedAdvertisingInstance",
        0xFD49: "COMND VSC_LERemoveExtendedAdvertisingInstance",
        0xFD4A: "COMND VSC_LESetExtendedAdvertisingParameters",
        0xFD4B: "COMND VSC_LESetExtendedAdvertisingData",
        0xFD4C: "COMND VSC_LESetExtendedScanResponseData",
        0xFD4D: "COMND VSC_LESetExtendedAdvertisingEnable",
        0xFD4E: "COMND VSC_LEUpdateExtendedAdvertisingInstance",
        0xFD53: "COMND VSC_LEGetAndroidVendorCapabilities",
        0xFD54: "COMND VSC_LEMultiAdvtCommand",
        0xFD55: "COMND VSC_LeRPAOffload",
        0xFD56: "COMND VSC_LEBatchScanCommand",
        0xFD57: "COMND VSC_LEBrcmPCF",
        0xFD59: "COMND VSC_GetControllerActivityEnergyInfo",
        0xFD5A: "COMND VSC_ExtendedSetScanParameters",
        0xFD5B: "COMND VSC_Getdebuginfo",
        0xFD5C: "COMND VSC_WriteLocalHostState",
        0xFD6E: "COMND VSC_HandleConfigure_Sleep_Lines",
        0xFD71: "COMND VSC_SetSpecialSniffTransitionEnable",
        0xFD73: "COMND VSC_EnableBTSync",
        0xFD79: "COMND VSC_hciulp_handleBTBLEHighPowerControl",
        0xFD7C: "COMND VSC_HandleCustomerEnableHALinkCommands",
        0xFD7D: "COMND VSC_DWPTestCommands",
        0xFD7F: "COMND VSC_Olympic_LTE_Settings",
        0xFD82: "COMND VSC_WriteLERemotePublicAddress",
        0xFD86: "COMND VSC_1SecondTimerCommands",
        0xFD88: "COMND VSC_ForceWLANChannel",
        0xFD8B: "COMND VSC_SVTConfigSetup",
        0xFD8F: "COMND VSC_HandleCustomerReadHADeltaCommands",
        0xFD9A: "COMND VSC_SetupRSSCommands",
        0xFD9C: "COMND VSC_SetupRSSLocalCommands",
        0xFDA1: "COMND VSC_AudioBufferCommands",
        0xFDA4: "COMND VSC_HealthStatusReport",
        0xFDA8: "COMND VSC_ChangeConnectionPriority",
        0xFDAA: "COMND VSC_SamSetupCommand",
        0xFDAB: "COMND VSC_bthci_cmd_ble_enhancedTransmitterTest_hopping",
        0xFDAF: "COMND VSC_Handle_coex_debug_counters",
        0xFDBB: "COMND VSC_Read_Inquiry_Transmit_Power",
        0xFDBE: "COMND VSC_Enable_PADGC_Override",
        0xFDCB: "COMND VSC_WriteTxPowerAFHMode",
        0xFDCD: "COMND VSC_setMinimumNumberOfUsedChannels",
        0xFDCE: "COMND VSC_HandleBrEdrLinkQualityStats",
        0xFF5E: "COMND VSC_SectorErase",
        0xFFCE: "COMND VSC_Chip_Erase",
        0xFFED: "COMND VSC_EnterDownloadMode",
    }

    HCI_CMD_STR_REVERSE = {v: k for k, v in HCI_CMD_STR.items()}

    @staticmethod
    def cmd_name(opcode):
        """
        Input is the opcode in hex, output is the command name, or false
        """

        opcode_int = int(opcode, 16)

        d = HCI_Cmd.HCI_CMD_STR
        if opcode_int in d:
            return d[opcode_int]

        log.warning("HCI command not found: %s" % opcode)

        return False

    @staticmethod
    def cmd_opcode(command_name):
        """
        Returns the opcode in hex, or false
        """

        d = HCI_Cmd.HCI_CMD_STR_REVERSE
        if command_name in d:
            return hex(d[command_name])

        log.warning("HCI command not found: %s" % command_name)

        return False

    @staticmethod
    def from_data(data):
        return HCI_Cmd(u16(data[0:2]), data[2], data[3:])

    def __init__(self, opcode, length, data):
        HCI.__init__(self, HCI.HCI_CMD)
        self.opcode = opcode
        self.length = length
        self.data = data

    def getRaw(self):
        return (
            super(HCI_Cmd, self).getRaw()
            + p16(self.opcode)
            + p8(self.length)
            + self.data
        )

    def __str__(self):
        parent = HCI.__str__(self)
        cmdname = "unknown"
        if self.opcode in self.HCI_CMD_STR:
            cmdname = self.HCI_CMD_STR[self.opcode]
        return parent + "<0x%04x %s (len=%d): %s>" % (
            self.opcode,
            cmdname,
            self.length,
            "".join(format(x, "02x") for x in self.data[0:16]),
        )


class HCI_Acl(HCI):
    @staticmethod
    def from_data(data):
        handle = u16(unbits(bits_str(data[0:2])[0:12].rjust(16, "0")))
        bp = u8(unbits(bits_str(data[1:2])[4:6].rjust(8, "0")))
        bc = u8(unbits(bits_str(data[1:2])[6:8].rjust(8, "0")))
        return HCI_Acl(handle, bp, bc, u16(data[2:4]), data[4:])

    def getRaw(self):
        raw = bits(p16(self.handle))[4:]
        raw.extend(bits(p8(self.bp))[6:])
        raw.extend(bits(p8(self.bc))[6:])
        raw.extend(bits(p16(self.length)))
        return super(HCI_Acl, self).getRaw() + unbits(raw) + self.data

    def __init__(self, handle, bp, bc, length, data):
        HCI.__init__(self, HCI.ACL_DATA)
        self.handle = handle
        self.bp = bp
        self.bc = bc
        self.length = length
        self.data = data


class HCI_Sco(HCI):
    @staticmethod
    def from_data(data):
        handle = u16(unbits(bits_str(data[0:2])[0:12].rjust(16, "0")))
        ps = u8(unbits(bits_str(data[1:2])[4:6].rjust(8, "0")))
        return HCI_Sco(handle, ps, u8(data[2]), data[3:])

    def getRaw(self):
        raw = bits(p16(self.handle))[4:]
        raw.extend(bits(p8(self.ps))[6:])
        raw.extend(bits(p8(0))[6:])
        raw.extend(bits(p8(self.length)))
        return super(HCI_Sco, self).getRaw() + unbits(raw) + self.data

    def __init__(self, handle, ps, length, data):
        HCI.__init__(self, HCI.SCO_DATA)
        self.handle = handle
        self.ps = ps
        self.length = length
        self.data = data


class HCI_Diag(HCI):

    BCM_DIAG_STR = {
        0x00: "LMP Sent",
        0x01: "LMP Received",
        0x80: "LE LLC Sent",  # Low Energy LL Control PDU LMP Message
        0x81: "LE LLC Received",
    }

    @staticmethod
    def from_data(data):
        return HCI_Diag(u8(data[0:1]), data[1:])

    def getRaw(self):
        return super(HCI_Diag, self).getRaw() + p8(self.opcode) + self.data

    def __init__(self, opcode, data):
        HCI.__init__(self, HCI.BCM_DIAG)
        self.opcode = opcode
        self.length = 63  # fixed length
        self.data = data

    def __str__(self):
        parent = HCI.__str__(self)
        cmdname = "unknown"
        if self.opcode in self.BCM_DIAG_STR:
            cmdname = self.BCM_DIAG_STR[self.opcode]
        return parent + "<0x%02x %s: %s>" % (
            self.opcode,
            cmdname,
            "".join(format(x, "02x") for x in self.data[0:16]),
        )


class HCI_Event(HCI):

    HCI_EVENT_STR = {
        0x01: "EVENT Inquiry_Complete",
        0x02: "EVENT Inquiry_Result",
        0x03: "EVENT Connection_Complete",
        0x04: "EVENT Connection_Request",
        0x05: "EVENT Disconnection_Complete",
        0x06: "EVENT Authentication_Complete",
        0x07: "EVENT Remote_Name_Request_Complete",
        0x08: "EVENT Encryption_Change",
        0x09: "EVENT Change_Connection_Link_Key_Complete",
        0x0A: "EVENT Master_Link_Key_Complete",
        0x0B: "EVENT Read_Remote_Supported_Features_Complete",
        0x0C: "EVENT Read_Remote_Version_Information_Complete",
        0x0D: "EVENT QoS_Setup_Complete",
        0x0E: "EVENT Command_Complete",
        0x0F: "EVENT Command_Status",
        0x10: "EVENT Hardware_Error",
        0x11: "EVENT Flush_Occurred",
        0x12: "EVENT Role_Change",
        0x13: "EVENT Number_Of_Completed_Packets",
        0x14: "EVENT Mode_Change",
        0x15: "EVENT Return_Link_Keys",
        0x16: "EVENT PIN_Code_Request",
        0x17: "EVENT Link_Key_Request",
        0x18: "EVENT Link_Key_Notification",
        0x19: "EVENT Loopback_Command",
        0x1A: "EVENT Data_Buffer_Overflow",
        0x1B: "EVENT Max_Slots_Change",
        0x1C: "EVENT Read_Clock_Offset_Complete",
        0x1D: "EVENT Connection_Packet_Type_Changed",
        0x1E: "EVENT QoS_Violation",
        0x20: "EVENT Page_Scan_Repetition_Mode_Change",
        0x21: "EVENT Flow_Specification_Complete",
        0x22: "EVENT Inquiry_Result_with_RSSI",
        0x23: "EVENT Read_Remote_Extended_Features_Complete",
        0x2C: "EVENT Synchronous_Connection_Complete",
        0x2D: "EVENT Synchronous_Connection_Changed",
        0x2E: "EVENT Sniff_Subrating",
        0x2F: "EVENT Extended_Inquiry_Result",
        0x30: "EVENT Encryption_Key_Refresh_Complete",
        0x31: "EVENT IO_Capability_Request",
        0x32: "EVENT IO_Capability_Response",
        0x33: "EVENT User_Confirmation_Request",
        0x34: "EVENT User_Passkey_Request",
        0x35: "EVENT Remote_OOB_Data_Request",
        0x36: "EVENT Simple_Pairing_Complete",
        0x38: "EVENT Link_Supervision_Timeout_Changed",
        0x39: "EVENT Enhanced_Flush_Complete",
        0x3B: "EVENT User_Passkey_Notification",
        0x3C: "EVENT Keypress_Notification",
        0x3D: "EVENT Remote_Host_Supported_Features_Notification",
        0x3E: "EVENT LE_Meta_Event",
        0x40: "EVENT Physical_Link_Complete",
        0x41: "EVENT Channel_Selected",
        0x42: "EVENT Disconnection_Physical_Link_Complete",
        0x43: "EVENT Physical_Link_Loss_Early_Warning",
        0x44: "EVENT Physical_Link_Recovery",
        0x45: "EVENT Logical_Link_Complete",
        0x46: "EVENT Disconnection_Logical_Link_Complete",
        0x47: "EVENT Flow_Spec_Modify_Complete",
        0x48: "EVENT Number_Of_Completed_Data_Blocks",
        0x4C: "EVENT Short_Range_Mode_Change_Complete",
        0x4D: "EVENT AMP_Status_Change",
        0x49: "EVENT AMP_Start_Test",
        0x4A: "EVENT AMP_Test_End",
        0x4B: "EVENT AMP_Receiver_Report",
        0x4E: "EVENT Triggered_Clock_Capture",
        0x4F: "EVENT Synchronization_Train_Complete",
        0x50: "EVENT Synchronization_Train_Received",
        0x51: "EVENT Connectionless_Slave_Broadcast_Receive",
        0x52: "EVENT Connectionless_Slave_Broadcast_Timeout",
        0x53: "EVENT Truncated_Page_Complete",
        0x54: "EVENT Slave_Page_Response_Timeout",
        0x55: "EVENT Connectionless_Slave_Broadcast_Channel_Map_Change",
        0x56: "EVENT Inquiry_Response_Notification",
        0x57: "EVENT Authenticated_Payload_Timeout_Expired",
        0xEF: "EVENT VSC_SleepModeEvent",
        0xFF: "EVENT BroadcomVendorSpecific",
    }

    # from CYW20735 / packet logger
    HCI_EVENT_VSC_STR = {
        0x07: "EVENT VSC_RadioRxTestResult",
        0x0C: "EVENT VSC_DualStackResume",
        0x16: "EVENT VSC_BFCSuspendComplete",
        0x18: "EVENT VSC_BFCResumeComplete",
        0x19: "EVENT VSC_HlpsDataReady",
        0x1B: "EVENT VSC_DBFW_TraceDump",
        0x29: "EVENT VSC_EirHandshakeComplete",
        0x30: "EVENT VSC_MulticastDataReceived",
        0x39: "EVENT VSC_BFCSuspend",
        0x3E: "EVENT VSC_PhoneComesBack",
        0x3F: "EVENT VSC_PhoneGoesAway",
        0x40: "EVENT VSC_AutoResumeComplete",
        0x41: "EVENT VSC_TxPowerChanged",
        0x42: "EVENT VSC_BFCSuspending",
        0x49: "EVENT VSC_RawRSSI",
        0x4D: "EVENT VSC_SynchronizationTrainReceived",
        0x4E: "EVENT VSC_StreamingPacketTransmitted",
        0x53: "EVENT VSC_RetransmissionStatusUpdate",
        0x54: "EVENT VSC_BatchScanStorageThreshBreach",
        0x55: "EVENT VSC_MultiAdvtStateChange",
        0x56: "EVENT VSC_LEAddressBasedTracking",
        0x6A: "EVENT VSC_GetBcsTimelineData",
        0x6D: "EVENT VSC_1SecondTimer",
        0x74: "EVENT VSC_RSSLocal",
        0x77: "EVENT VSC_AudioBufferNotificationStatsBuffer",
        0x78: "EVENT VSC_HSR_SendFlagsMemTest",
        0x79: "EVENT VSC_RadioRxTestResult",
        0x7E: "EVENT VSC_Sam_SendSettingsSlotmap",
        0x7F: "EVENT VSC_RSSDebug",
        0xA3: "EVENT VSC_AntennaSettingNotification",
        0xA5: "EVENT VSC_MemPoolsStats",  # ??
        0xE9: "EVENT VSC_CustomerSpecific",
        0xF0: "EVENT VSC_BFCSuspending_PwrConsumption",
        0xF3: "EVENT VSC_CustomerSpecificLocalMessages",
        0xF7: "EVENT VSC_CustomerSpecificDebugFramework",
    }

    HCI_COMMAND_ERROR_STR = {
        0x00: "Success",
        0x01: "Unknown HCI Command",
        0x02: "No Connection",
        0x03: "Hardware Failure",
        0x04: "Page Timeout",
        0x05: "Authentication Failure",
        0x06: "Key Missing",
        0x07: "Memory Full",
        0x08: "Connection Timeout",
        0x09: "Max Number Of Connections",
        0x0A: "Max Number Of SCO Connections To A Device",
        0x0B: "ACL Connection Already Exists",
        0x0C: "Command Disallowed",
        0x0D: "Host Rejected Due To Limited Resources",
        0x0E: "Host Rejected Due To Security Reasons",
        0x0F: "Host Rejected Due To A Remote Device Only A Personal Device",
        0x10: "Host Timeout",
        0x11: "Unsupported Feature Or Parameter Value",
        0x12: "Invalid HCI Command Parameters",
        0x13: "Other End Terminated Connection: User Ended Connection",
        0x14: "Other End Terminated Connection: Low Resources",
        0x15: "Other End Terminated Connection: About To Power Off",
        0x16: "Connection Terminated By Local Host",
        0x17: "Repeated Attempts",
        0x18: "Pairing Not Allowed",
        0x19: "Unknown LMP PDU",
        0x1A: "Unsupported Remote Feature",
        0x1B: "SCO Offset Rejected",
        0x1C: "SCO Interval Rejected",
        0x1D: "SCO Air Mode Rejected",
        0x1E: "Invalid LMP Parameters",
        0x1F: "Unspecified Error",
        0x20: "Unsupported LMP Parameter",
        0x21: "Role Change Not Allowed",
        0x22: "LMP Response Timeout",
        0x23: "LMP Error Transaction Collision",
        0x24: "LMP PDU Not Allowed",
        0x25: "Encryption Mode Not Acceptable",
        0x26: "Unit Key Used",
    }

    @staticmethod
    def event_name(code):
        """
        Input is the event code in hex, reply is the event name or false
        """

        code_int = int(code, 16)

        e = HCI_Event.HCI_EVENT_VSC_STR
        if code_int == 0xFF:
            if code_int in e:
                return e[int(self.data[0], 16)]

        d = HCI_Event.HCI_EVENT_STR
        if code_int in d:
            return d[code_int]

        log.warning("Hci event not found: %s" % code)

        return False

    @staticmethod
    def from_data(data):
        return HCI_Event(data[0], data[1], data[2:])

    def __init__(self, event_code, length, data):
        HCI.__init__(self, HCI.HCI_EVT)
        self.event_code = event_code
        self.length = length
        self.data = data

    def getRaw(self):
        return (
            super(HCI_Event, self).getRaw()
            + p8(self.event_code)
            + p8(self.length)
            + self.data
        )

    def __str__(self):
        parent = HCI.__str__(self)
        eventname = "unknown"
        if self.event_code in self.HCI_EVENT_STR:
            eventname = self.HCI_EVENT_STR[self.event_code]
        return parent + "<0x%02x %s (len=%d): %s>" % (
            self.event_code,
            eventname,
            self.length,
            "".join(format(x, "02x") for x in self.data[0:]),
        )


HCI_UART_TYPE_CLASS = {
    HCI.HCI_CMD: HCI_Cmd,
    HCI.ACL_DATA: HCI_Acl,
    HCI.SCO_DATA: HCI_Sco,
    HCI.HCI_EVT: HCI_Event,
    HCI.BCM_DIAG: HCI_Diag,
}


def parse_hci_packet(data):
    return HCI.from_data(data)


class StackDumpReceiver(object):
    memdump_addr = None
    memdumps = {}
    stack_dump_has_happend = False

    def __init__(self, data_directory="."):
        self.data_directory = data_directory
        self.stack_dump_filename = data_directory + "/internalblue_stackdump.bin"

    def recvPacket(self, record):
        hcipkt = record[0]
        if not issubclass(hcipkt.__class__, HCI_Event):
            return
        if hcipkt.event_code != 0xFF:
            return
        # TODO Android 8 introduced special handling for 0x57 HCI_VSE_SUBCODE_DEBUG_INFO_SUB_EVT,
        # stackdumps might no longer work
        if hcipkt.data[0] == "\x57":
            self.handleNexus6pStackDump(hcipkt)
        if hcipkt.data[0:4] == p32(0x039200F7):
            self.handleNexus5StackDump(hcipkt)
        # same header for S10 and evaluation board...
        if hcipkt.data[0:2] == p16(
            0x031B
        ):  # generated by bthci_event_vs_initializeCoredumpHdr()
            self.handleEvalStackDump(hcipkt)
            self.handleS10StackDump(hcipkt)

    def verifyChecksum(self, data):
        """ Data should be a byte string containing all payload bytes
        beginning with the checksum byte.
        """
        return sum([ord(x) for x in data]) % 0x100 == 0

    def handleRamDump(self, data):
        """ Data should be a byte string containing the address (4 byte)
        followed by the actual ram dump (at this address)
        """
        addr = u32(data[:4])
        if self.memdump_addr == None:
            self.memdump_addr = addr
        self.memdumps[addr - self.memdump_addr] = data[4:]
        log.debug("Stack dump handling addr %08x", addr - self.memdump_addr)

    def finishStackDump(self):
        dump = flat(self.memdumps)
        log.warn(
            "Stack dump @0x%08x written to %s!"
            % (self.memdump_addr, self.stack_dump_filename)
        )
        f = open(self.stack_dump_filename, "wb")
        f.write(dump)
        f.close()

        # Shut down:
        self.stack_dump_has_happend = True

    def handleNexus5StackDump(self, hcipkt):
        checksum_correct = self.verifyChecksum(hcipkt.data[5:])
        packet_type = u8(hcipkt.data[4])

        if packet_type == 0x2C:
            data = hcipkt.data[6:]
            values = [u32(data[i : i + 4]) for i in range(0, 64, 4)]
            log.debug(
                "Stack Dump (%s):\n%s"
                % (
                    "checksum correct" if checksum_correct else "checksum NOT correct",
                    "\n".join([hex(x) for x in values]),
                )
            )
            if data[0] == "\x02":
                # This is the second stack dump event (contains register values)
                log.warn(
                    "Received Stack-Dump Event (contains %d registers):" % (u8(data[1]))
                )
                registers = (
                    "pc: 0x%08x   lr: 0x%08x   sp: 0x%08x   r0: 0x%08x   r1: 0x%08x\n"
                    % (values[2], values[3], values[1], values[4], values[5])
                )
                registers += (
                    "r2: 0x%08x   r3: 0x%08x   r4: 0x%08x   r5: 0x%08x   r6: 0x%08x\n"
                    % tuple(values[6:11])
                )
                log.warn(registers)
                return True

        elif packet_type == 0xF0:  # RAM dump
            self.handleRamDump(hcipkt.data[10:])

        elif packet_type == 0x4C:  # RAM dump (last frame)
            self.handleRamDump(hcipkt.data[10:])
            # This is the last pkt ouput:
            self.finishStackDump()
            return True
        return False

    def handleNexus6pStackDump(self, hcipkt):
        checksum_correct = self.verifyChecksum(hcipkt.data[8:])
        packet_nr = u8(hcipkt.data[2])
        packet_type = u8(hcipkt.data[7])

        if packet_type in [0x2C, 0x4C]:
            data = hcipkt.data[9:]
            values = [u32(data[i : i + 4]) for i in range(0, 64, 4)]
            log.debug(
                "Stack Dump (%s) [packet_type=0x%x]:\n%s"
                % (
                    "checksum correct" if checksum_correct else "checksum NOT correct",
                    packet_type,
                    "\n".join([hex(x) for x in values]),
                )
            )

            if packet_type == 0x2C and data[0] == "\x02":
                # This is the second stack dump event (contains register values)
                log.warn(
                    "Received Stack-Dump Event (contains %d registers):" % (u8(data[1]))
                )
                registers = (
                    "pc: 0x%08x   lr: 0x%08x   sp: 0x%08x   r0: 0x%08x   r1: 0x%08x\n"
                    % (values[2], values[3], values[1], values[4], values[5])
                )
                registers += (
                    "r2: 0x%08x   r3: 0x%08x   r4: 0x%08x   r5: 0x%08x   r6: 0x%08x\n"
                    % tuple(values[6:11])
                )
                log.warn(registers)
                return True

        elif packet_type == 0xF0:  # RAM dump
            self.handleRamDump(hcipkt.data[13:])

        if packet_nr == 0x84:
            # This is the last pkt ouput:
            self.finishStackDump()
            return True

        return False

    def handleEvalStackDump(self, hcipkt):
        """
        Handles a core dump from the evaluation board. To trigger a dump execute:
            sendhcicmd 0xfc4e e81e2000
        This executes some memory set to ffff which is an invalid command.
        Many events like executing address 0x0 will only crash the chip but not
        trigger a proper stack dump.

        The evaluation board has quite a lot of memory, RAM dump takes ages...

        dbfw_coredump_exception_cm3() generates the following dumps:
            2c: CoreDumpInfo
            2c: CoreDumpCPURegs
            90: CoreDumpCPURegsExtend
            f0: CoreDumpRAMImage
            78: CoreDumpRAMImage EOF
            9c: CoreDumpHWRegs
            01: CoreDumpEnd

        :param hcipkt: stack dump packet
        :return: returns True if dump could be decoded.
        """
        checksum_correct = self.verifyChecksum(hcipkt.data[3:])
        packet_type = u8(hcipkt.data[2])

        log.debug("packet type %x", packet_type)

        # TODO CoreDumpInfo (shows LMP/HCI version, memory dumps)

        # CoreDumpCPURegs
        if packet_type == 0x2C:
            data = hcipkt.data[4:]
            values = [u32(data[i : i + 4]) for i in range(0, 64, 4)]
            log.debug(
                "Stack Dump (%s):\n%s"
                % (
                    "checksum correct" if checksum_correct else "checksum NOT correct",
                    "\n".join([hex(x) for x in values]),
                )
            )
            if data[0] == "\x02":
                # This is the second stack dump event (contains register values)
                log.warn(
                    "Received Evaluation Stack-Dump Event (contains %d registers):"
                    % (u8(data[1]))
                )
                registers = (
                    "pc: 0x%08x   lr: 0x%08x   sp: 0x%08x   r0: 0x%08x   r1: 0x%08x\n"
                    % (values[2], values[3], values[1], values[4], values[5])
                )
                registers += (
                    "r2: 0x%08x   r3: 0x%08x   r4: 0x%08x   r5: 0x%08x   r6: 0x%08x\n"
                    % tuple(values[6:11])
                )
                log.warn(registers)
                return True

        # CoreDumpRAMImage
        # TODO: Eval board produces this twice:
        #  for 0x200000+0x50000 and 0x270000+0x10000
        elif packet_type == 0xF0:
            self.handleRamDump(hcipkt.data[8:])
            return True

        # Last packet produced by CoreDumpRAMImage
        elif packet_type == 0x78:  # RAM dump (last frame), TODO not sure if this works
            # This is the last pkt ouput:
            log.info("End of stackdump block...")
            self.finishStackDump()
            return True

        # On a Raspberry Pi 3, the last packet of a stack dump is '1b0340df0338'.... so it's 0x40
        elif packet_type == 0xE8:
            # FIXME Raspi memdump is divided in two parts!
            # address change from 0001fe38 to packet type e8 and then it's computing addr -0130000
            # negative addr does not work with finishStackDump()
            # so even though the last packet is 0x40, let's just finish on 0xe8
            log.info(
                "End of first stackdump block, writing to file and skipping second..."
            )
            self.finishStackDump()
            return True

        return False

    def handleS10StackDump(self, hcipkt):
        """
        Packets in stack dump:
            1b 03 90: contains pc and r0
            1b 03 9c
            1b 03 00 (x3)
            1b 03 f0 (whole ram)
            
        """

        checksum_correct = self.verifyChecksum(hcipkt.data[3:])
        packet_type = u8(hcipkt.data[2])

        if packet_type == 0x90:
            data = hcipkt.data[4:]
            values = [u32(data[i : i + 4]) for i in range(0, 64 * 2, 4)]
            log.debug(
                "Stack Dump (%s):\n%s"
                % (
                    "checksum correct" if checksum_correct else "checksum NOT correct",
                    "\n".join([hex(x) for x in values]),
                )
            )
            # Values different than in other stack dump formats, experimental output!
            log.warn(
                "Received S10 Stack-Dump Event (contains %d registers):" % (u8(data[1]))
            )
            registers = (
                "pc: 0x%08x   lr: 0x%08x   sp: 0x%08x   r0: 0x%08x   r1: 0x%08x\n"
                % (values[16], values[17], values[23], values[19], values[20])
            )
            registers += (
                "r2: 0x%08x   r3: 0x%08x   r4: 0x%08x   r5: 0x%08x   r6: 0x%08x\n"
                % (values[21], values[22], values[23], values[24], values[25])
            )
            log.warn(registers)
            return True

        # log.info("%x" % u32(hcipkt.data[8:12]))
        # no last packet for S10e, just the size counts here... also is sometimes longer and sometimes shorter
        if packet_type == 0xF0 and u32(hcipkt.data[8:12]) == 0x230080:
            # This is the last pkt ouput:
            self.finishStackDump()
            return True

        return False
