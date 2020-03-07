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
from enum import Enum

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


class HCI_COMND(Enum):
    Inquiry = 0x401
    Inquiry_Cancel = 0x402
    Periodic_Inquiry_Mode = 0x403
    Exit_Periodic_Inquiry_Mode = 0x404
    Create_Connection = 0x405
    Disconnect = 0x406
    Create_Connection_Cancel = 0x408
    Accept_Connection_Request = 0x409
    Reject_Connection_Request = 0x40A
    Link_Key_Request_Reply = 0x40B
    Link_Key_Request_Negative_Reply = 0x40C
    PIN_Code_Request_Reply = 0x40D
    PIN_Code_Request_Negative_Reply = 0x40E
    Change_Connection_Packet_Type = 0x40F
    Authentication_Requested = 0x411
    Set_Connection_Encryption = 0x413
    Change_Connection_Link_Key = 0x415
    Master_Link_Key = 0x417
    Remote_Name_Request = 0x419
    Remote_Name_Request_Cancel = 0x41A
    Read_Remote_Supported_Features = 0x41B
    Read_Remote_Extended_Features = 0x41C
    Read_Remote_Version_Information = 0x41D
    Read_Clock_Offset = 0x41F
    Read_LMP_Handle = 0x420
    Setup_Synchronous_Connection = 0x428
    Accept_Synchronous_Connection_Request = 0x429
    Reject_Synchronous_Connection_Request = 0x42A
    IO_Capability_Request_Reply = 0x42B
    User_Confirmation_Request_Reply = 0x42C
    User_Confirmation_Request_Negative_Reply = 0x42D
    User_Passkey_Request_Reply = 0x42E
    User_Passkey_Request_Negative_Reply = 0x42F
    Remote_OOB_Data_Request_Reply = 0x430
    Remote_OOB_Data_Request_Negative_Reply = 0x433
    IO_Capability_Request_Negative_Reply = 0x434
    Create_Physical_Link = 0x435
    Accept_Physical_Link = 0x436
    Disconnect_Physical_Link = 0x437
    Create_Logical_Link = 0x438
    Accept_Logical_Link = 0x439
    Disconnect_Logical_Link = 0x43A
    Logical_Link_Cancel = 0x43B
    Flow_Spec_Modify = 0x43C
    Enhanced_Setup_Synchronous_Connection = 0x43D
    Enhanced_Accept_Synchronous_Connection_Request = 0x43E
    Truncated_Page = 0x43F
    Truncated_Page_Cancel = 0x440
    Set_Connectionless_Slave_Broadcast = 0x441
    Set_Connectionless_Slave_Broadcast_Broadcast_Receive = 0x442
    Start_Synchronization_Train = 0x443
    Receive_Synchronization_Train = 0x444
    Remote_OOB_Extended_Data_Request_Reply = 0x445
    Hold_Mode = 0x801
    Sniff_Mode = 0x803
    Exit_Sniff_Mode = 0x804
    Park_State = 0x805
    Exit_Park_State = 0x806
    QoS_Setup = 0x807
    Role_Discovery = 0x809
    Switch_Role = 0x80B
    Read_Link_Policy_Settings = 0x80C
    Write_Link_Policy_Settings = 0x80D
    Read_Default_Link_Policy_Settings = 0x80E
    Write_Default_Link_Policy_Settings = 0x80F
    Flow_Specification = 0x810
    Sniff_Subrating = 0x811
    Set_Event_Mask = 0xC01
    Reset = 0xC03
    Set_Event_Filter = 0xC05
    Flush = 0xC08
    Read_PIN_Type = 0xC09
    Write_PIN_Type = 0xC0A
    Create_New_Unit_Key = 0xC0B
    Read_Stored_Link_Key = 0xC0D
    Write_Stored_Link_Key = 0xC11
    Delete_Stored_Link_Key = 0xC12
    Write_Local_Name = 0xC13
    Read_Local_Name = 0xC14
    Read_Connection_Accept_Timeout = 0xC15
    Write_Connection_Accept_Timeout = 0xC16
    Read_Page_Timeout = 0xC17
    Write_Page_Timeout = 0xC18
    Read_Scan_Enable = 0xC19
    Write_Scan_Enable = 0xC1A
    Read_Page_Scan_Activity = 0xC1B
    Write_Page_Scan_Activity = 0xC1C
    Read_Inquiry_Scan_Activity = 0xC1D
    Write_Inquiry_Scan_Activity = 0xC1E
    Read_Authentication_Enable = 0xC1F
    Write_Authentication_Enable = 0xC20
    Read_Class_of_Device = 0xC23
    Write_Class_of_Device = 0xC24
    Read_Voice_Setting = 0xC25
    Write_Voice_Setting = 0xC26
    Read_Automatic_Flush_Timeout = 0xC27
    Write_Automatic_Flush_Timeout = 0xC28
    Read_Num_Broadcast_Retransmissions = 0xC29
    Write_Num_Broadcast_Retransmissions = 0xC30
    Read_Hold_Mode_Activity = 0xC2B
    Write_Hold_Mode_Activity = 0xC2C
    Read_Transmit_Power_Level = 0xC2D
    Read_Synchronous_Flow_Control_Enable = 0xC2E
    Write_Synchronous_Flow_Control_Enable = 0xC2F
    Set_Controller_To_Host_Flow_Control = 0xC31
    Host_Buffer_Size = 0xC33
    Host_Number_Of_Completed_Packets = 0xC35
    Read_Link_Supervision_Timeout = 0xC36
    Write_Link_Supervision_Timeout = 0xC37
    Read_Number_Of_Supported_IAC = 0xC38
    Read_Current_IAC_LAP = 0xC39
    Write_Current_IAC_LAP = 0xC3A
    Set_AFH_Host_Channel_Classification = 0xC3F
    Read_Inquiry_Scan_Type = 0xC42
    Write_Inquiry_Scan_Type = 0xC43
    Read_Inquiry_Mode = 0xC44
    Write_Inquiry_Mode = 0xC45
    Read_Page_Scan_Type = 0xC46
    Write_Page_Scan_Type = 0xC47
    Read_AFH_Channel_Assessment_Mode = 0xC48
    Write_AFH_Channel_Assessment_Mode = 0xC49
    Read_Extended_Inquiry_Response = 0xC51
    Write_Extended_Inquiry_Response = 0xC52
    Refresh_Encryption_Key = 0xC53
    Read_Simple_Pairing_Mode = 0xC55
    Write_Simple_Pairing_Mode = 0xC56
    Read_Local_OOB_Data = 0xC57
    Read_Inquiry_Response_Transmit_Power_Level = 0xC58
    Write_Inquiry_Response_Transmit_Power_Level = 0xC59
    Send_Key_Press_Notification = 0xC60
    Read_Default_Erroneous_Data_Reporting = 0xC5A
    Write_Default_Erroneous_Data_Reporting = 0xC5B
    Enhanced_Flush = 0xC5F
    Read_Logical_Link_Accept_Timeout = 0xC61
    Write_Logical_Link_Accept_Timeout = 0xC62
    Set_Event_Mask_Page_2 = 0xC63
    Read_Location_Data = 0xC64
    Write_Location_Data = 0xC65
    Read_Flow_Control_Mode = 0xC66
    Write_Flow_Control_Mode = 0xC67
    Read_Enhance_Transmit_Power_Level = 0xC68
    Read_Best_Effort_Flush_Timeout = 0xC69
    Write_Best_Effort_Flush_Timeout = 0xC6A
    Short_Range_Mode = 0xC6B
    Read_LE_Host_Support = 0xC6C
    Write_LE_Host_Support = 0xC6D
    Set_MWS_Channel_Parameters = 0xC6E
    Set_External_Frame_Configuration = 0xC6F
    Set_MWS_Signaling = 0xC70
    Set_MWS_Transport_Layer = 0xC71
    Set_MWS_Scan_Frequency_Table = 0xC72
    Set_MWS_PATTERN_Configuration = 0xC73
    Set_Reserved_LT_ADDR = 0xC74
    Delete_Reserved_LT_ADDR = 0xC75
    Set_Connectionless_Slave_Broadcast_Data = 0xC76
    Read_Synchronization_Train_Parameters = 0xC77
    Write_Synchronization_Train_Parameters = 0xC78
    Read_Secure_Connections_Host_Support = 0xC79
    Write_Secure_Connections_Host_Support = 0xC7A
    Read_Authenticated_Payload_Timeout = 0xC7B
    Write_Authenticated_Payload_Timeout = 0xC7C
    Read_Local_OOB_Extended_Data = 0xC7D
    Read_Extended_Page_Timeout = 0xC7E
    Write_Extended_Page_Timeout = 0xC7F
    Read_Extended_Inquiry_Length = 0xC80
    Write_Extended_Inquiry_Length = 0xC81
    Read_Local_Version_Information = 0x1001
    Read_Local_Supported_Commands = 0x1002
    Read_Local_Supported_Features = 0x1003
    Read_Local_Extended_Features = 0x1004
    Read_Buffer_Size = 0x1005
    Read_BD_ADDR = 0x1009
    Read_Data_Block_Size = 0x100A
    Read_Local_Supported_Codecs = 0x100B
    Read_Failed_Contact_Counter = 0x1401
    Reset_Failed_Contact_Counter = 0x1402
    Read_Link_Quality = 0x1403
    Read_RSSI = 0x1405
    Read_AFH_Channel_Map = 0x1406
    Read_Clock = 0x1407
    Encryption_Key_Size = 0x1408
    Read_Local_AMP_Info = 0x1409
    Read_Local_AMP_ASSOC = 0x140A
    Write_Remote_AMP_ASSOC = 0x140B
    Get_MWS_Transport_Layer_Configuration = 0x140C
    Set_Triggered_Clock_Capture = 0x140D
    Read_Loopback_Mode = 0x1801
    Write_Loopback_Mode = 0x1802
    Enable_Device_Under_Test_Mode = 0x1803
    Write_Simple_Pairing_Debug_Mode = 0x1804
    Enable_AMP_Receiver_Reports = 0x1807
    AMP_Test_End = 0x1808
    AMP_Test = 0x1809
    Write_Secure_Connection_Test_Mode = 0x180A
    LE_Set_Event_Mask = 0x2001
    LE_Read_Buffer_Size = 0x2002
    LE_Read_Local_Supported_Features = 0x2003
    LE_Set_Random_Address = 0x2005
    LE_Set_Advertising_Parameters = 0x2006
    LE_Read_Advertising_Channel_Tx_Power = 0x2007
    LE_Set_Advertising_Data = 0x2008
    LE_Set_Scan_Responce_Data = 0x2009
    LE_Set_Advertise_Enable = 0x200A
    LE_Set_Set_Scan_Parameters = 0x200B
    LE_Set_Scan_Enable = 0x200C
    LE_Create_Connection = 0x200D
    LE_Create_Connection_Cancel = 0x200E
    LE_Read_White_List_Size = 0x200F
    LE_Clear_White_List = 0x2010
    LE_Add_Device_To_White_List = 0x2011
    LE_RemoveDevice_From_White_List = 0x2012
    LE_Connection_Update = 0x2013
    LE_Set_Host_Channel_Classification = 0x2014
    LE_Read_Channel_Map = 0x2015
    LE_Read_Remote_Used_Features = 0x2016
    LE_Encrypt = 0x2017
    LE_Rand = 0x2018
    LE_Start_Encryption = 0x2019
    LE_Long_Term_Key_Request_Reply = 0x201A
    LE_Long_Term_Key_Request_Negative_Reply = 0x201B
    LE_Read_Supported_States = 0x201C
    LE_Receiver_Test = 0x201D
    LE_Transmitter_Test = 0x201E
    LE_Test_End = 0x201F
    LE_Remote_Connection_Parameter_Request_Reply = 0x2020
    LE_Remote_Connection_Parameter_Request_Negative_Reply = 0x2021
    VSC_CustomerExtension = 0xFC00
    VSC_WriteBdAddr = 0xFC01
    VSC_DumpSRAM = 0xFC02
    VSC_ChannelClassConfig = 0xFC03
    VSC_READ_PAGE_SCAN_REPETITION_MODE = 0xFC04
    VSC_WRITE_PAGE_SCAN_REPETITION_MODE = 0xFC05
    VSC_READ_PAGE_RESPONSE_TIMEOUT = 0xFC06
    VSC_WRITE_PAGE_RESPONSE_TIMEOUT = 0xFC07
    VSC_BTLinkQualityMode = 0xFC08
    VSC_WRITE_NEW_CONNECTION_TIMEOUT = 0xFC09
    VSC_Super_Peek_Poke = 0xFC0A
    VSC_WriteLocalSupportedFeatures = 0xFC0B
    VSC_Super_Duper_Peek_Poke = 0xFC0C
    VSC_RSSI_HISTORY = 0xFC0D
    VSC_SetLEDGlobalCtrl = 0xFC0E
    VSC_FORCE_HOLD_MODE = 0xFC0F
    VSC_Commit_BDAddr = 0xFC10
    VSC_WriteHoppingChannels = 0xFC12
    VSC_SleepForeverMode = 0xFC13
    VSC_SetCarrierFrequencyArm = 0xFC14
    VSC_SetEncryptionKeySize = 0xFC16
    VSC_Invalidate_Flash_and_Reboot = 0xFC17
    VSC_Update_UART_Baud_Rate = 0xFC18
    VSC_GpioConfigAndWrite = 0xFC19
    VSC_GpioRead = 0xFC1A
    VSC_SetTestModeType = 0xFC1B
    VSC_WriteScoPcmInterfaceParam = 0xFC1C
    VSC_ReadScoPcmIntParam = 0xFC1D
    VSC_WritePcmDataFormatParam = 0xFC1E
    VSC_ReadPcmDataFormatParam = 0xFC1F
    VSC_WriteComfortNoiseParam = 0xFC20
    VSC_WriteScoTimeSlot = 0xFC22
    VSC_ReadScoTimeSlot = 0xFC23
    VSC_WritePcmLoopbackModed = 0xFC24
    VSC_ReadPcmLoopbackModed = 0xFC25
    VSC_SetTransmitPower = 0xFC26
    VSC_SetSleepMode = 0xFC27
    VSC_ReadSleepMode = 0xFC28
    VSC_SleepmodeCommand = 0xFC29
    VSC_HandleDelayPeripheralSCOStartup = 0xFC2A
    VSC_WriteReceiveOnly = 0xFC2B
    VSC_RfConfigSettings = 0xFC2D
    VSC_HandleDownload_Minidriver = 0xFC2E
    VSC_CrystalPpm = 0xFC2F
    VSC_SetAFHBehavior = 0xFC32
    VSC_ReadBtwSecurityKey = 0xFC33
    VSC_EnableRadio = 0xFC34
    VSC_Cosim_Set_Mode = 0xFC35
    VSC_GetHIDDeviceList = 0xFC36
    VSC_AddHIDDevice = 0xFC37
    VSC_RemoveHIDDevice = 0xFC39
    VSC_EnableTca = 0xFC3A
    VSC_EnableUSBHIDEmulation = 0xFC3B
    VSC_WriteRfProgrammingTable = 0xFC3C
    VSC_ReadCollaborationMode = 0xFC40
    VSC_WriteCollaborationMode = 0xFC41
    VSC_WriteRFAttenuationTable = 0xFC43
    VSC_ReadUARTClockSetting = 0xFC44
    VSC_WriteUARTClockSetting = 0xFC45
    VSC_SetSleepClockAccuratyAndSettlingTime = 0xFC46
    VSC_ConfigureSleepMode = 0xFC47
    VSC_ReadRawRssi = 0xFC48
    # VSC_ChannelClassConfig = 0XFC49
    VSC_Write_RAM = 0xFC4C
    VSC_Read_RAM = 0xFC4D
    VSC_Launch_RAM = 0xFC4E
    VSC_InstallPatches = 0xFC4F
    VSC_RadioTxTest = 0xFC51
    VSC_RadioRxTest = 0xFC52
    VSC_DUT_LoopbackTest = 0xFC54
    VSC_EnhancedRadioRxTest = 0xFC56
    VSC_WriteHighPriorityConnection = 0xFC57
    VSC_SendLmpPdu = 0xFC58
    VSC_PortInformationEnable = 0xFC59
    VSC_ReadBtPortPidVid = 0xFC5A
    VSC_Read2MBitFlashCrc = 0xFC5B
    VSC_FactoryCommitProductionTestFlag = 0xFC5C
    VSC_ReadProductionTestFlag = 0xFC5D
    VSC_WritePcmMuteParam = 0xFC5E
    VSC_ReadPcmMuteParam = 0xFC5F
    VSC_WritePcmPins = 0xFC61
    VSC_ReadPcmPins = 0xFC62
    VSC_WriteI2sPcmInterface = 0xFC6D
    VSC_ReadControllerFeatures = 0xFC6E
    # VSC_WriteComfortNoiseParam = 0XFC6F
    VSC_WriteRamCompressed = 0xFC71
    VSC_CALCULATE_CRC = 0xFC78
    VSC_ReadVerboseConfigVersionInfo = 0xFC79
    VSC_TRANSPORT_SUSPEND = 0xFC7A
    VSC_TRANSPORT_RESUME = 0xFC7B
    VSC_BasebandFlowControlOverride = 0xFC7C
    VSC_WriteClass15PowerTable = 0xFC7D
    VSC_EnableWbs = 0xFC7E
    VSC_WriteVadMode = 0xFC7F
    VSC_ReadVadMode = 0xFC80
    VSC_WriteEcsiConfig = 0xFC81
    VSC_FM_TX_COMMAND = 0xFC82
    VSC_WriteDynamicScoRoutingChange = 0xFC83
    VSC_READ_HID_BIT_ERROR_RATE = 0xFC84
    VSC_EnableHciRemoteTest = 0xFC85
    VSC_CALIBRATE_BANDGAP = 0xFC8A
    VSC_UipcOverHci = 0xFC8B
    VSC_READ_ADC_CHANNEL = 0xFC8C
    VSC_CoexBandwidthStatistics = 0xFC90
    VSC_ReadPmuConfigFlags = 0xFC91
    VSC_WritePmuConfigFlags = 0xFC92
    VSC_ARUBA_CTRL_MAIN_STATUS_MON = 0xFC93
    VSC_CONTROL_AFH_ACL_SETUP = 0xFC94
    VSC_ARUBA_READ_WRITE_INIT_PARAM = 0xFC95
    VSC_INTERNAL_CAPACITOR_TUNING = 0xFC96
    VSC_BFC_DISCONNECT = 0xFC97
    VSC_BFC_SEND_DATA = 0xFC98
    VSC_COEX_WRITE_WIMAX_CONFIGURATION = 0xFC9A
    VSC_BFC_POLLING_ENABLE = 0xFC9B
    VSC_BFC_RECONNECTABLE_DEVICE = 0xFC9C
    VSC_CONDITIONAL_SCAN_CONFIGURATION = 0xFC9D
    VSC_PacketErrorInjection = 0xFC9E
    VSC_WriteRfReprogrammingTableMasking = 0xFCA0
    VSC_BLPM_ENABLE = 0xFCA1
    VSC_ReadAudioRouteInfo = 0xFCA2
    VSC_EncapsulatedHciCommand = 0xFCA3
    VSC_SendEpcLmpMessage = 0xFCA4
    VSC_TransportStatistics = 0xFCA5
    VSC_BistPostGetResults = 0xFCA6
    VSC_CurrentSensorCtrlerConfig = 0xFCAD
    VSC_Pcm2Setup = 0xFCAE
    VSC_ReadBootCrystalStatus = 0xFCAF
    VSC_SniffSubratingMaximumLocalLatency = 0xFCB2
    VSC_SET_PLC_ON_OFF = 0xFCB4
    VSC_BFC_Suspend = 0xFCB5
    VSC_BFC_Resume = 0xFCB6
    VSC_3D_TV2TV_SYNC_AND_REPORTING = 0xFCB7
    VSC_WRITE_OTP = 0xFCB8
    VSC_READ_OTP = 0xFCB9
    VSC_le_read_random_address = 0xFCBA
    VSC_le_hw_setup = 0xFCBB
    VSC_LE_DVT_TXRXTEST = 0xFCBC
    VSC_LE_DVT_TESTDATAPKT = 0xFCBD
    VSC_LE_DVT_LOG_SETUP = 0xFCBE
    VSC_LE_DVT_ERRORINJECT_SCHEME = 0xFCBF
    VSC_LE_DVT_TIMING_SCHEME = 0xFCC0
    VSC_LeScanRssiThresholdSetup = 0xFCC1
    VSC_BFCSetParameters = 0xFCC2
    VSC_BFCReadParameters = 0xFCC3
    VSC_TurnOffDynamicPowerControl = 0xFCC4
    VSC_IncreaseDecreasePowerLevel = 0xFCC5
    VSC_ReadRawRssiValue = 0xFCC6
    VSC_SetProximityTable = 0xFCC7
    VSC_SetProximityTrigger = 0xFCC8
    VSC_SET_SUB_SNIFF_INTERVAL = 0xFCCD
    VSC_ENABLE_REPEATER_FUNCTIONALITY = 0xFCCE
    VSC_UPDATE_CONFIG_ITEM = 0xFCCF
    VSC_BFCCreateConnection = 0xFCD0
    VSC_WBS_BEC_PARAMS = 0xFCD1
    VSC_ReadGoldenRange = 0xFCD2
    VSC_INITIATE_MULTICAST_BEACON_LOCK = 0xFCD3
    VSC_TERMINATE_MULTICAST = 0xFCD4
    VSC_ENABLE_H4IBSS = 0xFCD7
    VSC_BLUEBRIDGE_SPI_NEGOTIATION_REQUEST = 0xFCD8
    VSC_BLUEBRIDGE_SPI_SLEEPTHRESHOLD_REQUEST = 0xFCD9
    VSC_ACCESSORY_PROTOCOL_COMMAND_GROUP = 0xFCDA
    VSC_HandleWriteOtp_AuxData = 0xFCDB
    VSC_InitMcastIndPoll = 0xFCDC
    VSC_EnterMcastIndPoll = 0xFCDD
    VSC_DisconnectMcastIndPoll = 0xFCDE
    VSC_ExtendedInquiryHandshake = 0xFCE0
    VSC_UARTBRIDGE_ROUTE_HCI_CMD_TO_UART_BRIDGE = 0xFCE1
    VSC_Olympic = 0xFCE2
    VSC_CONFIG_HID_LHL_GPIO = 0xFCE4
    VSC_READ_HID_LHL_GPIO = 0xFCE5
    VSC_LeTxTest = 0xFCE6
    VSC_UARTBRIDGE_SET_UART_BRIDGE_PARAMETER = 0xFCE7
    VSC_BIST_BER = 0xFCE8
    VSC_HandleLeMetaVsc1 = 0xFCE9
    VSC_BFC_SET_PRIORITY = 0xFCEA
    VSC_BFC_READ_PRIORITY = 0xFCEB
    VSC_ANT_COMMAND = 0xFCEC
    VSC_LinkQualityStats = 0xFCED
    VSC_READ_NATIVE_CLOCK = 0xFCEE
    VSC_BfcSetWakeupFlags = 0xFCEF
    VSC_START_DVT_TINYDRIVER = 0xFCF2
    VSC_SET_3DTV_DUAL_MODE_VIEW = 0xFCF4
    VSC_BFCReadRemoeBPCSFeatures = 0xFCF5
    VSC_IgnoreUSBReset = 0xFCF7
    VSC_SNIFF_RECONNECT_TRAIN = 0xFCF8
    VSC_AudioIPCommand = 0xFCF9
    VSC_BFCWriteScanEnable = 0xFCFA
    VSC_ReadLocalFirmwareInfo = 0xFCFE
    VSC_RSSIMeasurements = 0xFCFF
    VSC_BFCReadScanEnable = 0xFD01
    VSC_EnableWbsModified = 0xFD02
    VSC_SetVsEventMask = 0xFD03
    VSC_BFCIsConnectionTBFCSuspended = 0xFD04
    VSC_SetUSBAutoResume = 0xFD05
    VSC_SetDirectionFindingParameters = 0xFD06
    VSC_ChangeLNAGainCoexECI = 0xFD08
    VSC_LTELinkQualityMode = 0xFD0C
    VSC_LTETriggerWCI2Message = 0xFD0D
    VSC_LTEEnableWCI2Messages = 0xFD0E
    VSC_LTEEnableWCI2LoopbackTesting = 0xFD0F
    VSC_ScoDiagStat = 0xFD10
    VSC_SetStreamingConnectionlessBroadcast = 0xFD11
    VSC_ReceiveStreamingConnectonlessBroadcast = 0xFD12
    VSC_WriteConnectionlessBroadcastStreamingData = 0xFD13
    VSC_FlushStreamingConnectionlessBroadcastData = 0xFD14
    VSC_FactoryCalSetTxPower = 0xFD15
    VSC_FactoryCalTrimTxPower = 0xFD16
    VSC_FactoryCalReadTempSettings = 0xFD17
    VSC_FactoryCalUpdateTableSettings = 0xFD18
    VSC_WriteA2DPConnection = 0xFD1A
    VSC_Factory_Cal_Read_Table_Settings = 0xFD1B
    VSC_DBFW = 0xFD1C
    VSC_FactoryCalibrationRxRSSITest = 0xFD1D
    # VSC_FactoryCalibrationRxRSSITest = 0XFD1E
    VSC_LTECoexTimingAdvance = 0xFD1F
    VSC_HandleLeMetaVsc2 = 0xFD23
    VSC_WriteLocalSupportedExtendedFeatures = 0xFD28
    VSC_PiconetClockAdjustment = 0xFD29
    VSC_ReadRetransmissionStatus = 0xFD2A
    VSC_SetTransmitPowerRange = 0xFD2F
    VSC_PageInquiryTxSuppression = 0xFD33
    VSC_RandomizeNativeClock = 0xFD35
    VSC_StoreFactoryCalibrationData = 0xFD36
    VSC_ReadSupportedVSCs = 0xFD3B
    VSC_LEWriteLocalSupportedFeatures = 0xFD3C
    VSC_LEReadRemoteSupportedBRCMFeatures = 0xFD3E
    VSC_BcsTimeline = 0xFD40
    VSC_BcsTimelineBroadcastReceive = 0xFD41
    VSC_ReadDynamicMemoryPoolStatistics = 0xFD42
    VSC_HandleIop3dtvTesterConfig = 0xFD43
    VSC_HandleAdcCapture = 0xFD45
    VSC_LEExtendedDuplicateFilter = 0xFD47
    VSC_LECreateExtendedAdvertisingInstance = 0xFD48
    VSC_LERemoveExtendedAdvertisingInstance = 0xFD49
    VSC_LESetExtendedAdvertisingParameters = 0xFD4A
    VSC_LESetExtendedAdvertisingData = 0xFD4B
    VSC_LESetExtendedScanResponseData = 0xFD4C
    VSC_LESetExtendedAdvertisingEnable = 0xFD4D
    VSC_LEUpdateExtendedAdvertisingInstance = 0xFD4E
    VSC_LEGetAndroidVendorCapabilities = 0xFD53
    VSC_LEMultiAdvtCommand = 0xFD54
    VSC_LeRPAOffload = 0xFD55
    VSC_LEBatchScanCommand = 0xFD56
    VSC_LEBrcmPCF = 0xFD57
    VSC_GetControllerActivityEnergyInfo = 0xFD59
    VSC_ExtendedSetScanParameters = 0xFD5A
    VSC_Getdebuginfo = 0xFD5B
    VSC_WriteLocalHostState = 0xFD5C
    VSC_HandleConfigure_Sleep_Lines = 0xFD6E
    VSC_SetSpecialSniffTransitionEnable = 0xFD71
    VSC_EnableBTSync = 0xFD73
    VSC_hciulp_handleBTBLEHighPowerControl = 0xFD79
    VSC_HandleCustomerEnableHALinkCommands = 0xFD7C
    VSC_DWPTestCommands = 0xFD7D
    VSC_Olympic_LTE_Settings = 0xFD7F
    VSC_WriteLERemotePublicAddress = 0xFD82
    VSC_1SecondTimerCommands = 0xFD86
    VSC_ForceWLANChannel = 0xFD88
    VSC_SVTConfigSetup = 0xFD8B
    VSC_HandleCustomerReadHADeltaCommands = 0xFD8F
    VSC_SetupRSSCommands = 0xFD9A
    VSC_SetupRSSLocalCommands = 0xFD9C
    VSC_AudioBufferCommands = 0xFDA1
    VSC_HealthStatusReport = 0xFDA4
    VSC_ChangeConnectionPriority = 0xFDA8
    VSC_SamSetupCommand = 0xFDAA
    VSC_bthci_cmd_ble_enhancedTransmitterTest_hopping = 0xFDAB
    VSC_Handle_coex_debug_counters = 0xFDAF
    VSC_Read_Inquiry_Transmit_Power = 0xFDBB
    VSC_Enable_PADGC_Override = 0xFDBE
    VSC_WriteTxPowerAFHMode = 0xFDCB
    VSC_setMinimumNumberOfUsedChannels = 0xFDCD
    VSC_HandleBrEdrLinkQualityStats = 0xFDCE
    VSC_SectorErase = 0xFF5E
    VSC_Chip_Erase = 0xFFCE
    VSC_EnterDownloadMode = 0xFFED


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

        try:
            cmdname = HCI_COMND(self.opcode).name
        except ValueError:
            cmdname = "unknown"

        return f"{HCI.__str__(self)}{'0x%04x'.format(self.opcode)} COMND {cmdname} (len={self.length}):  {''.join(format(x, '02x') for x in self.data[0:16])}"


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

    # @staticmethod
    def event_name(self, code):
        """
        Input is the event code in hex, reply is the event name or false
        """

        code_int = int(code, 16)

        e = HCI_Event.HCI_EVENT_VSC_STR
        if code_int == 0xFF:
            if code_int in e:
                return e[self.data[0]]

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
