#!/usr/bin/python2

# Dennis Mantz
# Many parts are from https://github.com/joekickass/python-btsnoop

from pwn import *

HCI_UART_TYPE_CLASS = {}

class HCI:

    """
    HCI Packet types for UART Transport layer
    Core specification 4.1 [vol 4] Part A (Section 2) - Protocol
    """
    HCI_CMD = 0x01
    ACL_DATA = 0x02
    SCO_DATA = 0x03
    HCI_EVT = 0x04

    HCI_UART_TYPE_STR = {
        HCI_CMD : "HCI_CMD",
        ACL_DATA : "ACL_DATA",
        SCO_DATA : "SCO_DATA",
        HCI_EVT : "HCI_EVT"
    }

    @staticmethod
    def from_data(data):
        uart_type = ord(data[0])
        return HCI_UART_TYPE_CLASS[uart_type].from_data(data[1:])

    def __init__(self, uart_type):
        self.uart_type = uart_type

    def __str__(self):
        return self.HCI_UART_TYPE_STR[self.uart_type]

class HCI_Cmd(HCI):
 
    HCI_CMD_STR = {
        0x0401 : "COMND Inquiry",
        0x0402 : "COMND Inquiry_Cancel",
        0x0403 : "COMND Periodic_Inquiry_Mode",
        0x0404 : "COMND Exit_Periodic_Inquiry_Mode",
        0x0405 : "COMND Create_Connection",
        0x0406 : "COMND Disconnect",
        0x0408 : "COMND Create_Connection_Cancel",
        0x0409 : "COMND Accept_Connection_Request",
        0x040a : "COMND Reject_Connection_Request",
        0x040b : "COMND Link_Key_Request_Reply",
        0x040c : "COMND Link_Key_Request_Negative_Reply",
        0x040d : "COMND PIN_Code_Request_Reply",
        0x040e : "COMND PIN_Code_Request_Negative_Reply",
        0x040f : "COMND Change_Connection_Packet_Type",
        0x0411 : "COMND Authentication_Requested",
        0x0413 : "COMND Set_Connection_Encryption ",
        0x0415 : "COMND Change_Connection_Link_Key",
        0x0417 : "COMND Master_Link_Key",
        0x0419 : "COMND Remote_Name_Request",
        0x041a : "COMND Remote_Name_Request_Cancel",
        0x041b : "COMND Read_Remote_Supported_Features",
        0x041c : "COMND Read_Remote_Extended_Features",
        0x041d : "COMND Read_Remote_Version_Information",
        0x041f : "COMND Read_Clock_Offset",
        0x0420 : "COMND Read_LMP_Handle",
        0x0428 : "COMND Setup_Synchronous_Connection",
        0x0429 : "COMND Accept_Synchronous_Connection_Request",
        0x042a : "COMND Reject_Synchronous_Connection_Request",
        0x042b : "COMND IO_Capability_Request_Reply",
        0x042c : "COMND User_Confirmation_Request_Reply",
        0x042d : "COMND User_Confirmation_Request_Negative_Reply",
        0x042e : "COMND User_Passkey_Request_Reply",
        0x042f : "COMND User_Passkey_Request_Negative_Reply",
        0x0430 : "COMND Remote_OOB_Data_Request_Reply",
        0x0433 : "COMND Remote_OOB_Data_Request_Negative_Reply",
        0x0434 : "COMND IO_Capability_Request_Negative_Reply",
        0x0435 : "COMND Create_Physical_Link",
        0x0436 : "COMND Accept_Physical_Link",
        0x0437 : "COMND Disconnect_Physical_Link",
        0x0438 : "COMND Create_Logical_Link",
        0x0439 : "COMND Accept_Logical_Link",
        0x043a : "COMND Disconnect_Logical_Link",
        0x043b : "COMND Logical_Link_Cancel",
        0x043c : "COMND Flow_Spec_Modify",
        0x043d : "COMND Enhanced_Setup_Synchronous_Connection",
        0x043e : "COMND Enhanced_Accept_Synchronous_Connection_Request",
        0x043f : "COMND Truncated_Page",
        0x0440 : "COMND Truncated_Page_Cancel",
        0x0441 : "COMND Set_Connectionless_Slave_Broadcast",
        0x0442 : "COMND Set_Connectionless_Slave_Broadcast_Broadcast_Receive",
        0x0443 : "COMND Start_Synchronization_Train",
        0x0444 : "COMND Receive_Synchronization_Train",
        0x0445 : "COMND Remote_OOB_Extended_Data_Request_Reply",
        0x0801 : "COMND Hold_Mode",
        0x0803 : "COMND Sniff_Mode",
        0x0804 : "COMND Exit_Sniff_Mode",
        0x0805 : "COMND Park_State",
        0x0806 : "COMND Exit_Park_State",
        0x0807 : "COMND QoS_Setup",
        0x0809 : "COMND Role_Discovery",
        0x080b : "COMND Switch_Role",
        0x080c : "COMND Read_Link_Policy_Settings",
        0x080d : "COMND Write_Link_Policy_Settings",
        0x080e : "COMND Read_Default_Link_Policy_Settings",
        0x080f : "COMND Write_Default_Link_Policy_Settings",
        0x0810 : "COMND Flow_Specification",
        0x0811 : "COMND Sniff_Subrating",
        0x0c01 : "COMND Set_Event_Mask",
        0x0c03 : "COMND Reset",
        0x0c05 : "COMND Set_Event_Filter",
        0x0c08 : "COMND Flush",
        0x0c09 : "COMND Read_PIN_Type",
        0x0c0a : "COMND Write_PIN_Type",
        0x0c0b : "COMND Create_New_Unit_Key",
        0x0c0d : "COMND Read_Stored_Link_Key",
        0x0c11 : "COMND Write_Stored_Link_Key",
        0x0c12 : "COMND Delete_Stored_Link_Key",
        0x0c13 : "COMND Write_Local_Name",
        0x0c14 : "COMND Read_Local_Name",
        0x0c15 : "COMND Read_Connection_Accept_Timeout",
        0x0c16 : "COMND Write_Connection_Accept_Timeout",
        0x0c17 : "COMND Read_Page_Timeout",
        0x0c18 : "COMND Write_Page_Timeout",
        0x0c19 : "COMND Read_Scan_Enable",
        0x0c1a : "COMND Write_Scan_Enable",
        0x0c1b : "COMND Read_Page_Scan_Activity",
        0x0c1c : "COMND Write_Page_Scan_Activity",
        0x0c1d : "COMND Read_Inquiry_Scan_Activity",
        0x0c1e : "COMND Write_Inquiry_Scan_Activity",
        0x0c1f : "COMND Read_Authentication_Enable",
        0x0c20 : "COMND Write_Authentication_Enable",
        0x0c23 : "COMND Read_Class_of_Device",
        0x0c24 : "COMND Write_Class_of_Device",
        0x0c25 : "COMND Read_Voice_Setting",
        0x0c26 : "COMND Write_Voice_Setting",
        0x0c27 : "COMND Read_Automatic_Flush_Timeout",
        0x0c28 : "COMND Write_Automatic_Flush_Timeout",
        0x0c29 : "COMND Read_Num_Broadcast_Retransmissions",
        0x0c30 : "COMND Write_Num_Broadcast_Retransmissions",
        0x0c2b : "COMND Read_Hold_Mode_Activity",
        0x0c2c : "COMND Write_Hold_Mode_Activity",
        0x0c2d : "COMND Read_Transmit_Power_Level",
        0x0c2e : "COMND Read_Synchronous_Flow_Control_Enable",
        0x0c2f : "COMND Write_Synchronous_Flow_Control_Enable",
        0x0c31 : "COMND Set_Controller_To_Host_Flow_Control",
        0x0c33 : "COMND Host_Buffer_Size",
        0x0c35 : "COMND Host_Number_Of_Completed_Packets",
        0x0c36 : "COMND Read_Link_Supervision_Timeout",
        0x0c37 : "COMND Write_Link_Supervision_Timeout",
        0x0c38 : "COMND Read_Number_Of_Supported_IAC",
        0x0c39 : "COMND Read_Current_IAC_LAP",
        0x0c3a : "COMND Write_Current_IAC_LAP",
        0x0c3f : "COMND Set_AFH_Host_Channel_Classification",
        0x0c42 : "COMND Read_Inquiry_Scan_Type",
        0x0c43 : "COMND Write_Inquiry_Scan_Type",
        0x0c44 : "COMND Read_Inquiry_Mode",
        0x0c45 : "COMND Write_Inquiry_Mode",
        0x0c46 : "COMND Read_Page_Scan_Type",
        0x0c47 : "COMND Write_Page_Scan_Type",
        0x0c48 : "COMND Read_AFH_Channel_Assessment_Mode",
        0x0c49 : "COMND Write_AFH_Channel_Assessment_Mode",
        0x0c51 : "COMND Read_Extended_Inquiry_Response",
        0x0c52 : "COMND Write_Extended_Inquiry_Response",
        0x0c53 : "COMND Refresh_Encryption_Key",
        0x0c55 : "COMND Read_Simple_Pairing_Mode",
        0x0c56 : "COMND Write_Simple_Pairing_Mode",
        0x0c57 : "COMND Read_Local_OOB_Data",
        0x0c58 : "COMND Read_Inquiry_Response_Transmit_Power_Level",
        0x0c59 : "COMND Write_Inquiry_Response_Transmit_Power_Level",
        0x0c60 : "COMND Send_Key_Press_Notification",
        0x0c5a : "COMND Read_Default_Erroneous_Data_Reporting",
        0x0c5b : "COMND Write_Default_Erroneous_Data_Reporting",
        0x0c5f : "COMND Enhanced_Flush",
        0x0c61 : "COMND Read_Logical_Link_Accept_Timeout",
        0x0c62 : "COMND Write_Logical_Link_Accept_Timeout",
        0x0c63 : "COMND Set_Event_Mask_Page_2",
        0x0c64 : "COMND Read_Location_Data",
        0x0c65 : "COMND Write_Location_Data",
        0x0c66 : "COMND Read_Flow_Control_Mode",
        0x0c67 : "COMND Write_Flow_Control_Mode",
        0x0c68 : "COMND Read_Enhance_Transmit_Power_Level",
        0x0c69 : "COMND Read_Best_Effort_Flush_Timeout",
        0x0c6a : "COMND Write_Best_Effort_Flush_Timeout",
        0x0c6b : "COMND Short_Range_Mode",
        0x0c6c : "COMND Read_LE_Host_Support",
        0x0c6d : "COMND Write_LE_Host_Support",
        0x0c6e : "COMND Set_MWS_Channel_Parameters",
        0x0c6f : "COMND  Set_ External_Frame_Configuration",
        0x0c70 : "COMND Set_MWS_Signaling",
        0x0c71 : "COMND Set_MWS_Transport_Layer",
        0x0c72 : "COMND Set_MWS_Scan_Frequency_Table",
        0x0c73 : "COMND Set_MWS_PATTERN_Configuration",
        0x0c74 : "COMND Set_Reserved_LT_ADDR",
        0x0c75 : "COMND Delete_Reserved_LT_ADDR",
        0x0c76 : "COMND Set_Connectionless_Slave_Broadcast_Data",
        0x0c77 : "COMND Read_Synchronization_Train_Parameters",
        0x0c78 : "COMND Write_Synchronization_Train_Parameters",
        0x0c79 : "COMND Read_Secure_Connections_Host_Support",
        0x0c7a : "COMND Write_Secure_Connections_Host_Support",
        0x0c7b : "COMND Read_Authenticated_Payload_Timeout",
        0x0c7c : "COMND Write_Authenticated_Payload_Timeout",
        0x0c7d : "COMND Read_Local_OOB_Extended_Data",
        0x0c7e : "COMND Read_Extended_Page_Timeout",
        0x0c7f : "COMND Write_Extended_Page_Timeout",
        0x0c80 : "COMND Read_Extended_Inquiry_Length",
        0x0c81 : "COMND Write_Extended_Inquiry_Length",
        0x1001 : "COMND Read_Local_Version_Information",
        0x1002 : "COMND Read_Local_Supported_Commands",
        0x1003 : "COMND Read_Local_Supported_Features",
        0x1004 : "COMND Read_Local_Extended_Features",
        0x1005 : "COMND Read_Buffer_Size",
        0x1009 : "COMND Read_BD_ADDR",
        0x100a : "COMND Read_Data_Block_Size",
        0x100b : "COMND Read_Local_Supported_Codecs",
        0x1401 : "COMND Read_Failed_Contact_Counter",
        0x1402 : "COMND Reset_Failed_Contact_Counter",
        0x1403 : "COMND Read_Link_Quality",
        0x1405 : "COMND Read_RSSI",
        0x1406 : "COMND Read_AFH_Channel_Map",
        0x1407 : "COMND Read_Clock",
        0x1408 : "COMND Encryption_Key_Size",
        0x1409 : "COMND Read_Local_AMP_Info",
        0x140a : "COMND Read_Local_AMP_ASSOC",
        0x140b : "COMND Write_Remote_AMP_ASSOC",
        0x140c : "COMND Get_MWS_Transport_Layer_Configuration",
        0x140d : "COMND Set_Triggered_Clock_Capture",
        0x1801 : "COMND Read_Loopback_Mode",
        0x1802 : "COMND Write_Loopback_Mode",
        0x1803 : "COMND Enable_Device_Under_Test_Mode",
        0x1804 : "COMND Write_Simple_Pairing_Debug_Mode",
        0x1807 : "COMND Enable_AMP_Receiver_Reports",
        0x1808 : "COMND AMP_Test_End",
        0x1809 : "COMND AMP_Test",
        0x180a : "COMND Write_Secure_Connection_Test_Mode",
        0x2001 : "COMND LE_Set_Event_Mask",
        0x2002 : "COMND LE_Read_Buffer_Size",
        0x2003 : "COMND LE_Read_Local_Supported_Features",
        0x2005 : "COMND LE_Set_Random_Address",
        0x2006 : "COMND LE_Set_Advertising_Parameters",
        0x2007 : "COMND LE_Read_Advertising_Channel_Tx_Power",
        0x2008 : "COMND LE_Set_Advertising_Data",
        0x2009 : "COMND LE_Set_Scan_Responce_Data",
        0x200a : "COMND LE_Set_Advertise_Enable",
        0x200b : "COMND LE_Set_Set_Scan_Parameters",
        0x200c : "COMND LE_Set_Scan_Enable",
        0x200d : "COMND LE_Create_Connection",
        0x200e : "COMND LE_Create_Connection_Cancel ",
        0x200f : "COMND LE_Read_White_List_Size",
        0x2010 : "COMND LE_Clear_White_List",
        0x2011 : "COMND LE_Add_Device_To_White_List",
        0x2012 : "COMND LE_RemoveDevice_From_White_List",
        0x2013 : "COMND LE_Connection_Update",
        0x2014 : "COMND LE_Set_Host_Channel_Classification",
        0x2015 : "COMND LE_Read_Channel_Map",
        0x2016 : "COMND LE_Read_Remote_Used_Features",
        0x2017 : "COMND LE_Encrypt",
        0x2018 : "COMND LE_Rand",
        0x2019 : "COMND LE_Start_Encryption",
        0x201a : "COMND LE_Long_Term_Key_Request_Reply",
        0x201b : "COMND LE_Long_Term_Key_Request_Negative_Reply",
        0x201c : "COMND LE_Read_Supported_States",
        0x201d : "COMND LE_Receiver_Test",
        0x201e : "COMND LE_Transmitter_Test",
        0x201f : "COMND LE_Test_End",
        0x2020 : "COMND LE_Remote_Connection_Parameter_Request_Reply",
        0x2021 : "COMND LE_Remote_Connection_Parameter_Request_Negative_Reply",
        0xfc7e : "COMND VSC_Write_Dynamic_SCO_Routing_Change",
        0xfc57 : "COMND VSC_Write_High_Priority_Connection",
        0xfc4c : "COMND VSC_Write_RAM",
        0xfc4d : "COMND VSC_Read_RAM",
        0xfc4e : "COMND VSC_Launch_RAM",
        0xfc18 : "COMND VSC_Update_UART_Baud_Rate",
        0xfc01 : "COMND VSC_Write_BD_ADDR",
        0xfc1c : "COMND VSC_Write_SCO_PCM_Int_Param",
        0xfc27 : "COMND VSC_Set_Sleepmode_Param",
        0xfc1e : "COMND VSC_Write_PCM_Data_Format_Param",
        0xfc2e : "COMND VSC_Download_Minidriver",
        0xfd53 : "COMND VSC_BLE_VENDOR_CAP",
        0xfd54 : "COMND VSC_BLE_MULTI_ADV",
        0xfd56 : "COMND VSC_BLE_BATCH_SCAN",
        0xfd57 : "COMND VSC_BLE_ADV_FILTER",
        0xfd58 : "COMND VSC_BLE_TRACK_ADV",
        0xfd59 : "COMND VSC_BLE_ENERGY_INFO"
    }

    @staticmethod
    def from_data(data):
        return HCI_Cmd(u16(data[0:2]), ord(data[2]), data[3:])

    def __init__(self, opcode, length, data):
        HCI.__init__(self, HCI.HCI_CMD)
        self.opcode = opcode
        self.length = length
        self.data = data

    def __str__(self):
        parent = HCI.__str__(self)
        cmdname = "unknown"
        if self.opcode in self.HCI_CMD_STR:
            cmdname = self.HCI_CMD_STR[self.opcode]
        return parent + "<0x%04x %s (len=%d): %s>" % (self.opcode, cmdname, self.length, self.data[0:16].encode('hex'))

class HCI_Acl(HCI):

    @staticmethod
    def from_data(data):
        handle = u16(unbits(bits_str(data[0:2])[0:12].rjust(16,'0')))
        pb = u8(unbits(bits_str(data[1:2])[4:6].rjust(8,'0')))
        bc = u8(unbits(bits_str(data[1:2])[6:8].rjust(8,'0')))
        return HCI_Acl(handle, pb, bc, u16(data[2:4]), data[4:])

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
        handle = u16(unbits(bits_str(data[0:2])[0:12].rjust(16,'0')))
        ps = u8(unbits(bits_str(data[1:2])[4:6].rjust(8,'0')))
        return HCI_Sco(handle, ps, u16(data[2]), data[3:])

    def __init__(self, handle, ps, length, data):
        HCI.__init__(self, HCI.SCO_DATA)
        self.handle = handle
        self.ps = ps
        self.length = length
        self.data = data

class HCI_Event(HCI): 

    HCI_EVENT_STR = {
        0x01 : "EVENT Inquiry_Complete",
        0x02 : "EVENT Inquiry_Result",
        0x03 : "EVENT Connection_Complete",
        0x04 : "EVENT Connection_Request",
        0x05 : "EVENT Disconnection_Complete",
        0x06 : "EVENT Authentication_Complete",
        0x07 : "EVENT Remote_Name_Request_Complete",
        0x08 : "EVENT Encryption_Change",
        0x09 : "EVENT Change_Connection_Link_Key_Complete",
        0x0a : "EVENT Master_Link_Key_Complete",
        0x0b : "EVENT Read_Remote_Supported_Features_Complete",
        0x0c : "EVENT Read_Remote_Version_Information_Complete",
        0x0d : "EVENT QoS_Setup_Complete",
        0x0e : "EVENT Command_Complete",
        0x0f : "EVENT Command_Status",
        0x10 : "EVENT Hardware_Error",
        0x11 : "EVENT Flush_Occurred",
        0x12 : "EVENT Role_Change",
        0x13 : "EVENT Number_Of_Completed_Packets",
        0x14 : "EVENT Mode_Change",
        0x15 : "EVENT Return_Link_Keys",
        0x16 : "EVENT PIN_Code_Request",
        0x17 : "EVENT Link_Key_Request",
        0x18 : "EVENT Link_Key_Notification",
        0x19 : "EVENT Loopback_Command",
        0x1a : "EVENT Data_Buffer_Overflow",
        0x1b : "EVENT Max_Slots_Change",
        0x1c : "EVENT Read_Clock_Offset_Complete",
        0x1d : "EVENT Connection_Packet_Type_Changed",
        0x1e : "EVENT QoS_Violation",
        0x20 : "EVENT Page_Scan_Repetition_Mode_Change",
        0x21 : "EVENT Flow_Specification_Complete",
        0x22 : "EVENT Inquiry_Result_with_RSSI",
        0x23 : "EVENT Read_Remote_Extended_Features_Complete",
        0x2c : "EVENT Synchronous_Connection_Complete",
        0x2d : "EVENT Synchronous_Connection_Changed",
        0x2e : "EVENT Sniff_Subrating",
        0x2f : "EVENT Extended_Inquiry_Result",
        0x30 : "EVENT Encryption_Key_Refresh_Complete",
        0x31 : "EVENT IO_Capability_Request",
        0x32 : "EVENT IO_Capability_Response",
        0x33 : "EVENT User_Confirmation_Request",
        0x34 : "EVENT User_Passkey_Request",
        0x35 : "EVENT Remote_OOB_Data_Request",
        0x36 : "EVENT Simple_Pairing_Complete",
        0x38 : "EVENT Link_Supervision_Timeout_Changed",
        0x39 : "EVENT Enhanced_Flush_Complete",
        0x3b : "EVENT User_Passkey_Notification",
        0x3c : "EVENT Keypress_Notification",
        0x3d : "EVENT Remote_Host_Supported_Features_Notification",
        0x3e : "EVENT LE_Meta_Event",
        0x40 : "EVENT Physical_Link_Complete",
        0x41 : "EVENT Channel_Selected",
        0x42 : "EVENT Disconnection_Physical_Link_Complete",
        0x43 : "EVENT Physical_Link_Loss_Early_Warning",
        0x44 : "EVENT Physical_Link_Recovery",
        0x45 : "EVENT Logical_Link_Complete",
        0x46 : "EVENT Disconnection_Logical_Link_Complete",
        0x47 : "EVENT Flow_Spec_Modify_Complete",
        0x48 : "EVENT Number_Of_Completed_Data_Blocks",
        0x4c : "EVENT Short_Range_Mode_Change_Complete",
        0x4d : "EVENT AMP_Status_Change",
        0x49 : "EVENT AMP_Start_Test",
        0x4a : "EVENT AMP_Test_End",
        0x4b : "EVENT AMP_Receiver_Report",
        0x4e : "EVENT Triggered_Clock_Capture",
        0x4f : "EVENT Synchronization_Train_Complete",
        0x50 : "EVENT Synchronization_Train_Received",
        0x51 : "EVENT Connectionless_Slave_Broadcast_Receive",
        0x52 : "EVENT Connectionless_Slave_Broadcast_Timeout",
        0x53 : "EVENT Truncated_Page_Complete",
        0x54 : "EVENT Slave_Page_Response_Timeout",
        0x55 : "EVENT Connectionless_Slave_Broadcast_Channel_Map_Change",
        0x56 : "EVENT Inquiry_Response_Notification",
        0x57 : "EVENT Authenticated_Payload_Timeout_Expired",
    }

    @staticmethod
    def from_data(data):
        return HCI_Event(ord(data[0]), ord(data[1]), data[2:])

    def __init__(self, event_code, length, data):
        HCI.__init__(self, HCI.HCI_EVT)
        self.event_code = event_code
        self.length = length
        self.data = data

    def __str__(self):
        parent = HCI.__str__(self)
        eventname = "unknown"
        if self.event_code in self.HCI_EVENT_STR:
            eventname = self.HCI_EVENT_STR[self.event_code]
        return parent + "<0x%02x %s (len=%d): %s>" % (self.event_code, eventname, self.length, self.data[0:16].encode('hex'))

HCI_UART_TYPE_CLASS = {
        HCI.HCI_CMD :  HCI_Cmd,
        HCI.ACL_DATA : HCI_Acl,
        HCI.SCO_DATA : HCI_Sco,
        HCI.HCI_EVT :  HCI_Event
    }

class HCI_TX:
    def __init__(self, s_inject):
        self.s_inject = s_inject

    def sendCmd(self, opcode, data):
        payload = p16(opcode) + p8(len(data)) + data

        # Prepend UART TYPE and length
        out = p8(HCI.HCI_CMD) + p16(len(payload)) + payload
        self.s_inject.send(out)

    def sendReadRamCmd(self, addr, length):
        self.sendCmd(0xfc4d, p32(addr) + p8(length))


def parse_hci_packet(data):
    return HCI.from_data(data)
