from builtins import object
from typing import Any

from internalblue.utils.packing import u8, u16, u32


class ConnectionInformation(object):
    connection_handle = 0
    connection_number = 0
    master_of_connection = False
    remote_name_address = 0
    remote_address = None
    id: bytearray
    public_rand = None
    extended_lmp_feat = None
    link_key = None
    tx_pwr_lvl_dBm = 0
    effective_key_len = 0
    host_supported_feat = None

    def __init__(
        self,
        connection_number,
        remote_address,
        remote_name_address,
        master_of_connection,
        connection_handle,
        public_rand,
        effective_key_len,
        link_key,
        tx_pwr_lvl_dBm,
        extended_lmp_feat,
        host_supported_feat,
        id,
    ):
        self.connection_number = connection_number
        self.remote_address = remote_address
        self.remote_name_address = remote_name_address
        self.master_of_connection = master_of_connection
        self.connection_handle = connection_handle
        self.public_rand = public_rand
        self.effective_key_len = effective_key_len
        self.link_key = link_key
        self.tx_pwr_lvl_dBm = tx_pwr_lvl_dBm
        self.extended_lmp_feat = extended_lmp_feat
        self.host_supported_feat = host_supported_feat
        self.id = id

    @staticmethod
    def from_connection_buffer(connection):

        # Possible TODO: Convert this to a Katai Struct parser with a proper .ksy grammar.
        return ConnectionInformation(
            u32(connection[:4]),
            connection[0x28:0x2E][::-1],
            u32(connection[0x4C:0x50]),
            u32(connection[0x1C:0x20]) & 1 << 15 == 0,
            u16(connection[0x64:0x66]),
            connection[0x78:0x88],
            u8(connection[0xA7:0xA8]),
            connection[0x68 : 0x68 + u8(connection[0xA7:0xA8])],
            u8(connection[0x9C:0x9D]) - 127,
            connection[0x30:0x38],
            connection[0x38:0x40],
            connection[0x0C:0x0D],
        )
        # For some reason the following doesn't work because some attributes like link_key end up as one element tuples
        # connection_number = u32(connection[:4])
        # remote_address = connection[0x28:0x2E][::-1],
        # remote_name_address = u32(connection[0x4C:0x50])
        # master_of_connection = u32(connection[0x1C:0x20]) & 1 << 15 == 0
        # connection_handle = u16(connection[0x64:0x66])
        # public_rand = connection[0x78:0x88]
        # effective_key_len = u8(connection[0xa7:0xa8])
        # link_key = connection[0x68:0x68 + effective_key_len],
        # tx_pwr_lvl_dBm = u8(connection[0x9c:0x9d]) - 127,
        # extended_lmp_feat = connection[0x30:0x38]
        # host_supported_feat = connection[0x38:0x40]
        # id = connection[0x0c:0x0d]
        # return ConnectionInformation(connection_number, remote_address, remote_name_address, master_of_connection,
        #                              connection_handle,
        #                              public_rand, effective_key_len, link_key, tx_pwr_lvl_dBm, extended_lmp_feat,
        #                              host_supported_feat, id)

    def __getitem__(self, item):
        # type: (str) -> Any
        return vars(self)[item]
