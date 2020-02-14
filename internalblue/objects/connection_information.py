class Connection_Information:
    connection_handle = 0
    connection_number = 0
    master_of_connection = False
    remote_name_address = 0
    remote_address = None
    id = None
    public_rand = None
    extended_lmp_feat = None
    link_key = None
    tx_pwr_lvl_dBm = 0
    effective_key_len = 0
    host_supported_feat = None

    def __init__(self, connection_number, remote_address, remote_name_address, master_of_connection, connection_handle,
                 public_rand, effective_key_len, link_key, tx_pwr_lvl_dBm, extended_lmp_feat, host_supported_feat, id):
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

    def __getitem__(self, item):
        # type: (str) -> Any
        return vars(self)[item]