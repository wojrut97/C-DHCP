from bitstring import BitArray


class packet():
    def __init__(self):
        self.content = {
        "OP": bytes([0x00]),                                            #1
        "HTYPE": bytes([0x00]),                                         #1
        "HLEN":bytes([0x00]),                                           #1
        "HOPS": bytes([0x00]),                                          #1
        "XID": bytes([0x00, 0x00, 0x00, 0x00]),                         #4
        "SECS": bytes([0x00, 0x00]),                                    #2
        "FLAGS": bytes([0x00, 0x00]),                                   #2
        "CIADDR": bytes([0x00, 0x00, 0x00, 0x00]),                      #4
        "YIADDR": bytes([0x00, 0x00, 0x00, 0x00]),                      #4
        "SIADDR": bytes([0x00, 0x00, 0x00, 0x00]),                      #4
        "GIADDR": bytes([0x00, 0x00, 0x00, 0x00]),                      #4
        "CHADDR1": bytes([0x00, 0x00, 0x00, 0x00]),                     #4
        "CHADDR2": bytes([0x00, 0x00, 0x00, 0x00]),                     #4
        "CHADDR3": bytes([0x00, 0x00, 0x00, 0x00]),                     #4
        "CHADDR4": bytes([0x00, 0x00, 0x00, 0x00]),                     #4
        "CHADDR5": bytes(0x00),                                         #1
        "Magiccookie": bytes([0x00, 0x00, 0x00, 0x00]),                 #4
        "DHCPOptions1": bytes([0x00, 0x00, 0x00]),                      #3
        "DHCPOptions2": bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])     #6      = 58
        }


    def decode(self, byte_packet):
        byte = 8
        mask1 = 0xFF
        mask2 = 0xFFFF
        mask3 = 0xFFFFFF
        mask4 = 0xFFFFFFFF
        mask6 = 0xFFFFFFFFFFFF
        int_packet = int.from_bytes(byte_packet, "big")

        self.content["OP"] = int_packet & (mask1 << (57 * byte))
        self.content["HTYPE"] = int_packet & (mask1 << (56 * byte))
        self.content["HLEN"] = int_packet & (mask1 << (55 * byte))
        self.content["HOPS"] = int_packet & (mask1 << (54 * byte))
        self.content["XID"] = int_packet & (mask4 << (50 * byte))
        self.content["SECS"] = int_packet & (mask2 << (48 * byte))
        self.content["FLAGS"] = int_packet & (mask2 << (46 * byte))
        self.content["CIADDR"] = int_packet & (mask4 << (42 * byte))
        self.content["YIADDR"] = int_packet & (mask4 << (38 * byte))
        self.content["SIADDR"] = int_packet & (mask4 << (34 * byte))
        self.content["GIADDR"] = int_packet & (mask4 << (30 * byte))
        self.content["CHADDR1"] = int_packet & (mask4 << (26 * byte))
        self.content["CHADDR2"] = int_packet & (mask4 << (22 * byte))
        self.content["CHADDR3"] = int_packet & (mask4 << (18 * byte))
        self.content["CHADDR4"] = int_packet & (mask4 << (14 * byte)) 
        self.content["CHADDR5"] = int_packet & (mask1 << (13 * byte))
        self.content["Magiccookie"] = int_packet & (mask4 << (9 * byte))
        self.content["DHCPOptions1"] = int_packet & (mask3 << (6 * byte))
        self.content["DHCPOptions2"] = int_packet & (mask6)
        
        return self.content

    def compress(self):
        packet = bytes()
        for key in self.content:
            packet += self.content[key]
        return packet


    def DHCP_discover(self):
        self.content["OP"] = bytes([0x01])
        self.content["HTYPE"] = bytes([0x01])
        self.content["HLEN"] = bytes([0x06])
        self.content["HOPS"] = bytes([0x00])
        self.content["XID"] = bytes([0x39, 0x03, 0xF3, 0x26])
        self.content["SECS"] = bytes([0x00, 0x00])
        self.content["FLAGS"] = bytes([0x00, 0x00])
        self.content["CIADDR"] = bytes([0x00, 0x00, 0x00, 0x00])
        self.content["YIADDR"] = bytes([0x00, 0x00, 0x00, 0x00])
        self.content["SIADDR"] = bytes([0x00, 0x00, 0x00, 0x00])
        self.content["GIADDR"] = bytes([0x00, 0x00, 0x00, 0x00])
        self.content["CHADDR1"] = bytes([0x00, 0x05, 0x3C, 0x04]) 
        self.content["CHADDR2"] = bytes([0x8D, 0x59, 0x00, 0x00]) 
        self.content["CHADDR3"] = bytes([0x00, 0x00, 0x00, 0x00]) 
        self.content["CHADDR4"] = bytes([0x00, 0x00, 0x00, 0x00]) 
        self.content["CHADDR5"] = bytes([0x12])
        self.content["Magiccookie"] = bytes([0x63, 0x82, 0x53, 0x63])
        self.content["DHCPOptions1"] = bytes([0x53 , 0x01 , 0x01])
        self.content["DHCPOptions2"] = bytes([0x50 , 0x04 , 0xC0, 0xA8, 0x01, 0x64])

        return self.compress()