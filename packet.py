from bitstring import BitArray


class packet():
    def __init__(self):
        self.content = {
        "OP": bytes([0x00]),
        "HTYPE": bytes([0x00]),
        "HLEN":bytes([0x00]),
        "HOPS": bytes([0x00]),
        "XID": bytes([0x00, 0x00, 0x00, 0x00]),
        "SECS": bytes([0x00, 0x00]),
        "FLAGS": bytes([0x00, 0x00]),
        "CIADDR": bytes([0x00, 0x00, 0x00, 0x00]),
        "YIADDR": bytes([0x00, 0x00, 0x00, 0x00]),
        "SIADDR": bytes([0x00, 0x00, 0x00, 0x00]),
        "GIADDR": bytes([0x00, 0x00, 0x00, 0x00]),
        "CHADDR1": bytes([0x00, 0x00, 0x00, 0x00]),
        "CHADDR2": bytes([0x00, 0x00, 0x00, 0x00]),
        "CHADDR3": bytes([0x00, 0x00, 0x00, 0x00]),
        "CHADDR4": bytes([0x00, 0x00, 0x00, 0x00]),
        "CHADDR5": bytes(0x00),
        "Magiccookie": bytes([0x00, 0x00, 0x00, 0x00]),
        "DHCPOptions1": bytes([0x00, 0x00, 0x00]),
        "DHCPOptions2": bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        }


    def decode(self, byte_packet):
        

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