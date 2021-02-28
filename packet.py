

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
        self.content["OP"] = byte_packet[0]
        self.content["HTYPE"] = byte_packet[1]
        self.content["HLEN"] = byte_packet[2]
        self.content["HOPS"] = byte_packet[3]
        self.content["XID"] = int.from_bytes(byte_packet[4:7], "big")
        self.content["SECS"] = int.from_bytes(byte_packet[8:9], "big")
        self.content["FLAGS"] = int.from_bytes(byte_packet[10:11], "big")
        self.content["CIADDR"] = int.from_bytes(byte_packet[12:15], "big")
        self.content["YIADDR"] = int.from_bytes(byte_packet[16:19], "big")
        self.content["SIADDR"] = int.from_bytes(byte_packet[20:23], "big")
        self.content["GIADDR"] = int.from_bytes(byte_packet[24:27], "big")
        self.content["CHADDR1"] = int.from_bytes(byte_packet[28:31], "big")
        self.content["CHADDR2"] = int.from_bytes(byte_packet[32:35], "big")
        self.content["CHADDR3"] = int.from_bytes(byte_packet[36:39], "big")
        self.content["CHADDR4"] = int.from_bytes(byte_packet[40:43], "big")
        self.content["CHADDR5"] = byte_packet[44]
        self.content["Magiccookie"] = int.from_bytes(byte_packet[45:48], "big")
        self.content["DHCPOptions1"] = int.from_bytes(byte_packet[49:51], "big")
        self.content["DHCPOptions2"] = int.from_bytes(byte_packet[52:57], "big")
        
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