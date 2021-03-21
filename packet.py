import random


class packet():
    def __init__(self):
        self.OP = bytes([0x00]),                                            #1
        self.HTYPE = bytes([0x00]),                                         #1
        self.HLEN =bytes([0x00]),                                           #1
        self.HOPS = bytes([0x00]),                                          #1
        self.XID = bytes([0x00, 0x00, 0x00, 0x00]),                         #4
        self.SECS = bytes([0x00, 0x00]),                                    #2
        self.FLAGS = bytes([0x00, 0x00]),                                   #2
        self.CIADDR = bytes([0x00, 0x00, 0x00, 0x00]),                      #4
        self.YIADDR = bytes([0x00, 0x00, 0x00, 0x00]),                      #4
        self.SIADDR = bytes([0x00, 0x00, 0x00, 0x00]),                      #4
        self.GIADDR = bytes([0x00, 0x00, 0x00, 0x00]),                      #4
        self.CHADDR1 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),         #6
        self.CHADDR2 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),         #6
        self.CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00]),                     #4
        self.Magiccookie = bytes([0x00, 0x00, 0x00, 0x00]),                 #4
        self.DHCPOptions1 = bytes([0x00, 0x00, 0x00]),                      #3
        self.DHCPOptions2 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])     #6      = 57


    def decode(self, byte_packet):
        self.OP = byte_packet[0]
        self.HTYPE = byte_packet[1]
        self.HLEN = byte_packet[2]
        self.HOPS = byte_packet[3]
        self.XID = int.from_bytes(byte_packet[4:7], "big")
        self.SECS = int.from_bytes(byte_packet[8:9], "big")
        self.FLAGS = int.from_bytes(byte_packet[10:11], "big")
        self.CIADDR = int.from_bytes(byte_packet[12:15], "big")
        self.YIADDR = int.from_bytes(byte_packet[16:19], "big")
        self.SIADDR = int.from_bytes(byte_packet[20:23], "big")
        self.GIADDR = int.from_bytes(byte_packet[24:27], "big")
        self.CHADDR1 = int.from_bytes(byte_packet[28:33], "big")
        self.CHADDR2 = int.from_bytes(byte_packet[34:39], "big")
        self.CHADDR3 = int.from_bytes(byte_packet[40:43], "big")
        self.Magiccookie = int.from_bytes(byte_packet[44:47], "big")
        self.DHCPOptions1 = int.from_bytes(byte_packet[48:50], "big")
        self.DHCPOptions2 = int.from_bytes(byte_packet[51:56], "big")
        
        return self

    def print(self):
        for key in self.__dict__:
            print(key, ": ", self.__dict__[key])

    def compress(self):
        packet = bytes()
        for key in self.__dict__:
            packet += self.__dict__[key]
        return packet
