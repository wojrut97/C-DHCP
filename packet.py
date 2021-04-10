import random
import struct
import dhcppython

class Packet():
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
        self.OP = byte_packet[0].to_bytes(1, "big")
        self.HTYPE = byte_packet[1].to_bytes(1, "big")
        self.HLEN = byte_packet[2].to_bytes(1, "big")
        self.HOPS = byte_packet[3].to_bytes(1, "big")
        self.XID = byte_packet[4:8]
        self.SECS = byte_packet[8:10]
        self.FLAGS = byte_packet[10:12]
        self.CIADDR = byte_packet[12:16]
        self.YIADDR = byte_packet[16:20]
        self.SIADDR = byte_packet[20:24]
        self.GIADDR = byte_packet[24:28]
        self.CHADDR1 = byte_packet[28:34]
        self.CHADDR2 = byte_packet[34:40]
        self.CHADDR3 = byte_packet[40:44]
        self.Magiccookie = byte_packet[44:48]
        self.DHCPOptions1 = byte_packet[48:51]
        self.DHCPOptions2 = byte_packet[51:57]
        
        return self

    def print(self):
        for key in self.__dict__:
            print(key, ": ", self.__dict__[key])

    def compress(self):
        packet = bytes()
        for key in self.__dict__:
            packet += self.__dict__[key]
        return packet
