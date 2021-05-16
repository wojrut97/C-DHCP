import random
import struct
import time 

class Packet():
    def __init__(self):
        self._OP_size = 1
        self._HTYPE_size = 1
        self._HLEN_size = 1
        self._HOPS_size = 1
        self._XID_size = 4
        self._SECS_size = 2
        self._FLAGS_size = 2
        self._CIADDR_size = 4
        self._YIADDR_size = 4
        self._SIADDR_size = 4
        self._GIADDR_size = 4
        self._CHADDR_size = 16
        self._SNAME_size = 64
        self._FILE_size = 128
        self._Magiccookie_size = 4
        self._DHCPOptions_size = 0

        self._DHCPOptions_dict = {}

        self.OP = self.fillWithZeros(self._OP_size)
        self.HTYPE = self.fillWithZeros(self._HTYPE_size)
        self.HLEN = self.fillWithZeros(self._HLEN_size)
        self.HOPS = self.fillWithZeros(self._HOPS_size)
        self.XID = self.fillWithZeros(self._XID_size)
        self.SECS = self.fillWithZeros(self._SECS_size)
        self.FLAGS = self.fillWithZeros(self._FLAGS_size)
        self.CIADDR = self.fillWithZeros(self._CIADDR_size)
        self.YIADDR = self.fillWithZeros(self._YIADDR_size)
        self.SIADDR = self.fillWithZeros(self._SIADDR_size)
        self.GIADDR = self.fillWithZeros(self._GIADDR_size)
        self.CHADDR = self.fillWithZeros(self._CHADDR_size)
        self.SNAME = self.fillWithZeros(self._SNAME_size)
        self.FILE = self.fillWithZeros(self._FILE_size)
        self.Magiccookie = self.fillWithZeros(self._Magiccookie_size)
        self.DHCPOptions = self.fillWithZeros(self._DHCPOptions_size)


    def fillWithZeros(self, size):
        zero = 0
        return zero.to_bytes(size, "big")

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
        self.CHADDR = byte_packet[28:44]
        self.SNAME = byte_packet[44:108]
        self.FILE = byte_packet[108:236]
        self.Magiccookie = byte_packet[236:240]
        self.DHCPOptions = byte_packet[240:-1]

        self.byteOptionsToDict()
        return self

    def isPacketData(self, key):
        return key[0] != "_"

    def print(self):
        for key in self.__dict__:
            if self.isPacketData(key):
                print(key, ": ", self.__dict__[key])

    def compress(self):
        packet = bytes()
        self.dictOptionsToByte()
        for key in self.__dict__:
            if self.isPacketData(key):
                packet += self.__dict__[key]
        return packet

    def isOptionSupported(self, tag):
        return tag in self._supported_options.keys()

    def macAlign(self, mac):
        zeros = self.fillWithZeros(10)
        return mac + zeros

    def createOption(self, tag, value):
        if type(value) == int:
            length = 1
            option = bytearray([tag, length] + [value])
        elif type(value) == list:
            length = len(value)
            option = bytearray([tag, length] + value)
        elif type(value) == str:
            length = len(value)
            option = bytearray([tag, length] + list(value))
        else:
            print("Unsupported option type, please provide int, str or list.")
            return
        return option

    def addOption(self, tag, value):
        if tag not in self._DHCPOptions_dict:
            self._DHCPOptions_dict[tag] = value

    def modifyOption(self, tag, value):
        if tag in self._DHCPOptions_dict:
            self._DHCPOptions_dict[tag] = value

    def delOption(self, tag):
        if tag in self._DHCPOptions_dict:
            del self._DHCPOptions_dict[tag]

    def printAllOptions(self):
        for byte in self.DHCPOptions:
            print(byte)

    def clearOptions(self):
        self.DHCPOptions = self.fillWithZeros(self._DHCPOptions_size)

    def purgeOptions(self):
        self._DHCPOptions_dict.clear()

    def byteOptionsToDict(self):
        idx = 0
        tag = self.DHCPOptions[idx]
        while tag != 0 and tag != 255 and idx != len(self.DHCPOptions):
            if tag not in self._DHCPOptions_dict:
                length = self.DHCPOptions[idx + 1]
                value = self.DHCPOptions[idx + 2 : idx + 2 + length]
                value_as_list = self.byteArrayToList(value)
                self._DHCPOptions_dict[tag] = value_as_list
            idx = idx + 2 + length
            tag = self.DHCPOptions[idx]
            
    def byteArrayToList(self, value):
        value_as_list = []
        for i in value:
            value_as_list.append(i)
        return value_as_list

    def dictOptionsToByte(self):
        self.clearOptions()
        for tag, value in self._DHCPOptions_dict.items():
            print("adding: ", tag, value)
            option = self.createOption(tag, value)
            self.DHCPOptions += option