from scapy.all import *
from netaddr import *
import random

def rand_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
        )

def ipv6_link_local(mac):
    splitted = mac.split(":")
    link_local = "fe80::"
    link_local += splitted[0] + splitted[1] + ":"
    link_local += splitted[2] + "ff:"
    link_local += "fe" + splitted[3]
    link_local += ":" + splitted[4] + splitted[5]
    return link_local

def main():
    l2 = Ether()
    l3 = IPv6()
    l4 = UDP()
    sol = DHCP6_Solicit()
    rc = DHCP6OptRapidCommit()
    opreq = DHCP6OptOptReq()
    et = DHCP6OptElapsedTime()
    cid = DHCP6OptClientId()
    iana = DHCP6OptIA_NA()
    rc.optlen = 0
    opreq.optlen = 4
    iana.optlen = 12
    iana.T1 = 0
    iana.T2 = 0
    cid.optlen = 10
    macdst = "ff:ff:ff:ff:ff:ab"
    l2.dst = macdst
    l3.dst = "ff02::1:2"
    l4.sport = 546
    l4.dport = 547

    my_mac = rand_mac()
    my_ipv6 = ipv6_link_local(my_mac)
    l2.src = my_mac
    l3.src = my_ipv6
    sol.trid = random.randint(0, 0xffffff)
    cid.duid = ("00030001" + str(EUI(my_mac)).replace("-","")) # decode("hex")?

    # packet = l2/l3/l4/sol/iana/rc/et/cid/opreq
    packet = l2/l3/l4/sol

    try:
        answer = srp(packet, iface="enp0s8")
    except KeyboardInterrupt:
        print("koniec")

main()