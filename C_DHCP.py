# Master Thesis
# Analysis of security and privacy of IP network auto-configuration services.
# Gdansk University of Technology 2021
# Author: Wojciech Rutkowski

import argparse
from server import Server
from client import Client
import time

# Entry point for the program
# 4 supported modes:
#        Secure Client    -   python3 C_DHCP.py -c
#        Secure Server    -   python3 C_DHCP.py -s
#        Insecure Client  -   python3 C_DHCP.py -ic
#        Insecure Server  -   python3 C_DHCP.py -is

def main():
    parser = argparse.ArgumentParser(description="Choose C-DHCP mode.")
    parser.add_argument("-s", "--server", help="run C-DHCP in server mode", action="store_true")
    parser.add_argument("-c", "--client", help="run C-DHCP in client mode", action="store_true")
    parser.add_argument("-i", "--insecure", help="run DHCP without encryption", action="store_true")
    args = parser.parse_args()

    if args.insecure:
        print("Running DHCPv6 without encryption!")
        if args.server:
            print("Running in server mode.")
            server = Server()
            server.awaitUnencryptedDHCPv6Message()
            if server.retrievedUnencryptedSolicit():
                server.sendUnencryptedAdvertise()
                server.awaitUnencryptedDHCPv6Message()
                if server.retrievedValidRequest():
                    server.sendUnencryptedReply()

        if args.client:
            print("Running in client mode.")
            client = Client()
            client.sendUnencryptedSolicit()
            client.awaitUnencryptedDHCPv6Message()
            if client.retrievedUnencryptedAdvertise():
                client.sendUnencryptedRequest()
                client.awaitUnencryptedDHCPv6Message()
                if client.retrievedUnencryptedReply():
                    client.assignIP()
            
    else:
        if args.server:
            print("Running in server mode.")
            server = Server()
            while server.got_half_key == False or server.got_certificate == False:
                server.awaitHandshakeMessage()
                if server.got_certificate:
                    server.sendCertificate()
                    server.sendEncryptedHalfKey()
                else:
                    continue
                server.awaitHandshakeMessage()
            server.awaitDHCPv6Message()
            if server.retrievedValidSolicit():
                server.sendAdvertise()
                server.awaitDHCPv6Message()
                if server.retrievedValidRequest():
                    server.sendReply()

        elif args.client:
            print("Running in client mode.")
            client = Client()
            client.sendCertificate()
            client.awaitHandshakeMessage()
            client.awaitHandshakeMessage()
            if client.got_certificate:
                client.sendEncryptedHalfKey()
                client.sendSolicit()
                client.awaitDHCPv6Message()
                if client.retrievedValidAdvertise():
                    client.sendRequest()
                    client.awaitDHCPv6Message()
                    if client.retrievedValidReply():
                        client.assignIP()


if __name__ == "__main__":
    main()