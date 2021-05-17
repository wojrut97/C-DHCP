import argparse
from server import Server
from client import Client
import time

def main():
    parser = argparse.ArgumentParser(description="Choose C-DHCP mode.")
    parser.add_argument("-s", "--server", help="run C-DHCP in server mode", action="store_true")
    parser.add_argument("-c", "--client", help="run C-DHCP in client mode", action="store_true")
    args = parser.parse_args()

    if args.server:
        print("Running in server mode.")
        CDHCP_server = Server(True)
        CDHCP_server.awaitMessage()
        if CDHCP_server.verifyAuthentication() == True:
            CDHCP_server.sendOffer()
            CDHCP_server.awaitMessage()
            if CDHCP_server.verifyAuthentication() == True:
                CDHCP_server.sendAck()
    elif args.client:
        print("Running in client mode.")
        CDHCP_client = Client(True)
        CDHCP_client.sendDiscover()
        CDHCP_client.awaitMessage()
        if CDHCP_client.verifyAuthentication() == True:
            CDHCP_client.sendRequest()
            CDHCP_client.awaitMessage()

if __name__ == "__main__":
    main()