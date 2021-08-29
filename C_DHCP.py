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
        CDHCP_server = Server()
        CDHCP_server.awaitValidHelloMessage()
        CDHCP_server.sendEncryptedHalfKeyAndCertificate()
        CDHCP_server.awaitDHCPv6Message(CDHCP_server.server_port)
        if CDHCP_server.retrievedValidSolicit():
            time.sleep(0.1)
            CDHCP_server.sendAdvertise()
            CDHCP_server.awaitDHCPv6Message(CDHCP_server.server_port)
            if CDHCP_server.retrievedValidRequest():
                time.sleep(0.1)
                CDHCP_server.sendReply()

    elif args.client:
        print("Running in client mode.")
        CDHCP_client = Client()
        CDHCP_client.sendCertRequest()
        CDHCP_client.awaitValidHelloMessage()
        CDHCP_client.sendSolicit()
        CDHCP_client.awaitDHCPv6Message(CDHCP_client.client_port)
        if CDHCP_client.retrievedValidAdvertise():
            time.sleep(0.1)
            CDHCP_client.sendRequest()
            CDHCP_client.awaitDHCPv6Message(CDHCP_client.client_port)
            if CDHCP_client.retrievedValidReply():
                CDHCP_client.assignIP()


if __name__ == "__main__":
    main()