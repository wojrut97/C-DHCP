import argparse
import server
import client

def main():
    parser = argparse.ArgumentParser(description="Choose C-DHCP mode.")
    parser.add_argument("-s", "--server", help="run C-DHCP in server mode", action="store_true")
    parser.add_argument("-c", "--client", help="run C-DHCP in client mode", action="store_true")
    args = parser.parse_args()

    if args.server:
        print("Running in server mode.")
        CDHCP_server = server.server()
        CDHCP_server.await_discover()
    elif args.client:
        print("Running in client mode.")
        CDHCP_client = client.client()
        CDHCP_client.DHCP_discover()

if __name__ == "__main__":
    main()