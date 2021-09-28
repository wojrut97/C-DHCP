# Master's Thesis
# Analysis of security and privacy of IP network auto-configuration services.
# Gdansk University of Technology 2021
# Author: Wojciech Rutkowski

import configparser

# Configuration class for all DHCP hosts 

class config:
    def __init__(self, config_file):
        config = configparser.ConfigParser()
        if config_file == "client_dhcp.conf":
            try:
                config.read(config_file)
                self.requested_ip = config["CLIENT"]["requested_ip"]
                self.lease_time = config["CLIENT"]["lease_time"]
                self.interface = config["CLIENT"]["interface"]
            except:
                print("Error reading client config file")
        elif config_file == "server_dhcp.conf":
            try:
                config.read(config_file)
                self.lease_time = config["SERVER"]["lease_time"]
                self.interface = config["SERVER"]["interface"]
                self.network_ip = config["SERVER"]["network_ip"]
                self.allowlist = config["SERVER"]["allowlist"]
            except:
                print("Error reading server config file")
        else:
            print("Wrong file name")
        

        



