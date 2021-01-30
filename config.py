import configparser

class config:
    def __init__(self, config_file):
        if config_file == "client_dhcp.conf":
            self.requested_ip = None
            self.lease_time = None
            self.apply_client_config(config_file)

        elif config_file == "server_dhcp.conf":
            self.lease_time = None
            self.apply_server_config(config_file)

        else:
            print("Wrong file name")
    

    def apply_client_config(self, config_file):
        config = configparser.ConfigParser()
        try:
            config.read(config_file)
            self.requested_ip = config["CLIENT"]["requested_ip"]
            self.lease_time = config["CLIENT"]["lease_time"]
        except:
            print("Error reading client config file")
        

    def apply_server_config(self, config_file):
        config = configparser.ConfigParser()
        try:
            config.read(config_file)
            self.lease_time = config["SERVER"]["lease_time"]

        except:
            print("Error reading server config file")
        

        



