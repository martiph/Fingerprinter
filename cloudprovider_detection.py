import requests
import sys
import ipaddress
import json
import urllib.request

# check if there is, in addition to the filename, also a commandline parameter
if len(sys.argv) != 2:
    print("-" * 80)
    print("Usage of Fingerprinter.cloudprovider_detection.py:\n./cloudprovider_detection.py <target-ip-address>\n")
    print("Example:\n./cloudprovider_detection.py 127.0.0.1 \nThis will check if the provided \'ip-address\' is hosted "
          "on Azure or AWS.")
    print("-" * 80)
    sys.exit()
else:
    remote_ip = sys.argv[1]
try:
    remote_ip = ipaddress.ip_address(remote_ip)
except ValueError:
    print("-" * 80)
    print("Please provide the ip address in a proper format.\nAll valid IPv4 and IPv6 addresses are supported.")
    print("-" * 80)
    sys.exit()

# Download Azure IP-Address file
print("Look up if the ip address is in the file of azure ip's")
# TODO maybe get the link dynamically as it may change when the file is updated from microsoft.
azure_url = "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20200427.json"
urllib.request.urlretrieve(azure_url, "./azure.json")
azure_file_content = open("./azure.json", "r")
azure_ips = json.load(azure_file_content)
# foreach ip subnet in the json file, append the subnet to the list azure_ip_subnet
azure_ip_subnets = []

# Download AWS IP-Address file, do the same as for the Azure subnets.
aws_ip_subnets = []

# Check in which cloud the system is hosted
if remote_ip in azure_ip_subnets:
    print("System is hosted on Azure.")
elif remote_ip in aws_ip_subnets:
    print("System is hosted on AWS.")
else:
    print("System is neither hosted on Azure nor on AWS. It might be hosted on another cloud providers infrastructure "
          "or on a on-premise infrastructure.")
    sys.exit()

# TODO fetch ip-addresses from the json-files of AWS and Azure.
#  Check if the ip address in the params-field is in one of the json-files.
#  -> determining the subnetmask of the  ip-address is required.
