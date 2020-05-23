import ipaddress
import json
import os.path
import sys
import urllib.request
from datetime import date, timedelta

import requests

############################################################################################
# Assign some variables
############################################################################################
script_location = os.path.dirname(os.path.abspath(__file__))

if "\\" in script_location:
    azure_file_path = script_location + "\\azure.json"
    aws_file_path = script_location + "\\aws.json"
elif "/" in script_location:
    azure_file_path = script_location + "/azure.json"
    aws_file_path = script_location + "/aws.json"
else:
    azure_file_path = ""
    aws_file_path = ""

aws_url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
azure_url = ""
# further down in the script is also the url to fetch the json for Azure. It needs to be dynamically created.

azure_ip_subnets = []
aws_ip_subnets = []

############################################################################################
# Check if there is, in addition to the filename, also a commandline parameter
############################################################################################
if len(sys.argv) != 2:
    print("-" * 80)
    print("Usage of Fingerprinter.cloudprovider_detection.py:\n./cloudprovider_detection.py <target-ip-address>\n")
    print("Example:\n./cloudprovider_detection.py 8.8.8.8 \nThis will check if the provided \'ip-address\' is hosted "
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

############################################################################################
# Download Azure IP-Address file. Create a list with subnets-addresses used by Azure.
############################################################################################
if os.path.exists(azure_file_path):
    os.remove(azure_file_path)
try:
    url_exists = False
    counter = 0
    while not url_exists:
        latest_date = date.today() - timedelta(days=counter)
        latest_date = latest_date.strftime("%Y%m%d")
        azure_url = "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63" \
                    "/ServiceTags_Public_" + str(latest_date) + ".json"
        request = requests.get(azure_url)
        if request.status_code == 200:
            url_exists = True
        else:
            counter += 1
    urllib.request.urlretrieve(azure_url, azure_file_path)
    with open(azure_file_path, "r") as azure_file:
        azure_ip_dictionary = json.load(azure_file)
        for ip_group in azure_ip_dictionary["values"]:
            for ip_addr in ip_group["properties"]["addressPrefixes"]:
                azure_ip_subnets.append(ipaddress.ip_network(ip_addr))
except FileNotFoundError:
    print("Please make sure you have read/write permissions on files in " + script_location)

############################################################################################
# Download AWS IP-Address file. Create a list with subnets-addresses used by AWS.
############################################################################################
if os.path.exists(aws_file_path):
    os.remove(aws_file_path)
try:
    urllib.request.urlretrieve(aws_url, aws_file_path)
    with open(aws_file_path, "r") as aws_file:
        aws_ip_dictionary = json.load(aws_file)
        for subnet_list in aws_ip_dictionary["prefixes"]:
            aws_ip_subnets.append(ipaddress.ip_network(subnet_list["ip_prefix"]))
        for subnet_list in aws_ip_dictionary["ipv6_prefixes"]:
            aws_ip_subnets.append(ipaddress.ip_network(subnet_list["ipv6_prefix"]))
except FileNotFoundError:
    print("Please make sure you have read/write permissions on files in " + script_location)

############################################################################################
# Check in which cloud the system is hosted
############################################################################################
for subnet in azure_ip_subnets:
    if remote_ip in subnet:
        print("System is hosted on Azure.")
        sys.exit()

for subnet in aws_ip_subnets:
    if remote_ip in subnet:
        print("System is hosted on AWS.")
        sys.exit()

print("System is neither hosted on Azure nor on AWS. It might be hosted on another cloud providers infrastructure or "
      "on a on-premise infrastructure.")
sys.exit()