import ipaddress
import json
import os.path
import sys
import urllib.request
from datetime import datetime

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

current_date = datetime.now()
current_date = current_date.strftime("%Y%m%d")
print(current_date)
#azure_url = "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_" + \
#            str(current_date) + ".json"
azure_url = "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20200504.json"
# TODO get the latest version of the file (date is in the filename)
aws_url = "https://ip-ranges.amazonaws.com/ip-ranges.json"

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
    urllib.request.urlretrieve(azure_url, azure_file_path)
    azure_file = open(azure_file_path, "r")
    azure_ip_dictionary = json.load(azure_file)
    for ip_group in azure_ip_dictionary["values"]:
        for ip_addr in ip_group["properties"]["addressPrefixes"]:
            azure_ip_subnets.append(ipaddress.ip_network(ip_addr))
except FileNotFoundError:
    print("Please make sure you have read/write permissions on files in " + script_location)
finally:
    azure_file.close()

############################################################################################
# Download AWS IP-Address file. Create a list with subnets-addresses used by AWS.
############################################################################################
if os.path.exists(aws_file_path):
    os.remove(aws_file_path)
try:
    urllib.request.urlretrieve(aws_url, aws_file_path)
    aws_file = open(aws_file_path, "r")
    aws_ip_dictionary = json.load(aws_file)
    for subnet_list in aws_ip_dictionary["prefixes"]:
        aws_ip_subnets.append(ipaddress.ip_network(subnet_list["ip_prefix"]))
    for subnet_list in aws_ip_dictionary["ipv6_prefixes"]:
        aws_ip_subnets.append(ipaddress.ip_network(subnet_list["ipv6_prefix"]))
except FileNotFoundError:
    print("Please make sure you have read/write permissions on files in " + script_location)
finally:
    aws_file.close()

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
