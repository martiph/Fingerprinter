import requests
import sys

# check if there is, in addition to the filename, also a commandline parameter
if len(sys.argv) != 2:
    print("-"*80)
    print("Usage of Fingerprinter.cloudprovider_detection.py:\n./cloudprovider_detection.py <target-ip-address>\n")
    print("Example:\n./cloudprovider_detection.py 127.0.0.1 \nThis will check if the provided \'ip-address\' is hosted "
          "on Azure or AWS.")
    print("-"*80)
    sys.exit()
else:
    remote_ip = sys.argv[1]


url = ""
r = requests.get(url, allow_redirects=True)

# TODO fetch ip-addresses from the json-files of AWS and Azure.
# TODO check if the ip address in the params-field is in one of the json-files.

