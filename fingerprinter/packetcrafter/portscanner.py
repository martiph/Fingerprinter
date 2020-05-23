import socket
import sys
from datetime import datetime

# Some parts of the code were copied from here (25.04.2020):
# https://www.pythonforbeginners.com/code-snippets-source-code/port-scanner-in-python/

# Display a banner with information about how to use the portscanner, if the user uses the script wrong.
if len(sys.argv) != 3:
    print("-"*80)
    print("Usage of Fingerprinter.portscanner.py:\npython ./portscanner.py <target-ip-address> <highest_port_in_range>")
    print("Example:\n./portscanner.py 127.0.0.1 1000\nThis will scan \'localhost\' in portrange 1 to 1000 (reserved "
          "ports).")
    print("-"*80)
    sys.exit()
else:
    remote_server = sys.argv[1]
    port_number = sys.argv[2]
    # TODO: Do some input validation on the ip address and the port number

remote_server_ip = socket.gethostbyname(remote_server)

# Print a banner with information about the host
print("-" * 80)
print("Please wait, scanning remote host {0} in port range 1 to {1}".format(remote_server_ip, port_number))
print("-" * 80)

# Check what time the scan started
t1 = datetime.now()

# Using the range function to specify ports (including error handling)
try:
    port_number = int(port_number) + 1
    for port in range(1, port_number):
        # TODO: Add socket_raw to build custom requests
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remote_server_ip, port))
        if result == 0:
            print("Port {}:\tOpen".format(port))
        else:
            print("Port {}:\tClosed".format(port))
        sock.close()

except KeyboardInterrupt:
    print("You pressed Ctrl+C\nLeaving portscanner...")
    sys.exit()

except socket.gaierror:
    print("Hostname could not be resolved.\nLeaving portscanner...")
    sys.exit()

except socket.error:
    print("Couldn't connect to server.\nLeaving portscanner...")
    sys.exit()

# Checking the time again
t2 = datetime.now()

# Calculates the difference of time, to see how long it took to run the script
total = t2 - t1

# Printing the information to screen
print("Scanning Completed in: {0}".format(total))
