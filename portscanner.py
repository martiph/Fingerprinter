import socket
import sys
from datetime import datetime

# copied some things from here: https://www.pythonforbeginners.com/code-snippets-source-code/port-scanner-in-python/

# Ask for server and ports to scan
remote_server = input("Enter a remote host to scan: ")
port_number = input("Enter the highest port number you want to scan: ")
remote_server_ip = socket.gethostbyname(remote_server)

# Print a banner with information about the host
print("-" * 60)
print("Please wait, scanning remote host {0} in port range 1 to {1}".format(remote_server_ip, port_number))
print("-" * 60)

# Check what time the scan started
t1 = datetime.now()

# Using the range function to specify ports (here it will scans all ports between 1 and 1024)

# We also put in some error handling for catching errors

try:
    port_number = int(port_number) + 1
    for port in range(1, port_number):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remote_server_ip, port))
        if result == 0:
            print("Port {}: 	 Open".format(port))
        else:
            print("Port {}: 	 Closed".format(port))
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
print("Scanning Completed in: {}", total)
