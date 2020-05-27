import socket
import sys
import threading
import queue
from datetime import datetime
from collections import OrderedDict

q = queue.Queue()


def scan_port_range(remote_server_ip, start_port, end_port):
    for port in range(start_port, end_port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remote_server_ip, port))
        if result == 0:
            q.put((port, "Open"))
            print("Port " + str(port) + " is open.\n")
        else:
            q.put((port, "Closed"))
            print("Port " + str(port) + " is closed.\n")
        sock.close()


# Some parts of the code were copied from here (25.04.2020):
# https://www.pythonforbeginners.com/code-snippets-source-code/port-scanner-in-python/

# Display a banner with information about how to use the portscanner, if the user uses the script wrong.
# if len(sys.argv) != 3:
#     print("-" * 80)
#     print("Usage of Fingerprinter.portscanner.py:\npython ./portscanner.py <target-ip-address> <highest_port_in_range>")
#     print("Example:\n./portscanner.py 127.0.0.1 1000\nThis will scan \'localhost\' in portrange 1 to 1000 (reserved "
#           "ports).")
#     print("-" * 80)
#     sys.exit()
# else:
#     remote_server = sys.argv[1]
#     port_number = sys.argv[2]


def scan(remote_server: str, highest_port_number: int):

    remote_server_ip = socket.gethostbyname(remote_server)
    # Print a banner with information about the host
    print("-" * 80)
    print("Please wait, scanning remote host {0} in port range 1 to {1}".format(remote_server_ip, highest_port_number))
    print("-" * 80)

    # Check what time the scan started
    t1 = datetime.now()
    # Using the range function to specify ports (including error handling)
    try:
        port_number = int(highest_port_number) + 1
        port_range = [1, (port_number // 4), ((port_number // 4) * 2), ((port_number // 4) * 3), port_number]
        thread_list = []

        for i in range(4):
            thread = threading.Thread(target=scan_port_range, args=[remote_server, port_range[i], port_range[i + 1]])
            thread_list.append(thread)
            thread.start()

        for thread in thread_list:
            thread.join()

        port_dictionary = {}
        while not q.empty():
            port_status = q.get()
            port_dictionary[port_status[0]] = port_status[1]
        port_dictionary = dict(sorted((port_dictionary.items())))

        # Checking the time again
        t2 = datetime.now()

        # Calculates the difference of time, to see how long it took to run the script
        total = t2 - t1
        # Printing the information to screen
        print("Scanning Completed in: {0}".format(total))
        return port_dictionary
    except KeyboardInterrupt:
        print("You pressed Ctrl+C\nLeaving portscanner...")
        return None

    except socket.gaierror:
        print("Hostname could not be resolved.\nLeaving portscanner...")
        return None

    except socket.error:
        print("Couldn't connect to server.\nLeaving portscanner...")
        return None


if __name__ == '__main__':
    scan("127.0.0.1", 1000)