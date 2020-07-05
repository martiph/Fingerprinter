import queue
import socket
import threading
from datetime import datetime

q = queue.Queue()


def scan_port_range(remote_server_ip, start_port, end_port):
    """
    scan a port range for open ports
    :param remote_server_ip: system to scan
    :param start_port: start of port range (inclusive)
    :param end_port: end of port range (exclusive)
    :return: none This function writes the results to a queue.
    """
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


def scan(remote_server: str, highest_port_number: int):
    """

    :param remote_server: target system
    :param highest_port_number: highest port number to scan
    :return: dictionary with port:status (open|closed)
    """
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