import threading
import re
import socket
import queue
import packetcrafter.calculate_header_checksum as calc_check
import sniffer.sniffer as sniffer

# global variables
q = queue.Queue()


def convert_ip_address(ip_address: str):
    """
    This function converts a ipv4 address in standard string format to a HEX representation

    :param ip_address: string with IPv4 address in format '192.168.0.1'
    :return: HEX representation of IPv4 address (string)
    """
    if re.search('^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\.(?!$)|$)){4}$', ip_address) is None:
        return None
    ip_addr = ip_address.split('.')
    for i in range(4):
        ip_addr[i] = hex(int(ip_addr[i]))[2:]
        while len(ip_addr[i]) < 2:
            ip_addr[i] = '0' + ip_addr[i]
    ip_address = ip_addr[0] + ip_addr[1] + ' ' + ip_addr[2] + ip_addr[3]
    return ip_address


def convert_port(port: int):
    """
    Converts a port number from Integer to HEX-value

    :param port: Integer which represents a port
    :return: HEX representation of port number (string), without preceeding '0x'
    """
    port = hex(int(port))
    port = port[2:].zfill(4)
    return port


def receive_data_socket(src_ip, src_port, dest_ip, dest_port, ack_number):
    """
    receive data on a socket
    :param src_ip: Source ip address of the packet to capture
    :param src_port: Source port of the packet to capture
    :param dest_ip: Destination ip address of the packet to capture
    :param dest_port: Destination port of the packet to capture
    :param ack_number: The acknowledge number of the packet to capture
    :return: none, Data was written to a queue
    """
    recv_data = sniffer.sniff(src_ip, src_port, dest_ip, dest_port, ack_number)
    q.put(recv_data)


def send_packet(src_ip: str, src_port: int, dest_ip: str, dest_port: int, packet: bytes, current_ack_number: int):
    """
    sends a raw packet to a specified system
    :param src_ip: the source address for the packet to send
    :param src_port: the source port for the packet to send
    :param dest_ip: the destination address for the packet to send
    :param dest_port: the destination port for the packet to send
    :param packet: the whole packet to send in bytes
    :param current_ack_number: the current acknowledge number of the packet
    :return: True if packet was sent and response received
    """

    # create a raw IPv4 socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    # set the socket option IP_HDRINCL to 1, to tell the kernel that a ip-header is provided
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # start receiving socket, search for packets coming from the current destination host
    # the thread is used because the sniffer could start too slow if it would be started after the sending of the packet
    # the answer from the thread is written to the queue
    sniffer_thread = threading.Thread(target=receive_data_socket,
                                      args=(dest_ip, dest_port, src_ip, src_port, current_ack_number + 1))
    sniffer_thread.start()

    # connect to the remote system
    print("Trying to send data to " + dest_ip + " on port " + str(dest_port))
    value = s.sendto(packet, (dest_ip, int(dest_port)))
    print("Packet sent, " + str(value) + " bytes sent")

    # wait for the answer
    sniffer_thread.join()
    s.close()
    return True


def craft_packet(src_ip, src_port, dest_ip, dest_port):
    """
    craft a packet with the provided parameters
    :param src_ip: the source ip address in IPv4 format
    :param src_port: the source port
    :param dest_ip: the destination ip address in IPv4 format
    :param dest_port: the destination port
    :return: the responding packet as a map
    """

    # create the ip-header
    ip_header = '4500 003c'  # Version, IHL, Type of Service | Total Length (inclusive data, in bytes)
    ip_header += ' abcd 0000'  # Identification | Flags, Fragment Offset
    ip_header += ' 4006 0000'  # TTL, Protocol | Header Checksum
    ip_header += ' ' + convert_ip_address(src_ip)  # Source Address
    ip_header += ' ' + convert_ip_address(dest_ip)  # Destination Address

    # create the tcp-header
    tcp_header = convert_port(src_port) + ' ' + convert_port(dest_port)  # Source Port | Destination Port
    tcp_header += ' 0000 0000'  # Sequence Number
    tcp_header += ' 0000 0000'  # Acknowledgement Number
    tcp_header += ' 5002 7110'  # Data Offset, Reserved, Flags | Window Size
    tcp_header += ' 0000 0000'  # Checksum | Urgent Pointer

    # create the tcp-payload
    tcp_payload = 'abcd abcd'
    tcp_payload += ' abcd abcd'
    tcp_payload += ' abcd abcd'
    tcp_payload += ' abcd abcd'
    tcp_payload += ' abcd abcd'

    # calculate the ip-header checksum and the tcp-header checksum
    ip_checksum = calc_check.ip(ip_header)
    ip_header = ip_header.split(' ')
    ip_header[5] = ip_checksum[2:]  # return value of calc_check.ip() is prefixed with '0x'

    tcp_checksum = calc_check.tcp(' '.join(ip_header) + ' ' + tcp_header + ' ' + tcp_payload)
    tcp_header = tcp_header.split(' ')
    tcp_header[8] = tcp_checksum[2:]  # return value of calc_check.tcp() is prefixed with '0x'

    current_ack_number = int(''.join(tcp_header[4:6]), 16)
    ip_header = ' '.join(ip_header)
    tcp_header = ' '.join(tcp_header)

    # assemble the packet
    packet = ip_header + ' ' + tcp_header + ' ' + tcp_payload
    print("Packet to send: " + packet)
    packet = bytes.fromhex(packet)
    if send_packet(src_ip, src_port, dest_ip, dest_port, packet, current_ack_number):
        return q.get()


def fingerprint(src_ip, src_port, dest_ip, dest_port):
    """
    Determine the operating system based on the TTL
    :param src_ip: Source IPv4 address for the packet
    :param src_port: Source port for the packet
    :param dest_ip: IPv4 address of the target
    :param dest_port: Open port of the target
    :return: Prints either 'Windows' or 'Linux'
    """
    result = craft_packet(src_ip, src_port, dest_ip, dest_port)
    # if another matching algorithm would be used, it could be implemented here
    if 64 < int(result["ttl"]) <= 128:
        print("Windows")
    elif int(result["ttl"]) <= 64:
        print("Linux")


if __name__ == '__main__':
    src_ip = '192.168.100.10'
    src_port = 65432
    dest_ip = '192.168.100.20'
    dest_port = 80
    fingerprint(src_ip, src_port, dest_ip, dest_port)
