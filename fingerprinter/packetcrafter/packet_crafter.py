import threading
import re
import socket
import fingerprinter.packetcrafter.calculate_header_checksum as calc_check
import fingerprinter.sniffer.sniffer as sniffer


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
    port = hex(port)
    port = port[2:]
    while len(port) < 4:
        port = '0' + port
    return port


def receive_data_socket(src_ip, src_port, dest_ip, dest_port, ack_number):
    recv_data = sniffer.sniff(src_ip, src_port, dest_ip, dest_port, ack_number)
    return recv_data


# Tutorial on how to craft manually a raw ip-packet:
# https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/
# https://www.binarytides.com/raw-socket-programming-in-python-linux/
# more information about raw socket: man 7 socket


# variables
src_ip = '192.168.100.10'
src_port = 65432

dest_ip = '192.168.100.20'
dest_port = 80

# create a raw IPv4 socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
# set the socket option IP_HDRINCL to 1, to tell the kernel that a ip-header is provided
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

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

# start receiving socket, search for packets coming from the current destination host
recv_socket_thread = threading.Thread(target=receive_data_socket(dest_ip, dest_port, src_ip, src_port, current_ack_number + 1))
recv_socket_thread.start()

# connect to the remote system
print("Trying to send data to " + dest_ip + " on port " + str(dest_port))
value = s.sendto(packet, (dest_ip, dest_port))
print("Packet sent, " + str(value) + " bytes sent")

# wait for the answer
recv_socket_thread.join()
s.close()