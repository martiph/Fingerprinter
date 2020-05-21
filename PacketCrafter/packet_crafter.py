import sys
import re
import socket
import calculate_header_checksum as calc_check


def convert_ip_address(ip_address):
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


# Tutorial on how to craft manually a raw ip-packet:
# https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/
# https://www.binarytides.com/raw-socket-programming-in-python-linux/


# variables
src_ip = '192.168.100.10'
dest_ip = '192.168.100.20'


# create a raw IPv4 socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
# set the socket option IP_HDRINCL to 1, to tell the kernel that a ip-header is provided
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)


# create the ip-header
ip_header = '4500 003c'  # Version, IHL, Type of Service | Total Length (inclusive data, in bytes)
ip_header += ' abcd 0000'  # Identification | Flags, Fragment Offset
ip_header += ' 4006 0000'  # TTL, Protocol | Header Checksum
ip_header += ' ' + convert_ip_address(src_ip)  # Source Address 172.17.232.161
ip_header += ' ' + convert_ip_address(dest_ip)  # Destination Address 172.17.232.161

# create the tcp-header
tcp_header = 'ff99 ff98'  # Source Port (65433) | Destination Port (65432)
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

local_ip = str(int(ip_header[6][:2], 16)) + '.' + str(int(ip_header[6][2:], 16)) + '.' + str(
    int(ip_header[7][:2], 16)) + '.' + str(int(ip_header[7][2:], 16))
remote_ip = str(int(ip_header[8][:2], 16)) + '.' + str(int(ip_header[8][2:], 16)) + '.' + str(
    int(ip_header[9][:2], 16)) + '.' + str(int(ip_header[9][2:], 16))
dest_port = int(tcp_header.split(' ')[1], 16)

tcp_checksum = calc_check.tcp(' '.join(ip_header) + ' ' + tcp_header)  # + ' ' + tcp_payload)
tcp_header = tcp_header.split(' ')
tcp_header[8] = tcp_checksum[2:]  # return value of calc_check.tcp() is prefixed with '0x'

ip_header = ' '.join(ip_header)
tcp_header = ' '.join(tcp_header)

# assemble the packet
packet = ip_header + ' ' + tcp_header + ' ' + tcp_payload
# packet = packet.replace(' ', '')
print("Packet to send: " + packet)
packet = bytes.fromhex(packet)
# print(packet)
# print(packet.hex())

# connect to the remote system
# s.connect((remote_ip, 80))
print("connected successfully to " + remote_ip + " on port " + str(dest_port))
value = s.sendto(packet, (remote_ip, 80))
print("Packet sent, " + str(value) + " bytes sent")
data = s.recv(4096).hex()
print(repr(data))
s.close()

# values to test: src_ip: 172.17.232.161; dest_ip: 172.17.232.161
