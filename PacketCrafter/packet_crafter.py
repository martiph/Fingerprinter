import sys
import socket
import calculate_header_checksum as calc_check

# https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/

# create a raw IPv4 socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW)
# set the socket option IP_HDRINCL to 1, to tell the kernel that a ip-header is provided
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# create the ip-header
ip_header = '4500 003c'  # Version, IHL, Type of Service | Total Length (inclusive data, in bytes)
ip_header += ' abcd 0000'  # Identification | Flags, Fragment Offset
ip_header += ' 4006 0000'  # TTL, Protocol | Header Checksum
ip_header += ' ac11 b0b1'  # Source Address 172.17.176.177
ip_header += ' ac11 b0b3'  # Destination Address 172.17.176.179

# create the tcp-header
tcp_header = '3039 0050'  # Source Port (12345) | Destination Port (80)
tcp_header += ' 0000 0000'  # Sequence Number
tcp_header += ' 0000 0000'  # Acknowledgement Number
tcp_header += ' 5002 7110'  # Data Offset, Reserved, Flags | Window Size
tcp_header += ' 0000 0000'  # Checksum | Urgent Pointer

# create the tcp-payload
tcp_payload = '0000 0000'
tcp_payload += ' 0000 0000'
tcp_payload += ' 0000 0000'
tcp_payload += ' 0000 0000'
tcp_payload += ' 0000 0000'

# calculate the ip-header checksum and the tcp-header checksum
ip_checksum = calc_check.ip(ip_header)
ip_header = ip_header.split(' ')
ip_header[5] = ip_checksum[2:]  # return value of calc_check.ip() is prefixed with '0x'

src_ip = [ip_header[5], ip_header[6]]
dest_ip = [ip_header[7], ip_header[8]]

tcp_checksum = calc_check.tcp(' '.join(src_ip), ' '.join(dest_ip), ip_header[4][2:], tcp_header + ' ' + tcp_payload)
tcp_header = tcp_header.split(' ')
tcp_header[8] = tcp_checksum[2:]  # return value of calc_check.tcp() is prefixed with '0x'

ip_header = ' '.join(ip_header)
tcp_header = ' '.join(tcp_header)

# assemble the packet
packet = ip_header + tcp_header + tcp_payload

# connect to the remote system
remote_ip = '172.17.176.179'
port = 80

s.connect((remote_ip, port))
print("connected successfully")
s.sendto(packet.replace(' ', '').encode('UTF-8'), (remote_ip, port))
print("Packet sent")
data = s.recv(4096)
s.close()
print(data)
sys.exit()

# values to test: src_ip: 172.17.176.177; dest_ip:172.17.176.179
