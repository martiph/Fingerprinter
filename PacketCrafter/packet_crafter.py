import socket

# https://inc0x0.com/tcp-ip-packets-introduction/tcp-ip-packets-3-manually-create-and-send-raw-tcp-ip-packets/

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # tells the kernel not to create a header

ip_header = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
ip_header += b'\x40\x06\x4c\xdf'  # TTL, Protocol | Header Checksum
ip_header += b'\xc0\xa8\x00\x9e'  # Source Address 192.168.0.158
ip_header += b'\xc0\xa8\x00\x2b'  # Destination Address 192.168.0.43

tcp_header = b'\x30\x39\x00\x50'  # Source Port (12345) | Destination Port (80)
tcp_header += b'\x00\x00\x00\x00'  # Sequence Number
tcp_header += b'\x00\x00\x00\x00'  # Acknowledgement Number
tcp_header += b'\x50\x02\x71\x10'  # Data Offset, Reserved, Flags | Window Size
tcp_header += b'\xe6\x32\x00\x00'  # Checksum | Urgent Pointer

packet = ip_header + tcp_header
s.sendto(packet, ('192.168.0.43', 0))
print("Packet sent")
