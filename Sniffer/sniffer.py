import platform
import socket
import sys

# tutorial on https://www.binarytides.com/python-packet-sniffer-code-linux/
# another tutorial https://www.bitforestinfo.com/2017/01/how-to-write-simple-packet-sniffer.html

HOST = '192.168.100.10'
PORT = 0


def create_ip_dict():
    """
    Creates a dictionary with all fields of IP-header, TCP-header and an element for the TCP-data

    IP-options and TCP-options include always padding

    :return: ip_dict
    """
    ip_dict = {
        "version": None,
        "ihl": None,
        "tos": None,
        "total_length": None,
        "identification": None,
        "ip_flags": None,
        "fragment_offset": None,
        "ttl": None,
        "protocol": None,
        "ip_checksum": None,
        "src_ip": None,
        "dest_ip": None,
        "ip_options": None,
        "src_port": None,
        "dest_port": None,
        "seq_number": None,
        "ack_number": None,
        "data_offset": None,
        "tcp_flags": None,
        "window": None,
        "tcp_checksum": None,
        "urgent_pointer": None,
        "tcp_options": None,
        "tcp_data": None
    }
    return ip_dict


def parse(ip_packet):
    # TODO: Add input validation (check if it's a string and in HEX-format)

    packet_dict = create_ip_dict()
    packet_dict["version"] = ip_packet[0]
    packet_dict["ihl"] = ip_packet[1]
    ihl = int(packet_dict["ihl"], 16) * 4  # calculate count of bytes of IHL
    ip_header = ip_packet[:int(round(ihl * 2, 0))]  # one byte is represented as 2 chars, therefore multiply with 2.
    tcp_segment = ip_packet[int(round(ihl * 2, 0)):]

    packet_dict["tos"] = ip_header[2:4]  # if a detailed analysis would be needed, consult the RFC's
    packet_dict["total_length"] = int(ip_header[4:8], 16)  # total packet length in bytes
    # third and fourth word
    packet_dict["identification"] = ip_header[8:10] + ip_header[10:12]
    packet_dict["ip_flags"] = int(bin(int(ip_header[12], 16)[2:5]), 2)  # flags only use 3 bit...
    packet_dict["fragment_offset"] = int(bin(int(ip_header[12:16], 16))[5:], 2)
    packet_dict["ttl"] = int(ip_header[16:18], 16)
    packet_dict["protocol"] = ip_header[18:20]
    packet_dict["ip_checksum"] = ip_header[20:24]

    src_ip = ip_header[24:32]
    dest_ip = ip_header[32:40]
    for i in range(4):
        src_ip[i] = int(src_ip[i], 16)
        dest_ip[i] = int(dest_ip[i], 16)
    src_ip = '.'.join(src_ip)
    dest_ip = '.'.join(dest_ip)

    packet_dict["src_ip"] = src_ip
    packet_dict["dest_ip"] = dest_ip
    if len(ip_header) > 40:
        packet_dict["ip_options"] = ip_header[40:]

    packet_dict["src_port"] = tcp_segment[0:4]
    packet_dict["dest_port"] = tcp_segment[4:8]
    packet_dict["seq_number"] = tcp_segment[8:16]
    packet_dict["ack_number"] = tcp_segment[16:24]
    packet_dict["data_offset"] = int(tcp_segment[24], 16)
    tcp_data_start = packet_dict["data_offset"] * 8  # index of first char of the tcp-data

    packet_dict["tcp_flags"] = int(tcp_segment[25:28], 16)  # flags including reserved bits (set to 0)
    packet_dict["window"] = tcp_segment[28:32]
    packet_dict["tcp_checksum"] = tcp_segment[32:36]
    packet_dict["urgent_pointer"] = tcp_segment[36:40]

    if tcp_data_start > 40:
        packet_dict["options"] = tcp_segment[40:tcp_data_start]
    packet_dict["tcp_data"] = tcp_segment[tcp_data_start:]
    return packet_dict


def sniff():
    if platform.system() == 'Linux':
        print("Your operating system was determined as " + platform.system())
        # s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(0x0800))
        # s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)  # works, verified on ubuntu
    elif platform.system() == 'Windows':
        # windows sockets work a little bit different than linux sockets
        print("Your operating system was determined as " + platform.system())
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((HOST, PORT))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        raise NotImplementedError("Function not implemented for your operating system.")

    # receive a packet
    try:
        print("capturing now traffic")
        while True:
            data = s.recvfrom(65565)

            print(data[0].hex() + ' ' + str(data[1]))
            # TODO: Parse the incoming traffic
    except KeyboardInterrupt:
        print("You pressed Ctrl+C\nStop sniffing...")
        sys.exit()
