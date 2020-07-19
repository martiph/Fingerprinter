import platform
import socket
import sys


def create_ip_dict():
    """
    Creates a dictionary with all fields of IP-header, TCP-header and an element for the TCP-data

    IP-options and TCP-options always include padding

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


def parse(ip_packet: str):
    """
    Extract the values for different fields from the provided IP-packet

    :param ip_packet: String consisting of IP-Header, TCP-Header and TCP-Data in HEX-format
    :return: packet_dict with the extracted values
    """
    # Do some input validation.
    if not isinstance(ip_packet, str):
        raise TypeError("You must provide a string.")
    hex(int(ip_packet, 16))
    if ip_packet.startswith('0b'):
        ip_packet = ip_packet[2:]
    ip_packet.replace(' ', '')

    # parse the packet
    packet_dict = create_ip_dict()
    packet_dict["version"] = ip_packet[0]
    packet_dict["ihl"] = ip_packet[1]
    ihl = int(packet_dict["ihl"], 16) * 4  # calculate count of bytes of IHL
    ip_header = ip_packet[:int(round(ihl * 2, 0))]  # one byte is represented as 2 chars, therefore multiply with 2.
    tcp_segment = ip_packet[int(round(ihl * 2, 0)):]

    packet_dict["tos"] = ip_header[2:4]  # if a detailed analysis would be needed, consult the RFC's
    packet_dict["total_length"] = int(ip_header[4:8], 16)  # total packet length in bytes
    packet_dict["identification"] = ip_header[8:10] + ip_header[10:12]

    # flags only use 3 bit, the other 13 bits are for the fragment offset
    flags_fragment_offset = bin(int(ip_header[12:16], 16))[2:]
    while len(flags_fragment_offset) < 16:
        flags_fragment_offset = '0' + flags_fragment_offset

    packet_dict["ip_flags"] = int(flags_fragment_offset[:3], 2)
    packet_dict["fragment_offset"] = int(flags_fragment_offset[3:], 2)

    packet_dict["ttl"] = int(ip_header[16:18], 16)
    packet_dict["protocol"] = ip_header[18:20]
    packet_dict["ip_checksum"] = ip_header[20:24]

    src_ip = ip_header[24:32]
    dest_ip = ip_header[32:40]
    src_ip_dec = [src_ip[0:2], src_ip[2:4], src_ip[4:6], src_ip[6:8]]
    dest_ip_dec = [dest_ip[0:2], dest_ip[2:4], dest_ip[4:6], dest_ip[6:8]]
    for i in range(len(src_ip_dec)):
        src_ip_dec[i] = str(int(src_ip_dec[i], 16))
        dest_ip_dec[i] = str(int(dest_ip_dec[i], 16))
    src_ip = '.'.join(src_ip_dec)
    dest_ip = '.'.join(dest_ip_dec)

    packet_dict["src_ip"] = src_ip
    packet_dict["dest_ip"] = dest_ip
    if len(ip_header) > 40:
        packet_dict["ip_options"] = ip_header[40:]

    packet_dict["src_port"] = int(tcp_segment[0:4], 16)
    packet_dict["dest_port"] = int(tcp_segment[4:8], 16)
    packet_dict["seq_number"] = int(tcp_segment[8:16], 16)
    packet_dict["ack_number"] = int(tcp_segment[16:24], 16)
    packet_dict["data_offset"] = int(tcp_segment[24], 16)
    tcp_data_start = packet_dict["data_offset"] * 8  # index of first char of the tcp-data

    packet_dict["tcp_flags"] = int(tcp_segment[25:28], 16)  # flags including reserved bits (set to 0)
    packet_dict["window"] = tcp_segment[28:32]
    packet_dict["tcp_checksum"] = tcp_segment[32:36]
    packet_dict["urgent_pointer"] = tcp_segment[36:40]

    if tcp_data_start > 40:
        packet_dict["tcp_options"] = tcp_segment[40:tcp_data_start]
    packet_dict["tcp_data"] = tcp_segment[tcp_data_start:]

    return packet_dict


def sniff(src_ip, src_port, dest_ip, dest_port, ack_number):
    """
    Specify in the parameters some field values of a packet which you expect to receive on any network card. This
    function sniffs all traffic. It does it by opening a raw socket on either Linux- or Windows-based systems and
    listening for any traffic. All sniffed traffic is printed to STDOUT. The function returns the packet which
    matches the parameters.

    :param src_ip: The source IPv4 address
    :param src_port: The source port
    :param dest_ip: The destination IPv4 address
    :param dest_port: The destination port
    :param ack_number: The acknowledge number
    :return: the packet matching the parameters as a dictionary
    """
    if platform.system() == 'Linux':
        print("Your operating system was determined as " + platform.system())
        # cannot use IPPROTO_IP as protocol since this is a dummy protocol on linux
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    elif platform.system() == 'Windows':
        # windows sockets work a little bit different than linux sockets, IPPROTO_IP can be used
        print("Your operating system was determined as " + platform.system())
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        # bind socket to the destination host (host from where the original request was sent)
        s.bind((dest_ip, dest_port))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        raise NotImplementedError("Function not implemented for your operating system. You use " + platform.system())

    # receive a packet
    try:
        print("capturing now traffic")
        while True:
            data = s.recvfrom(65565)
            data = parse(data[0].hex())
            print(data.items())
            if (data["src_ip"] == src_ip) and (data["src_port"] == src_port) and (data["dest_ip"] == dest_ip) and (
                    data["dest_port"] == dest_port) and (data["ack_number"] == ack_number):
                return data
    except KeyboardInterrupt:
        print("You pressed Ctrl+C\nStop sniffing...")
        sys.exit()


if __name__ == '__main__':
    sniff(sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5]))
