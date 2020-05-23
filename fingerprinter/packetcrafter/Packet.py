import socket


class Packet:
    """An object of this class represents an ip packet"""
    src_ip = ""
    dest_ip = ""

    def calc_ip_checksum(self, ip_header: str):
        """A simple method to calculate the checksum of the ip-header."""
        checksum = ""
        return None

    def calc_tcp_checksum(self, src_ip: str, dest_ip: str, protocol: str, tcp_packet: str):
        """A simple method to calculate the checksum of the tcp-header. The pseudo header will be created"""
        checksum = ""
        pseudo_header = ""
        return hex(checksum)

    def calc_checksum(self, packet: list[int]):
        checksum = None
        return checksum

    def get_hex_dump(self, packet):
        return hex(packet)
