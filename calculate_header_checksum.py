import sys


def ip():
    # source: RFC 791; https://tools.ietf.org/html/rfc791#section-3.1
    # 0                   1                   2                   3
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |Version|  IHL  |Type of Service|          Total Length         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         Identification        |Flags|      Fragment Offset    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |  Time to Live |    Protocol   |         Header Checksum       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                       Source Address                          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    Destination Address                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    Options                    |    Padding    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # Example Internet Datagram Header
    # To compute the checksum, the checksum-field is set to 0.

    print("Please provide the values for the fields in the ip-header in HEX-format (without preceding 0x).")
    version = input("Version: ")
    ihl = input("Internet Header Length: ")
    tos = input("Type of Service: ")
    total_length = input("Total Length :")
    result_1 = version + ihl + tos + total_length  # result of first 32-bit

    identification = input("Identification: ")
    flags = input("Flags: ")
    fragment_offset = input("Fragment Offset: ")
    result_2 = result_1 + identification + flags + fragment_offset  # result of second 32-bit

    ttl = input("Time to live: ")
    protocol = input("Protocol: ")
    header_checksum = 0
    result_3 = result_2 + ttl + protocol + header_checksum  # result of third 32-bit
    src_address = input("Source Address: ")
    dest_addr = input("Destination Address: ")
    checksum = version + ihl + tos + total_length + identification + flags + fragment_offset + ttl + protocol + src_address + dest_addr
    # TODO: Fix computation of checksum
    return checksum


def tcp():
    checksum = ""
    # TODO: Add computation of checksum
    return checksum


if len(sys.argv) == 2:
    if sys.argv[1] == "ip":
        print(ip())
        sys.exit()
    elif sys.argv[1] == "tcp":
        print(tcp())
        sys.exit()
    else:
        print("No valid script parameter was provided. Please use 'ip' or 'tcp' as parameter.")
        sys.exit()
else:
    print("-"*80)
    print("Usage of Fingerprinter.calculate_header_checksum.py:\npython ./calculate_header_checksum.py <ip | tcp>\n")
    print("Example:\n./calculate_header_checksum.py 'ip'")
    print("This will ask you to provide the values of every field in the IPv4-header.")
    print("-"*80)
    sys.exit(1)
