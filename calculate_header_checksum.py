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
    # convert the HEX-values to BIN-values, https://stackoverflow.com/questions/1425493/convert-hex-to-binary
    version = format(int(input("Version: "),16),'0>4b')
    ihl = format(int(input("Internet Header Length: "), 16), '0>4b')
    tos = format(int(input("Type of Service: "), 16), '0>8b')
    total_length = format(int(input("Total Length :"), 16), '0>16b')
    result_1 = version + ihl + tos + total_length  # result of first 32-bit

    identification = format(int(input("Identification: "), 16), '0>16b')
    flags = format(int(input("Flags: "), 16), '0>3b')
    fragment_offset = format(int(input("Fragment Offset: "), 16), '0>13b')
    result_2 = result_1 + identification + flags + fragment_offset  # result of second 32-bit

    ttl = format(int(input("Time to live: "), 16), '0>8b')
    protocol = format(int(input("Protocol: "), 16), '0>8b')
    header_checksum = format(int(0, 16), '0>16b')
    result_3 = result_2 + ttl + protocol + header_checksum  # result of third 32-bit

    src_address = format(int(input("Source Address: "), 16), '0>32b')
    dest_addr = format(int(input("Destination Address: "), 16), '0>32b')

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
