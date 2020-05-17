import sys


def ip(packet):
    """
    Used to calculate the checksum of an IP-Packet


    :param packet: The IP-packet header, in form of 16-bit words in HEX (without preceding 0x)
    :return:
    """
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
    if packet == "":
        print("Please provide the 16-bit words in HEX-format (without preceding 0x). Example for a 16-bit ip_header: "
              "abcd")
        print("It is assumed that the IHL is 5.")

        ip_header = []
        ip_header.append(int(input("Version, IHL and ToS: "), 16))
        ip_header.append(int(input("Total Length: "), 16))
        ip_header.append(int(input("Identification: "), 16))
        ip_header.append(int(input("Flags and Fragment Offset: "), 16))
        ip_header.append(int(input("TTL and Protocol: "), 16))
        ip_header.append(int("0", 16))  # checksum-field is during the computation set to 0
        ip_header.append(int(input("First Part of Source IP-Address: "), 16))
        ip_header.append(int(input("Second Part of Source IP-Address: "), 16))
        ip_header.append(int(input("First Part of Destination IP-Address: "), 16))
        ip_header.append(int(input("Second Part of Destination IP-Address: "), 16))
    else:
        ip_header = packet.split(" ")

    for i in range(len(ip_header)):  # do some input validation
        print(ip_header[i])
        if len(ip_header[i]) != 4:
            try:
                hex(int(ip_header[i], 16))
            except TypeError:
                print("TypeError occurred.")
            finally:
                print("Word " + ip_header[i] + " does not meet the expected format. You must provide a string with "
                                               "multiple four HEX-value words separated by a whitespace.")
                return None
        ip_header[i] = int(ip_header[i], 16)
        print(ip_header[i])

    checksum = calc_checksum(ip_header)
    print("Checksum as Integer (DEC): " + str(checksum))
    return hex(checksum)


def tcp(ip_packet):
    """
    Calculate the checksum in a tcp-segment

    Provide the IP-packet in the parameter as hex-values (without leading '0x', in form of 16-bit words separated by a
    whitespace. The format of the TCP-header is as follows:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    TCP Header Format

    create the pseudo header: src ip, dest ip, 1 byte reserved (0-filled), protocol from ip-header, tcp segment length
    calculate checksum over pseudo header and the whole tcp segment
    the algorithm to calculate the checksum is the same as for ip-header checksum
    Check out RFC 793 for more information about the specification.


    :param ip_packet: A complete IP-packet (inclusive payload), with 'next-level protocol' set to 06 (TCP).
    :return: Checksum of the TCP-segment provided in the payload of the IP-packet
    """

    print("Started calculating the tcp checksum with ip-packet: " + ip_packet)
    # Do some input validation.
    try:
        if not isinstance(ip_packet, str):
            raise TypeError
        ip_packet = ip_packet.split(" ")
        for i in range(len(ip_packet)):
            if (len(ip_packet[i]) != 4) and (i != (len(ip_packet) - 1)):
                raise ValueError
            hex(int(ip_packet[i], 16))
    except TypeError:
        print("Your package is broken. You must provide HEX-values.")
        return None
    except ValueError:
        print("Please provide the input in form of 16-bit HEX-words separated by a whitespace.")
        return None

    # extract some information from the ip header and determine where the tcp-segment starts
    internet_header_length = ip_packet[0][1]
    internet_header_length = int(internet_header_length, 16) * 4  # IHL in bytes

    ip_header = ip_packet[:(internet_header_length / 2)]  # ip-packet is a list with 16-bit words, not with bytes
    tcp_segment = ip_packet[(internet_header_length / 2):]

    protocol = ip_header[9][2:]  # next-level protocol field from the ip-header
    src_ip = ' '.join([ip_header[12], ip_header[13]])  # source ip-address in hex format
    dest_ip = ' '.join([ip_header[14], ip_header[15]])  # destination ip-address in hex format

    # calculate the total length of the ip-packet in bytes (later used for determining the tcp-segment length)
    if len(ip_packet[-1]) == 4:
        ip_total_length = 2 * len(ip_packet)
    elif len(ip_packet[-1]) == 2:
        ip_total_length = 2 * len(ip_packet) - 1
        tcp_segment[-1] = tcp_segment[-1] + '00'  # for checksum-calculation, add trailing zeros (according to RFC 793)
    else:
        # this case does not exist
        ip_total_length = 0
        raise Exception

    # Length of the TCP-segment in bytes (field is 16 bit long),  used in the pseudo header, calculation is done
    # according to the calculation in wireshark
    segment_length = ip_total_length - internet_header_length
    segment_length = hex(segment_length)[2:]
    while len(segment_length) < 4:
        segment_length = '0' + segment_length
    print("Segment is 0x" + segment_length + " byte long.")

    # construct the packet for calculating the checksum
    pseudo_header = src_ip + " " + dest_ip + " 00" + protocol + " " + segment_length  # according to specs: 96 bit long
    extended_segment = pseudo_header + ' ' + ' '.join(tcp_segment)
    print("TCP-Segment inclusive pseudo header: " + extended_segment)
    extended_segment = extended_segment.split(" ")

    # prepare the extended segment for the actual checksum calculation
    for i in range(len(extended_segment)):
        extended_segment[i] = int(extended_segment[i], 16)

    checksum = calc_checksum(extended_segment)
    print("Checksum is: " + str(checksum) + " and in HEX-format: " + hex(checksum))
    return hex(checksum)


def ones_complement_addition(number1, number2):
    """
    Build the one's complement addition as used in the calculation of IP-, TCP- and UDP-headers.

    To see how the one's complement addition works, visit: https://youtu.be/EmUuFRMJbss
    :param number1: A 16-bit number as Integer
    :param number2: A 16-bit number as Integer
    :return: One's complement of the two numbers
    """

    print("calculating the one's complement of " + str(number1) + " + " + str(number2))
    if not (isinstance(number1, int)) and not (isinstance(number2, int)):
        return None
    result = bin(number1 + number2)  # string will begin with '0b', just ignore result[0] and result[1]

    if len(result) < 18:  # add leading zeros
        partial_result = result[2:]
        while len(partial_result) < 16:
            partial_result = '0' + partial_result
        result = '0b' + partial_result

    if len(result) > 18:
        if len(result) == 19 and result[2] == '1':
            print("carry bit needed")
            carry_bit = '1'
            result = list(result)  # convert the string to a list
            result.pop(2)
            print(result)
            for i in range(1, 17):
                if result[-i] == '0' and carry_bit == '1':
                    result[-i] = '1'
                    carry_bit = '0'
                elif result[-i] == '1' and carry_bit == '1':
                    result[-i] = '0'
                    carry_bit = '1'
                elif carry_bit == '0':
                    break
                else:
                    # this should never be executed
                    carry_bit = '0'
            result = ''.join(result)  # convert the list to a string
    print("Result of ones complement addition: " + result)
    return int(result, 2)


def calc_checksum(packet):
    """
    Calculates the checksum of the given packet.

    This function is only for use in environments where 16-bit words are used.

    :param packet: A list with 16-bit numbers as Integers.
    :return:
    """

    # validate the input
    try:
        if not isinstance(packet, list):
            raise TypeError
        for i in range(len(packet)):
            if not isinstance(packet, int):
                raise TypeError
    except TypeError:
        print("Wrong type used for method 'calc_checksum(packet)'")

    print("Calculating the checksum...")
    checksum = ones_complement_addition(packet[0], packet[1])
    for i in range(2, len(packet)):
        checksum = ones_complement_addition(checksum, packet[i])
    checksum = bin(checksum)

    if len(checksum) < 18:  # add leading zeros
        partial_checksum = checksum[2:]
        while len(partial_checksum) < 16:
            partial_checksum = '0' + partial_checksum
        checksum = '0b' + partial_checksum
    checksum = list(checksum)

    for i in range(2, len(checksum)):  # flip the bits
        if checksum[i] == '0':
            checksum[i] = '1'
        elif checksum[i] == '1':
            checksum[i] = '0'
        else:
            # this should be an unreachable code section
            print("Checksum is broken. Please contact the developer.")
    print("Checksum as list: " + ''.join(checksum))
    checksum = int(''.join(checksum), 2)
    return checksum


def main(protocol):
    if "ip" in protocol or "tcp" in protocol:
        if "ip" in protocol:
            print(ip())
            sys.exit()
        elif "tcp" in protocol:
            print(tcp("", "", "", ""))
            sys.exit()
        else:
            print("No valid parameter was provided. Please use 'ip' or 'tcp' as parameter.")
            sys.exit()
    else:
        print("-" * 80)
        print(
            "Usage of Fingerprinter.calculate_header_checksum.py:\npython ./calculate_header_checksum.py <ip | tcp>\n")
        print("Example:\n./calculate_header_checksum.py 'ip'")
        print("This will ask you to provide the values of every field in the IPv4-header.")
        print("-" * 80)
        sys.exit(1)


# main(input("IP or TCP checksum? "))

# ip("4500 00cd 29e7 4000 8006 0000 c0a8 009e c0a8 000c")

# tcp("c0a8 009e", "c0a8 000c", "06", "060c cc63 5f8d 1e40 6923 1857 5018 faf0 c658 0000 4745 5420 2f64 6d72 2e78 6d6c 2048 5454 502f 312e 310d 0a55 7365 722d 4167 656e 743a 2053 706f 7469 6679 2f31 3133 3030 3036 3538 2057 696e 3332 2f30 2028 5043 2064 6573 6b74 6f70 290d 0a48 6f73 743a 2031 3932 2e31 3638 2e30 2e31 323a 3532 3332 330d 0a4b 6565 702d 416c 6976 653a 2030 0d0a 4163 6365 7074 2d45 6e63 6f64 696e 673a 2067 7a69 700d 0a43 6f6e 6e65 6374 696f 6e3a 206b 6565 702d 616c 6976 650d 0a0d 0a00")

# tcp("c0a8 000c", "c0a8 009e", "06", "cc63 060c 6923 365e 5f8d 1ee5 5019 1920 0000 0000 3737 3c2f 6176 3a58 5f52 4449 535f 454e 5452 595f 504f 5254 3e0a 2020 2020 3c2f 6176 3a58 5f52 4449 535f 4465 7669 6365 496e 666f 3e0a 2020 3c2f 6465 7669 6365 3e0a 3c2f 726f 6f74 3e0a")

# tcp("c0a8 009e", "c0a8 000c", "06", "060d 0050 025a 1462 6de6 be48 5018 faf0 0000 0000 4745 5420 2f44 4941 4c2f 6170 7073 2f63 6f6d 2e73 706f 7469 6679 2e53 706f 7469 6679 2e54 5676 3220 4854 5450 2f31 2e31 0d0a 5573 6572 2d41 6765 6e74 3a20 5370 6f74 6966 792f 3131 3330 3030 3635 3820 5769 6e33 322f 3020 2850 4320 6465 736b 746f 7029 0d0a 486f 7374 3a20 3139 322e 3136 382e 302e 3132 0d0a 4b65 6570 2d41 6c69 7665 3a20 300d 0a41 6363 6570 742d 456e 636f 6469 6e67 3a20 677a 6970 0d0a 436f 6e6e 6563 7469 6f6e 3a20 6b65 6570 2d61 6c69 7665 0d0a 0d0a")


# to calculate the checksum for the packet crafter:
# print(ip("4500 003b abcd 0000 4006 0000 ac11 b0b1 ac11 b0b3"))

print(tcp("4500 003c abcd 0000 4006 caf2 c0a8 c151 c0a8 c159 ff98 0050 0000 0000 0000 0000 5002 7110 3ad9 0000 0000 "
          "0000 0000 0000 0000 0000 0000 0000 0000 0000"))
