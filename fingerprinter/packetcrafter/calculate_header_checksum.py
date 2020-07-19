def ip(packet: str):
    """
    Used to calculate the checksum of an IP-Packet

    source: RFC 791; https://tools.ietf.org/html/rfc791#section-3.1
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Example Internet Datagram Header
    To compute the checksum, the checksum-field is set to 0.

    :param packet: The IP-packet header as a string, in form of 16-bit words in HEX (without preceding 0x)
    :return: IP-Header checksum as HEX-value (inclusive preceeding '0x'), as a string
    """
    print("Started calculating the ip header checksum for packet: " + packet)

    # Do some input validation.
    try:
        if not isinstance(packet, str):
            raise TypeError("Parameter not of type 'string'")
        ip_header = packet.split(' ')
        for i in range(len(ip_header)):
            if len(ip_header[i]) != 4:
                raise ValueError("A 16-bit word in HEX-format consists of four characters.")
            hex(int(ip_header[i], 16))
    except TypeError:
        print("Your packet is of wrong type.")
        return None
    except ValueError:
        print("Your packet has wrong values")
        return None

    # prepare the ip-header for the checksum calculation
    for i in range(len(ip_header)):
        ip_header[i] = int(ip_header[i], 16)
        if not isinstance(ip_header[i], int):
            return None

    checksum = calc_checksum(ip_header)
    print("Checksum as Integer (DEC): " + str(checksum))
    return hex(checksum)


def tcp(ip_packet: str):
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
    :return: Checksum of the TCP-segment provided in the payload of the IP-packet (as HEX-Value, including leading '0x')
    """

    print("Started calculating the tcp checksum with ip-packet: " + ip_packet)
    # Do some input validation.
    try:
        if not isinstance(ip_packet, str):
            raise TypeError("Parameter not of type 'string'")
        ip_packet = ip_packet.split(' ')
        for i in range(len(ip_packet)):
            if (len(ip_packet[i]) != 4) and (i != (len(ip_packet) - 1)):
                raise ValueError("A 16-bit word in HEX-format consists of four characters.")
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

    end_of_ip_header = int(internet_header_length / 2)  # index of first 16-bit word after the ip-header
    ip_header = ip_packet[:end_of_ip_header]
    tcp_segment = ip_packet[end_of_ip_header:]
    while len(tcp_segment[-1]) < 4:
        tcp_segment[-1] = tcp_segment[-1] + '0'

    protocol = ip_header[4][2:]  # next-level protocol field from the ip-header
    src_ip = ' '.join([ip_header[6], ip_header[7]])  # source ip-address in hex format
    dest_ip = ' '.join([ip_header[8], ip_header[9]])  # destination ip-address in hex format

    # extract the total length of the ip-packet in bytes (later used for determining the tcp-segment length)
    ip_total_length = int(ip_header[1], 16)

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
            carry_bit = '1'
            result = list(result)  # convert the string to a list
            result.pop(2)
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
                    raise ValueError
            result = ''.join(result)  # convert the list to a string
    print("Result of ones complement addition: " + result)
    return int(result, 2)


def calc_checksum(packet):
    """
    Calculates the checksum of a given packet.

    This function is only for use in environments where 16-bit words are used.

    :param packet: A list with 16-bit numbers as Integers.
    :return: The checksum of the packet as Integer
    """

    # validate the input
    try:
        if not isinstance(packet, list):
            raise TypeError("Packet " + str(packet) + "is not of type 'list'")
        for i in range(len(packet)):
            if not isinstance(packet[i], int):
                raise TypeError(
                    "Value " + str(packet[i]) + " on position " + str(i) + " in the packet is not of type 'int'")
    except TypeError as te:
        print("Wrong type used for method 'calc_checksum(packet)'")
        print(te)

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
            raise ValueError("Other value than 0 or 1 in a binary-string.")
    print("Checksum as list: " + ''.join(checksum))
    checksum = int(''.join(checksum), 2)
    return checksum


if __name__ == 'main':
    ip("0000 0000 0000 0000 0000 0000 0000 0000 0000 0000")
