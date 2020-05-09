import sys


def ip(packet=""):
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
    if packet != "":
        word = packet.split(" ")
        print(word)
        for i in range(len(word)):
            print(word[i])
            if len(word[i]) != 4:
                try:
                    hex(int(word[i], 16))
                except TypeError:
                    print("TypeError occurred.")
                finally:
                    print("Word " + word[i] + " does not meet the expected format. You must provide a string with "
                                              "multiple four HEX-value words separated by a whitespace.")
                    return None
            word[i] = int(word[i], 16)
    else:
        print("Please provide the 16-bit words in HEX-format (without preceding 0x). Example for a 16-bit word: abcd")
        print("It is assumed that the IHL is 5.")

        # convert the HEX-values to BIN-values, https://stackoverflow.com/questions/1425493/convert-hex-to-binary
        # the tilde will do a bitwise negation of the provided value
        word = []
        word.append(int(input("Version, IHL and ToS: "), 16))
        word.append(int(input("Total Length: "), 16))
        word.append(int(input("Identification: "), 16))
        word.append(int(input("Flags and Fragment Offset: "), 16))
        word.append(int(input("TTL and Protocol: "), 16))
        word.append(int("0", 16))  # checksum-field is during the computation set to 0
        word.append(int(input("First Part of Source IP-Address: "), 16))
        word.append(int(input("Second Part of Source IP-Address: "), 16))
        word.append(int(input("First Part of Destination IP-Address: "), 16))
        word.append(int(input("Second Part of Destination IP-Address: "), 16))

    checksum = ones_complement_addition(word[0], word[1])  # result of first 32-bit
    for i in range(2, len(word)):
        checksum = ones_complement_addition(checksum, word[i])
    checksum = bin(checksum)
    if len(checksum) < 18:  # add leading zeros
        partial_checksum = checksum[2:]
        while len(partial_checksum) < 16:
            partial_checksum = '0'+partial_checksum
        checksum = '0b'+partial_checksum
    checksum = list(checksum)

    for i in range(2, len(checksum)):
        # flip the bits
        if checksum[i] == '0':
            checksum[i] = '1'
        elif checksum[i] == '1':
            checksum[i] = '0'
        else:
            # this should be an unreachable code section
            print("Checksum is broken. Please contact the developer.")
    print("Checksum as list: " + ''.join(checksum))
    checksum = int(''.join(checksum), 2)
    print("Checksum as Integer: " + str(checksum))
    return hex(checksum)


def tcp():
    # create the pseudo header: src ip, dest ip, 1 byte reserved (0-filled), protocol from ip-header, tcp segment length
    # calculate checksum over pseudo header and the whole tcp segment
    # the algorithm to calculate the checksum is the same as for ip-header checksum
    checksum = ""
    # TODO: Add computation of checksum
    return checksum


def ones_complement_addition(number1, number2):
    # to see how the one's complement addition works, visit: https://youtu.be/EmUuFRMJbss
    print("calculating the one's complement of " + str(number1) + " + " + str(number2))
    if not (isinstance(number1, int)) and not (isinstance(number2, int)):
        return None
    result = bin(number1 + number2)  # string will begin with '0b', just ignore result[0] and result[1]
    if result[2] == '1':
        if len(result) < 18:  # add leading zeros
            partial_result = result[2:]
            while len(partial_result) < 16:
                partial_result = '0'+partial_result
            result = '0b'+partial_result
    if len(result) > 18:
        if len(result) == 19 and result[2] == '1':
            print("carry bit needed")
            carry_bit = result[2]
            result = list(result)  # convert the string to a list
            result.pop(2)
            print(result)
            for i in range(1, 17):
                if result[-i] == '0' and carry_bit == '1':
                    result[-i] = '1'
                    carry_bit = '0'
                elif result[-i] == '1':
                    result[-i] = '0'
                    carry_bit = '1'
                elif carry_bit == '0':
                    break
                else:
                    # this should never be executed
                    carry_bit = '0'
            result = ''.join(result)  # convert the list to a string
    return int(result, 2)


def main(protocol):
    if "ip" in protocol or "tcp" in protocol:
        if "ip" in protocol:
            print(ip())
            sys.exit()
        elif "tcp" in protocol:
            print(tcp())
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


#main(input("IP or TCP checksum? "))
