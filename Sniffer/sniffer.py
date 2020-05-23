import platform
import socket
import sys

# tutorial on https://www.binarytides.com/python-packet-sniffer-code-linux/
# another tutorial https://www.bitforestinfo.com/2017/01/how-to-write-simple-packet-sniffer.html

HOST = '192.168.100.10'
PORT = 0

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
