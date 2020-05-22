import socket
import platform


# tutorial on https://www.binarytides.com/python-packet-sniffer-code-linux/
# another tutorial https://www.bitforestinfo.com/2017/01/how-to-write-simple-packet-sniffer.html

if platform.system() == 'Linux':
    # for linux
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
elif platform.system() == 'Windows':
    # for windows
    s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
    s.bind(("192.168.0.158", 0))
    s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
    s.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
else:
    raise NotImplementedError("Function not implemented for your operating system.")

# receive a packet
while True:
    print(s.recvfrom(65565))
