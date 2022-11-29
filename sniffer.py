import os
import socket


class Sniffer:
    def __init__(self):
        self.ip = socket.gethostbyname(socket.gethostname())
        self.port = 0
        self.socket = None

    def initialize(self):
        if os.name == "nt":
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.socket.bind((self.ip, self.port))
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        # if other
        elif os.name == "posix":
            self.socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

    def start(self, buffer_size=65565):
        data = self.socket.recvfrom(buffer_size)
        return data
