import os
import socket


class Sniffer:
    def __init__(self):
        self.ip = "192.168.1.119"
        self.port = 0
        self.socket = None

    def initialize(self):
        if os.name == "nt":
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.socket.bind((self.ip, self.port))
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.socket.ioctl(socket.SIO_RCVALL, 1)
        elif os.name == "posix":
            self.socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

    def start(self, buffer_size=65565):
        data = self.socket.recvfrom(buffer_size)
        return data
