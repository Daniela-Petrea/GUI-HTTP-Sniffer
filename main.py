import socket
import struct

def get_ipv(ether_type):
    if ether_type == 0x0800:
        return 4
    elif ether_type == 0x86DD:
        return 6

def ethernet_head(raw_data):
    eth_header = raw_data[:14]
    #print(raw_data[:14])
    eth_header_unpacked = struct.unpack('! 6s 6s H', eth_header)
    #eth_header_unpacked = struct.unpack('! 6s 6s 2s', eth_header)
    mac_dest_addr = get_mac_addr(eth_header_unpacked[0])
    mac_src_addr = get_mac_addr(eth_header_unpacked[1])
    print(eth_header_unpacked[2])
    print(socket.htons(eth_header_unpacked[2]))
    #eth_type = socket.htons(eth_header_unpacked[2])
    eth_type=get_ipv(eth_header_unpacked[2])
    print(eth_type)
    data = raw_data[14:]
    return mac_dest_addr, mac_src_addr, eth_type, data

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


if __name__ == '__main__':
    # HOST = socket.gethostbyname(socket.gethostname())
    # print(HOST)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    s.bind(("10.20.0.103", 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    while True:
        raw_data, addr = s.recvfrom(65536)
        mac_dest, mac_src, eth_type, data = ethernet_head(raw_data)
        print('\nMAC Header:')
        print('Destination MAC Address: {},Source MAC Address: {},EtherType: {}'.format(mac_dest, mac_src, eth_type))



