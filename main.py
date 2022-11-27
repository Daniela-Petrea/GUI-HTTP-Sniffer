import ipaddress
import socket
import struct


def get_ip_version(ether_type):
    if ether_type == 0x0800:
        return 4
    elif ether_type == 0x86DD:
        return 6


def ethernet_header(raw_data):
    ethernet_dict = {}
    eth_header = raw_data[:14]
    eth_header_unpacked = struct.unpack('! 6s 6s H', eth_header)
    ethernet_dict["MAC Destination Address"] = get_mac_addr(eth_header_unpacked[0])
    ethernet_dict["MAC Source Address"] = get_mac_addr(eth_header_unpacked[1])
    ethernet_dict["Ethernet Type"] = get_ip_version(eth_header_unpacked[2])
    ethernet_dict["Data (payload)"] = raw_data[14:]
    return ethernet_dict


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv4_unpack(info_ethernet):
    ipv4_dict = {}
    ipv4_header = info_ethernet[:20]
    ipv4_header_unpacked = struct.unpack("! B B H H H B B H 4s 4s", ipv4_header)
    ipv4_dict["Version"] = ipv4_header_unpacked[0] >> 4
    ipv4_dict["IHL"] = ipv4_header_unpacked[0] & 0b1111
    ipv4_dict["Type of service"] = ipv4_header_unpacked[1]
    ipv4_dict["Total length"] = ipv4_header_unpacked[2]
    ipv4_dict["Identification"] = ipv4_header_unpacked[3]
    if (ipv4_header_unpacked[4] >> 13) == 1:
        ipv4_dict["Flags"] = "DF"
    else:
        ipv4_dict["Flags"] = "MF"
    ipv4_dict["Fragment offset"] = ipv4_header_unpacked[4] & 0b0001111111111111
    ipv4_dict["Time to live"] = ipv4_header_unpacked[5]
    ipv4_dict["Protocol"] = ipv4_header_unpacked[6]
    ipv4_dict["Header checksum"] = ipv4_header_unpacked[7]
    ipv4_dict["Source address"] = str(ipaddress.IPv4Address(ipv4_header_unpacked[8]))
    ipv4_dict["Destination address"] = str(ipaddress.IPv4Address(ipv4_header_unpacked[9]))
    return ipv4_dict


def ipv6_unpack(info_ethernet):
    ipv6_dict = {}
    ipv6_header = info_ethernet[:40]
    ipv6_header_unpacked = struct.unpack("! L H B B 16s 16s", ipv6_header)
    ipv6_dict["Version"] = ipv6_header_unpacked[0] >> 28
    ipv6_dict["Traffic class"] = (ipv6_header_unpacked[0] >> 20) & 0b000011111111
    ipv6_dict["Flow label"]=ipv6_header_unpacked[0]&0b00000000000011111111111111111111
    ipv6_dict["Payload length"]=ipv6_header_unpacked[1]
    ipv6_dict["Next header"]=ipv6_header_unpacked[2]
    ipv6_dict["Hop limit"]=ipv6_header_unpacked[3]
    ipv6_dict["Source address"]=str(ipaddress.IPv6Address(ipv6_header_unpacked[4]))
    ipv6_dict["Destination address"]=str(ipaddress.IPv6Address(ipv6_header_unpacked[5]))
    return ipv6_dict


if __name__ == '__main__':
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    while True:
        raw_data, addr = s.recvfrom(65536)
        info_ethernet = ethernet_header(raw_data)
        print('\nMAC Header:')
        print(info_ethernet)
        if info_ethernet[list(info_ethernet)[2]] == 4:
            ipv4 = ipv4_unpack(info_ethernet[list(info_ethernet)[3]])
            print('\t - ' + 'IPv4 Packet:')
            print(ipv4)
        elif info_ethernet[list(info_ethernet)[2]] == 6:
            ipv6 = ipv6_unpack(info_ethernet[list(info_ethernet)[3]])
            print('\t - ' + 'IPv6 Packet:')
            print(ipv6)




