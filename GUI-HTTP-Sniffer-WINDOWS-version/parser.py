import ipaddress
import struct


def ipv4_unpack(raw_data):
    ipv4_dict = {}
    ipv4_header_unpacked = struct.unpack("! B B H H H B B H 4s 4s", raw_data)
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


def tcp_unpack(raw_data):
    tcp_dict = {}
    tcp_header_unpacked = struct.unpack("! H H L L H H H H", raw_data)
    tcp_dict["Source port"] = tcp_header_unpacked[0]
    tcp_dict["Destination port"] = tcp_header_unpacked[1]
    tcp_dict["Sequence number"] = tcp_header_unpacked[2]
    tcp_dict["Acknowledgement number"] = tcp_header_unpacked[3]
    tcp_dict["Header length"] = tcp_header_unpacked[4] >> 12
    tcp_dict["Reserved bits"] = (tcp_header_unpacked[4] >> 6) & 0b0000111111
    tcp_dict["Flags"] = tcp_header_unpacked[4] & 0b0000000000111111
    tcp_dict["Window size"] = tcp_header_unpacked[5]
    tcp_dict["Check sum"] = tcp_header_unpacked[6]
    tcp_dict["Urgent pointer"] = tcp_header_unpacked[7]
    return tcp_dict


def http_decode(raw_data):
    hex_string = raw_data.hex()
    new_string_without_00 = ""
    for i in range(0, len(hex_string), 2):
        if hex_string[i:i + 2] != "00":
            new_string_without_00 += hex_string[i:i + 2]
    http_string_decoded = ""
    for i in range(0, len(new_string_without_00), 2):
        http_string_decoded += chr(int(new_string_without_00[i:i + 2], 16))
    return http_string_decoded
