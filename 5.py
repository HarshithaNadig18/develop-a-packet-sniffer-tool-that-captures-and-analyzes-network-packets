import socket
import struct


def unpack_ethernet_frame(data):
    dest_mac = format_mac_address(data[:6])
    src_mac = format_mac_address(data[6:12])
    eth_proto = struct.unpack('!H', data[12:14])[0]
    return dest_mac, src_mac, eth_proto, data[14:]


def format_mac_address(mac_bytes):
    mac_str = map('{:02x}'.format, mac_bytes)
    return ':'.join(mac_str).upper()

def unpack_ipv4_packet(data):
    version_and_length = data[0]
    header_length = (version_and_length & 0x0F) * 4
    ttl, proto, src_ip, dest_ip = struct.unpack('!8xBB2x4s4s', data[:20])
    return ttl, proto, format_ipv4_address(src_ip), format_ipv4_address(dest_ip), data[header_length:]


def format_ipv4_address(ip_bytes):
    return '.'.join(map(str, ip_bytes))

def main():
    # Create a raw socket and bind it to the network interface
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    
    
    raw_data, _ = conn.recvfrom(65535)
    dest_mac, src_mac, eth_proto, payload = unpack_ethernet_frame(raw_data)

    print("\nEthernet Frame:")
    print(f"Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}")

    
    if eth_proto == 0x0800:  # 0x0800 is the Ethernet protocol number for IPv4
        ttl, proto, src_ip, dest_ip, ipv4_data = unpack_ipv4_packet(payload)
        print("\nIPv4 Packet:")
        print(f"TTL: {ttl}, Protocol: {proto}, Source IP: {src_ip}, Destination IP: {dest_ip}")
        
        
        print(f"Payload Data: {ipv4_data}")

if _name_ == "_main_":
    main()

