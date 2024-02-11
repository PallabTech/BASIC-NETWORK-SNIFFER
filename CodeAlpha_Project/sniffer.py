import socket
import struct

# Function to print tool name
def print_tool_name():
    print("NETWORK PACKET TRACER")
    print("---------------------->")

# Function to parse Ethernet frame
def parse_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]

# Function to parse IPv4 packet
def parse_ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src_ip, target_ip = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src_ip), ipv4(target_ip), data[header_length:]

# Function to parse TCP segment
def parse_tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = (offset_reserved_flags & 0x003f)
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

# Function to parse UDP segment
def parse_udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]

# Function to parse ICMP packet
def parse_icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Function to format IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Function to format MAC address
def get_mac_address(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Main function
def main():
    # Create a raw socket to listen for Ethernet frames
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Print tool name
    print_tool_name()

    try:
        while True:
            # Receive raw data and address
            raw_data, addr = conn.recvfrom(65535)
            
            # Parse Ethernet frame
            dest_mac, src_mac, eth_proto, data = parse_ethernet_frame(raw_data)
            
            # Print Ethernet frame information
            print('\nEthernet Frame:')
            print('Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

            # If the Ethernet protocol is IPv4
            if eth_proto == 8:
                # Parse IPv4 packet
                version, header_length, ttl, proto, src_ip, target_ip, data = parse_ipv4_packet(data)

                # Print IPv4 packet information
                print('IPv4 Packet:')
                print('Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                print('Protocol: {}, Source IP: {}, Target IP: {}'.format(proto, src_ip, target_ip))

                # If the protocol is TCP
                if proto == 6:
                    # Parse TCP segment
                    src_port, dest_port, sequence, acknowledgment, flags, data = parse_tcp_segment(data)
                    print('TCP Segment:')
                    print('Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    print('Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                    print('Flags:')
                    print('URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(
                        (flags & 0x020), (flags & 0x010), (flags & 0x008), (flags & 0x004), (flags & 0x002), (flags & 0x001)))

                # If the protocol is UDP
                elif proto == 17:
                    # Parse UDP segment
                    src_port, dest_port, length, data = parse_udp_segment(data)
                    print('UDP Segment:')
                    print('Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

                # If the protocol is ICMP
                elif proto == 1:
                    # Parse ICMP packet
                    icmp_type, code, checksum, data = parse_icmp_packet(data)
                    print('ICMP Packet:')
                    print('Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))

    # Handle keyboard interrupt
    except KeyboardInterrupt:
        print("\n[+] Exiting...")

# Entry point of the script
if __name__ == "__main__":
    main()
