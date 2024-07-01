import socket
import struct
import random

def create_dhcp_discover():
    transaction_id = random.randint(0, 0xFFFFFFFF)
    mac_address = b'\xDE\xAD\xBE\xEF\x00\x01'  # Exemplo de MAC Address

    dhcp_discover = b''
    dhcp_discover += b'\x01'  # Message type: Boot Request (1)
    dhcp_discover += b'\x01'  # Hardware type: Ethernet
    dhcp_discover += b'\x06'  # Hardware address length: 6
    dhcp_discover += b'\x00'  # Hops: 0
    dhcp_discover += struct.pack('>I', transaction_id)  # Transaction ID
    dhcp_discover += b'\x00\x00'  # Seconds elapsed: 0
    dhcp_discover += b'\x80\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
    dhcp_discover += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
    dhcp_discover += b'\x00\x00\x00\x00'  # Your (client) IP address: 0.0.0.0
    dhcp_discover += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
    dhcp_discover += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
    dhcp_discover += mac_address + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client MAC address + padding
    dhcp_discover += b'\x00' * 64  # Server host name not given
    dhcp_discover += b'\x00' * 128  # Boot file name not given
    dhcp_discover += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
    dhcp_discover += b'\x35\x01\x01'  # Option: (53) DHCP Message Type (Discover)
    dhcp_discover += b'\xff'  # End Option

    return dhcp_discover

def send_dhcp_packet(packet):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(packet, ('<broadcast>', 67))

def main():
    dhcp_discover_packet = create_dhcp_discover()
    send_dhcp_packet(dhcp_discover_packet)
    print("DHCP Discover packet sent to port 67.")

if __name__ == "__main__":
    main()
