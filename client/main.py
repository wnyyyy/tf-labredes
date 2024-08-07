from scapy.all import Ether, IP, UDP, BOOTP, DHCP, RandMAC, sendp, sniff
import requests
import random
import os
import subprocess

def configure_interface(interface, ip, gateway):
    # Seta o endereço IP na interface
    subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', interface])
    subprocess.run(['sudo', 'ip', 'addr', 'add', f'{ip}/24', 'dev', interface])
    subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'])

    # Seta o default gateway
    subprocess.run(['sudo', 'ip', 'route', 'add', 'default', 'via', gateway])

def send_dhcp_discover(interface, client_mac, transaction_id):
    chaddr = bytes.fromhex(client_mac.replace(":", ""))
    dhcp_discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=client_mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=chaddr, xid=transaction_id) /
        DHCP(options=[("message-type", 1), "end"])
    )

    print(f"Enviando DHCP DISCOVER do MAC: {client_mac}")
    sendp(dhcp_discover, iface=interface, verbose=True)

def handle_dhcp_response(packet, client_mac, transaction_id, interface):
    if DHCP in packet:
        dhcp_type = packet[DHCP].options[0][1]
        if dhcp_type == 2:  # DHCP Offer
            if packet[Ether].dst != client_mac:
                print(f"Pacote ignorado, não é para esse MAC: {packet[Ether].dst}")
                return None

            if packet[BOOTP].xid != transaction_id:
                print(f"Pacote ignorado, id da transação não confere: {packet[BOOTP].xid}")
                return None

            offered_ip = packet[BOOTP].yiaddr
            gateway_ip = None
            for option in packet[DHCP].options:
                if option[0] == "router":
                    gateway_ip = option[1]

            if gateway_ip:
                print(f"Recebido DHCP OFFER: IP = {offered_ip}, Gateway IP = {gateway_ip}")
                send_dhcp_request(interface, client_mac, transaction_id, offered_ip, gateway_ip)
                return gateway_ip
        elif dhcp_type == 5:  # DHCP ACK
            if packet[Ether].dst != client_mac:
                print(f"Pacote ignorado packet, não é para esse MAC: {packet[Ether].dst}")
                return None

            if packet[BOOTP].xid != transaction_id:
                print(f"Pacote ignorado, id da transação não confere: {packet[BOOTP].xid}")
                return None

            assigned_ip = packet[BOOTP].yiaddr
            gateway_ip = None
            for option in packet[DHCP].options:
                if option[0] == "router":
                    gateway_ip = option[1]

            if assigned_ip and gateway_ip:
                print(f"Recebido DHCP ACK: Atribuído IP = {assigned_ip}, Gateway IP = {gateway_ip}")
                configure_interface(interface, assigned_ip, gateway_ip)
                make_http_request(gateway_ip)
                return gateway_ip
        else:
            print(f"Recebido pacote DHCP do tipo {dhcp_type}")
    else:
        print("Pacote não DHCP recebido")

def send_dhcp_request(interface, client_mac, transaction_id, offered_ip, gateway_ip):
    chaddr = bytes.fromhex(client_mac.replace(":", ""))
    dhcp_request = (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=chaddr, xid=transaction_id) /
        DHCP(options=[
            ("message-type", 3),  # DHCP REQUEST
            ("requested_addr", offered_ip),
            ("server_id", gateway_ip),
            ("param_req_list", [1, 3, 6, 15, 31, 33, 43, 119, 121, 252, 255]),
            "end"
        ])
    )

    print(f"Enviando DHCP REQUEST para o IP: {offered_ip}")
    sendp(dhcp_request, iface=interface, verbose=True)

def sniff_dhcp(interface, client_mac, transaction_id):
    def custom_action(packet):
        handle_dhcp_response(packet, client_mac, transaction_id, interface)

    print(f"Iniciando captura de pacotes na interface: {interface}, MAC: {client_mac}")
    sniff(filter="udp and (port 67 or port 68)", prn=custom_action, iface=interface, store=0)

def make_http_request(gateway_ip):
    os.environ['http_proxy'] = f'http://{gateway_ip}:80'
    os.environ['https_proxy'] = f'http://{gateway_ip}:80'
    
    try:
        response = requests.get('http://example.com')
        print(f"Resposta de example.com: {response.status_code}")
        print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"HTTP request falhou: {e}")

if __name__ == "__main__":
    interface = "veth1"  # Interface virtual
    client_mac = str(RandMAC())  # Gera um endereço MAC aleatorio
    transaction_id = random.randint(0, 0xFFFFFFFF)  # Gera um id de transação aleatório

    print(f"Endereço MAC gerado: {client_mac}")
    print(f"ID de transação gerado: {transaction_id}")

    # Envia DHCP Discover
    send_dhcp_discover(interface, client_mac, transaction_id)

    # Captura respostas DHCP
    sniff_dhcp(interface, client_mac, transaction_id)
