import socket, ipaddress, psutil
from scapy.layers.l2    import ARP
from scapy.layers.inet  import Ether
from scapy.sendrecv import srp

def is_ip_address(address):
    try:
        # Check if the input is a valid IP address
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def resolve_ip_from_url(url):
    try:
        # Resolve the IP address from the URL
        ip = socket.gethostbyname(url)
        return ip
    except socket.gaierror:
        print("Error: Did not resolve ip address")
        return None

def set_ip_address(entry):
    if(is_ip_address(entry)):
        return entry;
    else:
        return resolve_ip_from_url(entry)

def get_private_ip_address(interface_name):
    addrs = psutil.net_if_addrs()  # Récupère les adresses de toutes les interfaces réseau
    if interface_name in addrs:
        for addr in addrs[interface_name]:
            if addr.family == socket.AF_INET:  # Vérifie si l'adresse est IPv4
                return addr.address
    return None

def resolve_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None
