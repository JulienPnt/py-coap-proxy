import socket
import ipaddress
import psutil
from scapy.layers.l2 import ARP
from scapy.layers.inet import Ether
from scapy.sendrecv import srp


def is_ip_address(address):
    """
    Check if the given address is a valid IP address.

    Args:
        address (str): The address to check.

    Returns:
        bool: True if the address is a valid IP address, False otherwise.
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def resolve_ip_from_url(url):
    """
    Resolve the IP address from a given URL.

    Args:
        url (str): The URL to resolve.

    Returns:
        str or None: The resolved IP address as a string,
        or None if resolution fails.
    """
    try:
        ip = socket.gethostbyname(url)
        return ip
    except socket.gaierror:
        print("Error: Did not resolve IP address")
        return None


def set_ip_address(entry):
    """
    Return the IP address if the entry is a valid IP,
    otherwise resolve it from a URL.

    Args:
        entry (str): The IP address or URL to process.

    Returns:
        str: The IP address as a string.
    """
    if is_ip_address(entry):
        return entry
    else:
        return resolve_ip_from_url(entry)


def get_private_ip_address(interface_name):
    """
    Retrieve the private IP address associated with
    a specific network interface.

    Args:
        interface_name (str): The name of the network interface.

    Returns:
        str or None: The private IP address associated with the interface,
        or None if not found.
    """
    addrs = psutil.net_if_addrs()
    if interface_name in addrs:
        for addr in addrs[interface_name]:
            if addr.family == socket.AF_INET:  # Check if the address is IPv4
                return addr.address
    return None


def resolve_mac(ip):
    """
    Resolve the MAC address corresponding to a given IP address using ARP.

    Args:
        ip (str): The IP address to resolve.

    Returns:
        str or None: The resolved MAC address,
        or None if no response is received.
    """
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None
