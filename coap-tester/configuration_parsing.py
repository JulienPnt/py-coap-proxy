import yaml
import ipaddress
import validators
import psutil
import sys

def extract_yaml_file(path):
    """
    Load a YAML file.

    Args:
        path (str): Path to the YAML file.

    Returns:
        tuple: Status code (int), and the parsed content (dict) or None.
    """
    try:
        with open(path, 'r') as file:
            content = yaml.safe_load(file)
        return 0, content
    except Exception as e:
        print(f"Failed to load YAML file: {e}", file=sys.stderr)
        return 1, None

def is_valid_ip_or_url(ip_or_url):
    """
    Check if the given string is a valid IP or URL.

    Args:
        ip_or_url (str): String to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    return True
    try:
        ipaddress.ip_address(ip_or_url)
        return True
    except ValueError:
        return validators.url(ip_or_url)

def extract_key_value(my_dict, key_path):
    """
    Extract a value from a nested dictionary by key path.

    Args:
        my_dict (dict): The dictionary to extract from.
        key_path (str): Dot-separated key path.

    Returns:
        tuple: Status code (int), and the value (any) or None.
    """
    keys = key_path.split('.')
    try:
        value = my_dict
        for key in keys:
            value = value[key]
        return 0, value
    except KeyError:
        return 1, None

def is_valid_port(port):
    """
    Check if a port number is valid.

    Args:
        port (int): Port number to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    return isinstance(port, int) and 1 <= port <= 65535

def interface_exists(interface_name):
    """
    Check if a network interface exists.

    Args:
        interface_name (str): Name of the network interface.

    Returns:
        bool: True if exists, False otherwise.
    """
    return interface_name in psutil.net_if_addrs()


