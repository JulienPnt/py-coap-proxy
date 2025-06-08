from scapy.layers.inet import Ether, IP, UDP
from scapy.contrib.coap import CoAP
from scapy.contrib.coap import coap_options, coap_codes

from py_coap_proxy.coap_proxy import CoAPProxy
from py_coap_proxy.utils.logs import str_packet_info, AFORWARDED, ARECEIVED, OCLIENT, OSERVER
from py_coap_proxy.utils.coap_block_options import *
from py_coap_proxy.utils.logs import *
from py_coap_proxy.utils.coap_options import *
from py_coap_proxy.utils.constants import *

def get_packet_descriptor(packet):
    descriptor = {}
    descriptor['ip_source'] = getattr(packet[IP], 'src', None)
    descriptor['ip_dest'] = getattr(packet[IP], 'dst', None)
    descriptor['ip_source'] = None
    descriptor['ip_dest'] = None

    descriptor['port_source'] = getattr(packet[UDP], 'sport', None)
    descriptor['port_dest'] = getattr(packet[UDP], 'dport', None)

    descriptor['code'] = getattr(packet[CoAP], 'code', None)
    if descriptor['code'] is not None:
        descriptor['code']=coap_codes.get(descriptor['code'])
    descriptor['msg_type'] = getattr(packet[CoAP], 'type', None)
    if descriptor['msg_type'] is not None:
        descriptor['msg_type']=Coap_type.get(descriptor['msg_type'])
    descriptor['token'] = getattr(packet[CoAP], 'token', None)
    descriptor['msg_id'] = getattr(packet[CoAP], 'msg_id', None)

    descriptor['uri'] = {}
    try:
        options = getattr(packet[CoAP], 'options', None)
        descriptor['uri']['host'] = extract_uri_host(options) if options else None
        descriptor['uri']['port'] = extract_uri_port(options) if options else None
        descriptor['uri']['query'] = extract_uri_query(options) if options else None
        descriptor['uri']['path'] = extract_uri_path(options) if options else None
    except Exception:
        descriptor['uri'] = {'host': None, 'port': None, 'query': None, 'path': None}

    try:
        block1_opt = CoAPBlockOption(extract_block1_option(getattr(packet[CoAP], 'options', None)))
        descriptor['block1'] = {'num': block1_opt.num, 'm': block1_opt.m, 'szx': block1_opt.szx}
    except Exception:
        descriptor['block1'] = {'num': None, 'm': None, 'szx': None}

    try:
        block2_opt = CoAPBlockOption(extract_block2_option(getattr(packet[CoAP], 'options', None)))
        descriptor['block2'] = {'num': block2_opt.num, 'm': block2_opt.m, 'szx': block2_opt.szx}
    except Exception:
        descriptor['block2'] = {'num': None, 'm': None, 'szx': None}

    return descriptor

def compare_descriptor_to_selector(selector, descriptor):
    """
    Compare the descriptor with the selector, considering only keys with None values in the selector.

    Args:
        selector (dict): The selector dictionary with optional values.
        descriptor (dict): The descriptor dictionary to validate.

    Returns:
        tuple: (bool, str) - A boolean indicating if the descriptor matches and an error message if not.
    """

    for key1, selector_value in selector.items():
        if isinstance(selector_value, dict):
            for key2, sub_selector_value in selector_value.items():
                if sub_selector_value is None:
                    continue
                elif not isinstance(descriptor[key1], dict):
                    return False, f"Key '{key1}' is missing or not a dictionary in descriptor."
                elif key1 not in descriptor or key2 not in descriptor[key1]:
                    return False, f"Key '{key2}' is missing in descriptor[{key1}]."
                elif sub_selector_value != descriptor[key1][key2]:
                    return False, f"Mismatch in descriptor[{key1}][{key2}]: Expected {sub_selector_value}, got {descriptor[key1][key2]}."
        else:
            if selector_value is None:
                continue
            elif key1 not in descriptor:
                return False, f"Key '{key1}' is missing in descriptor."
            elif selector_value != descriptor[key1]:
                return False, f"Mismatch in descriptor[{key1}]: Expected {selector_value}, got {descriptor[key1]}."
    return True, "Validation passed."

