from scapy.contrib.coap import CoAP

from .coap_block_options import CoAPBlockOption, get_coap_block_opt

AFORWARDED = "Forwarded"
ARECEIVED = "Received"
OCLIENT = "client"
OSERVER = "server"

coap_type = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def str_packet_info(packet, origin, action):
    if (action == AFORWARDED):
        str = f'{bcolors.OKBLUE} {action} to {origin} \
        {bcolors.ENDC}:\n{packet}'
    else:
        str = f'{bcolors.OKGREEN} {action} from {origin} \
        {bcolors.ENDC}:\n{packet}'
    if CoAP in packet:
        coap_layer = packet[CoAP]
        str += f'\nCoAP Message ID: {coap_layer.msg_id}, \
        Type: {coap_type[coap_layer.type]} ({coap_layer.type}), \
        Code: {coap_layer.code}'
        block_opt = get_coap_block_opt(coap_layer.options)
        if (block_opt is not None):
            str += f"\nBlock2 {CoAPBlockOption(block_opt).get_block_opt()}"
        else:
            str += "\nNo Block2"
    return str
