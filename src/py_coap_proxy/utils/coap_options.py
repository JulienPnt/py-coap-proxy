from .constants import *
from scapy.contrib.coap import coap_options

coap_options[0].update({
    23: BLOCK2,
    27: BLOCK1
})

coap_options[1].update({
    BLOCK2: 23,
    BLOCK1: 27,
})


def extract_coap_opt(CoAP_options, option_id):
    res=[]
    for opt_tuple in CoAP_options:
        if(opt_tuple[0] == option_id):
            res.append(opt_tuple[1])
    return res

def extract_uri_host(CoAP_frame):
    return extract_coap_opt(CoAP_frame, OPT_NUM_URI_HOST)

def extract_uri_port(CoAP_frame):
    return extract_coap_opt(CoAP_frame, OPT_NUM_URI_PORT)

def extract_uri_query(CoAP_frame):
    return extract_coap_opt(CoAP_frame, OPT_NUM_URI_QUERY)

def extract_uri_path(CoAP_frame):
    uri_path_list=extract_coap_opt(CoAP_frame, OPT_NUM_URI_PATH)
    uri_path_list=map(lambda hex_value: hex_value.decode('ascii'), uri_path_list)
    uri_path='/'.join(uri_path_list)
    return uri_path

def extract_block1_option(CoAP_frame):
    try:
        value=extract_coap_opt(CoAP_frame, BLOCK1)[0]
    except:
        value=None
    return (BLOCK1, value)

def extract_block2_option(CoAP_frame):
    try:
        value=extract_coap_opt(CoAP_frame, BLOCK2)[0]
    except:
        value=None
    return (BLOCK2, value)

def set_coap_opt(CoAP_options, option_id, option_value):
    for opt_tuple in CoAP_options:
        if(opt_tuple[0] == option_id):
            opt_tuple[1]=option_value
            return 0
    return 1

def set_block2_option(CoAP_options, option_value):
    return set_coap_opt(CoAP_options, BLOCK2, option_value)

def set_block1_option(CoAP_options, option_value):
    return set_coap_opt(CoAP_options, BLOCK1, option_value)
