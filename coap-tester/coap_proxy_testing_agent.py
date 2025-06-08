import sys, os
from enum import Enum
import configuration_parsing
import asyncio

from scapy.interfaces import conf
from scapy.layers.inet import Ether, IP, UDP
from scapy.arch import get_if_hwaddr
from scapy.packet import Packet
from scapy.contrib.coap import CoAP
from scapy.contrib.coap import coap_options, coap_codes

from py_coap_proxy import CoAPProxy
from py_coap_proxy.utils.coap_block_options import *
from py_coap_proxy.utils.logs import *
from py_coap_proxy.utils.coap_options import *
from py_coap_proxy.utils.constants import *
from actions import get_delay_duration, get_new_coap_code

from selector_and_descriptor import get_packet_descriptor, compare_descriptor_to_selector

ACTION_OPTS_KEY='opts'
ACTION_NAME_DELAY='delay'

class TestCoAP(CoAPProxy):

    def __init__(self, 
        test_configuration_path,
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0',
        logger_filename=f'/tmp/coap_proxy_test'):
        status, self.configuration=configuration_parsing.extract_yaml_file(test_configuration_path)
        if (status != 0):
            print("Failed to extract configuration", file=sys.stderr)
            sys.exit(1)
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, logger_filename=logger_filename)
        self.request_answer_index=0
        self.test_scenario_running=True
        
        self.current_test_index=1
        self.current_test_application_counter=0
        self.current_test_application_limit=0

        # For TEST 1
        self.display_new_test()

    def content_extraction(self, key_path, validation_func=None):
        status, value = configuration_parsing.extract_key_value(self.configuration, key_path)
        if status != 0 or (validation_func and not validation_func(value)):
            #print(f"Failed to extract or validate {key_path}", file=sys.stderr)
            return None, f"Failed to extract or validate {key_path}"
        return value, None

    def extract_test(self):
        test, _ = self.content_extraction(f'test_{self.current_test_index}')
        if test == None:
            self.test_scenario_running=False
            return 1, None
        return 0, test

    def update_current_test_application_limit(self):
        res, _ = self.content_extraction(f'test_{self.current_test_index}.repetition')
        if res is None:
            self.current_test_application_limit=1
        else:
            self.current_test_application_limit=res

    def increase_current_test_application_counter(self):
        self.current_test_application_counter += 1

    def update_current_test_index_and_application_counter(self):
        if self.current_test_application_counter < self.current_test_application_limit:
            return
        else:
            self.current_test_application_counter=0
            self.current_test_index+=1
            self.update_testing_scenario_running()
            if(self.test_scenario_running == False):
                return
            self.update_current_test_application_limit()
            self.display_new_test()

    def update_testing_scenario_running(self):
        if(self.check_if_current_test_index_exists() == False):
            self.test_scenario_running=False

    def check_if_current_test_index_exists(self):
        status, test = self.extract_test()
        if status != 0 or test == None:
            return False
        return True

    def extract_selector(self):
        status, test = self.extract_test()
        if status != 0 or test == None:
            print(f"Failed to extract test_{self.current_test_index}", file=sys.stderr)
            return 1, None
        status, selector = configuration_parsing.extract_key_value(test, 'selector')
        if status != 0 or selector==None:
            return 2, None
        return 0, selector

    def apply_selector(self):
        status, selector = self.extract_selector()
        if status != 0 or selector == None:
            print(f"Failed to extract selector on test_{self.current_test_index}", file=sys.stderr)
            return 1, None
        return 0, None
    
    def extract_action(self):
        status, test = self.extract_test()
        if status != 0 or test == None:
            print(f"Failed to extract test_{self.current_test_index}", file=sys.stderr)
            return 1, None
        status, action = configuration_parsing.extract_key_value(test, 'action')
        if status != 0 or action == None:
            return 2, None
        return 0, action
    
    async def apply_action(self, packet, forward_function):
        status, action = self.extract_action()
        if status != 0 or not isinstance(action, dict):
            return 1, "Failed to extract action"
        elif not 'name' in action:
            return 2, "Action does not have a name"
        name=action['name']
        match name:
            case 'delay':
                _, opts = configuration_parsing.extract_key_value(action, ACTION_OPTS_KEY)
                duration = get_delay_duration(opts)
                self.logger.debug(f"Packet is delayed of {duration}")
                await asyncio.sleep(duration)
                await forward_function(packet)
            case 'skip':
                packet[IP].dst = "0.0.0.0"
                self.logger.debug(f"Packet is skipped")
                await self.forward_to_null(packet)
            case 'forward':
                self.logger.debug("Expected packet has been detected")
                await forward_function(packet)
            case 'change_coap_code':
                _, opts = configuration_parsing.extract_key_value(action, ACTION_OPTS_KEY)
                new_coap_code = get_new_coap_code(opts)
                current_coap_code = getattr(packet[CoAP], 'code', None)
                if current_coap_code is not None:
                    current_coap_code=coap_codes.get(current_coap_code)
                self.logger.debug(f"Change current CoAP code {current_coap_code} with {new_coap_code}")
                packet[CoAP].code = new_coap_code
                await forward_function(packet)
            case _ :
                self.logger.debug(f"Unknown action name: {name}")
                return 3, f"Unknown action name {name}"

    def is_selector_matched(self, packet):
        status, selector = self.extract_selector()
        if status != 0:
            return False, "No selector"
        packet_descriptor=get_packet_descriptor(packet)
        return compare_descriptor_to_selector(selector, packet_descriptor)

    def display_new_test(self):
        _, selector = self.extract_selector()
        _, action = self.extract_action()
        print(f"\n" + "*"*20)
        print(f"{bcolors.HEADER} TEST_{self.current_test_index} STARTING! {bcolors.ENDC}")
        print(f"selector: {selector}")
        print(f"action: {action}")
        print(f"repetition: {self.current_test_application_limit}")
        print(f"*"*20 + "\n")

    async def handle_packet(self, packet, role, forward_function, sport_attribute):
        """
        Handle a packet generically for client or server.

        Args:
            packet: The packet to handle.
            role: The role of the handler (e.g., OCLIENT or OSERVER).
            forward_function: Function to forward the packet (e.g., forward_to_server or forward_to_client).
            sport_attribute: Attribute name to set the source port (e.g., 'client_sport' or 'server_sport').
        """
        setattr(self, sport_attribute, packet[UDP].sport)
        await self.log_with_lock_lambda(packet, role, ARECEIVED)
        self.update_testing_scenario_running()
        if self.test_scenario_running == False:
            self.logger.debug(f"packet_descriptor={get_packet_descriptor(packet)}")
            await forward_function(packet)
            return
        status, selector = self.extract_selector()
        if status != 0 or selector is None:
            self.logger.error("No selector provided")
        else:
            #self.logger.debug(f"selector={selector}")
            self.logger.debug(f"packet_descriptor={get_packet_descriptor(packet)}")
            match, message = self.is_selector_matched(packet)
            if match:
                self.logger.debug(f"<SELECTOR RESULT>: {bcolors.OKCYAN} MATCH ! {bcolors.ENDC}")
                await self.apply_action(packet, forward_function)
                self.update_current_test_application_limit()
                self.increase_current_test_application_counter()
                self.update_current_test_index_and_application_counter()
                return
            else:
                self.logger.debug(f"<SELECTOR RESULT>: {bcolors.UNDERLINE} {message} {bcolors.ENDC}")
                await forward_function(packet)
                return

    async def handle_client_packet(self, packet):
        """
        Handle a packet from the client.

        Args:
            packet: The packet to handle.
        """
        print("\n" + "=" * 20 + f" REQUEST/ANSWER: ({self.request_answer_index})")
        self.request_answer_index += 1
        await self.handle_packet(packet, OCLIENT, self.forward_to_server, 'client_sport')

    async def handle_server_packet(self, packet):
        """
        Handle a packet from the server.

        Args:
            packet: The packet to handle.
        """
        await self.handle_packet(packet, OSERVER, self.forward_to_client, 'server_sport')
