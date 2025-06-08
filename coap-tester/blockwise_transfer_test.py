from scapy.contrib.coap import CoAP
from scapy.layers.inet import UDP

from py_coap_proxy.utils.coap_block_options import *
from py_coap_proxy.utils.logs import *

from general_test import TestCoAP, ERROR_403, ERROR_408

class TestCoAP_Block_Num_To_Delay(TestCoAP):

    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0',
        num_of_block_to_delay=0,
        occurence = 1):

        self.num_of_block_to_delay = num_of_block_to_delay
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, logger_filename=f'/tmp/TestCoAP_Block{self.num_of_block_to_delay}_Num0_Delayed.txt')
        # Used to ensure that the block2 num 1 packet is delayed once
        self.occurence = occurence
        self.occurence_count = 0

    async def handle_server_packet(self, packet):
        self.server_sport = packet[UDP].sport
        await self.log_with_lock_lambda(packet, OSERVER, ARECEIVED)
        try:
            block_opt = get_coap_block_opt(packet[CoAP].options)
            if (block_opt is not None and block_opt[0] == BLOCK2 and CoAPBlockOption(block_opt).num == 0 and self.occurence_count < self.occurence):
                self.occurence_count += 1
                await self.log_with_lock(f"{bcolors.WARNING} Packet is delayed! {bcolors.ENDC}")
                await self.forward_to_client_delayed(packet, delay=5)
            else:
                await self.forward_to_client(packet)
        except:
            raise ValueError(f"Error package is not CoAP")

class TestCoAP_Block_Num_To_Delay_One_Time(TestCoAP_Block_Num_To_Delay):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0',
        num_of_block_to_delay=0):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, num_of_block_to_delay, occurence=1)

class TestCoAP_Block2_Num0_Delayed(TestCoAP_Block_Num_To_Delay_One_Time):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, num_of_block_to_delay=0)

class TestCoAP_Block2_Num1_Delayed(TestCoAP_Block_Num_To_Delay_One_Time):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface)

class TestCoAP_Block2_Num2_Delayed(TestCoAP_Block_Num_To_Delay_One_Time):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface)

class TestCoAP_Block_Num_To_Delay_Two_Time(TestCoAP_Block_Num_To_Delay):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0',
        num_of_block_to_delay=0):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, num_of_block_to_delay, occurence=2)

class TestCoAP_Block2_Num0_Delayed_Two_Time(TestCoAP_Block_Num_To_Delay_Two_Time):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, num_of_block_to_delay=0)

class TestCoAP_Block2_Num1_Delayed_Two_Time(TestCoAP_Block_Num_To_Delay_Two_Time):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface)

class TestCoAP_Block2_Num2_Delayed_Two_Time(TestCoAP_Block_Num_To_Delay_Two_Time):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface)

class TestCoAP_Block_Num_To_Lost(TestCoAP):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0',
        num_of_block_to_lost=0,
        occurence = 1):

        self.num_of_block_to_lost = num_of_block_to_lost
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface)
        self.occurence = occurence
        self.occurence_count = 0

    async def handle_server_packet(self, packet):
        self.server_sport = packet[UDP].sport
        await self.log_with_lock_lambda(packet, OSERVER, ARECEIVED)
        block_opt = get_coap_block_opt(packet[CoAP].options)
        if (block_opt is not None and block_opt[0] == BLOCK2 and CoAPBlockOption(block_opt).num == self.num_of_block_to_lost and self.occurence_count < self.occurence):
            self.occurence_count += 1
            await self.log_with_lock(f"{bcolors.WARNING} Packet is lost! {bcolors.ENDC}")
            return
        else:
            await self.forward_to_client(packet)

class TestCoAP_Block_Num_To_Lost_One_Time(TestCoAP_Block_Num_To_Lost):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0',
        num_of_block_to_lost=0):
        
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, num_of_block_to_lost, occurence = 1)

class TestCoAP_Block2_Num0_Lost(TestCoAP_Block_Num_To_Lost_One_Time):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, num_of_block_to_lost=0)

class TestCoAP_Block2_Num1_Lost(TestCoAP_Block_Num_To_Lost_One_Time):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, num_of_block_to_lost=1)

class TestCoAP_Block2_Num2_Lost(TestCoAP_Block_Num_To_Lost_One_Time):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, num_of_block_to_lost=2)

class TestCoAP_Block_Num_To_Lost_Two_Time(TestCoAP_Block_Num_To_Lost):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0',
        num_of_block_to_lost=0):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, num_of_block_to_lost, occurence = 2)

class TestCoAP_Block2_Num0_Lost_Two_Time(TestCoAP_Block_Num_To_Lost_Two_Time):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, num_of_block_to_lost=0)

class TestCoAP_Block2_Num1_Lost_Two_Time(TestCoAP_Block_Num_To_Lost_Two_Time):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, num_of_block_to_lost=1)

class TestCoAP_Block2_Num2_Lost_Two_Time(TestCoAP_Block_Num_To_Lost_Two_Time):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, num_of_block_to_lost=2)

class TestCoAP_Block2_Num_Switch_Num(TestCoAP):
    def __init__(self, 
        client_ip="localhost", 
        server_ip="localhost", 
        client_dport=5683, 
        server_dport=5683, 
        client_iface='enp2s0', 
        server_iface='enp2s0',
        proxy_iface='enp2s0',
        num_of_block_to_replace=0,
        num_of_block_to_send=0):

        self.num_of_block_to_replace = num_of_block_to_replace
        self.num_of_block_to_send   = num_of_block_to_send
        self.test_flag = False

        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface)

    async def handle_client_packet(self, packet):
        self.client_sport = packet[UDP].sport
        await self.log_with_lock_lambda(packet, OCLIENT, ARECEIVED)
        block_opt = get_coap_block_opt(packet[CoAP].options)
        print("block opt:", block_opt)
        if (block_opt is not None and block_opt[0] == BLOCK2 and CoAPBlockOption(block_opt).num == self.num_of_block_to_replace and self.test_flag == False):
            self.test_flag = True
            await self.log_with_lock(f"{bcolors.WARNING} Packet is going to be switch from {self.num_of_block_to_replace} to {self.num_of_block_to_send} ! {bcolors.ENDC}")
            new_block_opt = create_coap_block_option(num=self.num_of_block_to_send, m=CoAPBlockOption(block_opt).m, szx=CoAPBlockOption(block_opt).szx)
            packet[CoAP].options = set_coap_Block2_opt(packet[CoAP].options, new_block_opt)
        await self.forward_to_server(packet)

class TestCoAP_Block2_Num_Switch_Num1_and_Num2(TestCoAP_Block2_Num_Switch_Num):
        def __init__(self, 
            client_ip="localhost", 
            server_ip="localhost", 
            client_dport=5683, 
            server_dport=5683, 
            client_iface='enp2s0', 
            server_iface='enp2s0',
            proxy_iface='enp2s0'):
            super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, 
                             server_iface, proxy_iface, num_of_block_to_replace=1, num_of_block_to_send=2)

class TestCoAP_Block2_Num_Switch_Num2_and_Num1(TestCoAP_Block2_Num_Switch_Num):
        def __init__(self, 
            client_ip="localhost", 
            server_ip="localhost", 
            client_dport=5683, 
            server_dport=5683, 
            client_iface='enp2s0', 
            server_iface='enp2s0',
            proxy_iface='enp2s0'):
            super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, 
                             server_iface, proxy_iface, num_of_block_to_replace=2, num_of_block_to_send=1)

class TestCoap_Send_ErrorMessage_To_Specific_Block(TestCoAP):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0',
                 error=ERROR_403,
                 block_num=0,
                 occurence=1):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface)
        self.occurence = occurence
        self.occurence_count = 0
        self.block_num = block_num
        self.error = error

    async def handle_server_packet(self, packet):
        self.server_sport = packet[UDP].sport
        await self.log_with_lock_lambda(packet, OSERVER, ARECEIVED)
        block_opt = get_coap_block_opt(packet[CoAP].options)
        if (block_opt is not None and block_opt[0] == BLOCK2 and CoAPBlockOption(block_opt).num == 0 and self.occurence_count < self.occurence):
            self.occurence_count += 1
            await self.log_with_lock(f"{bcolors.WARNING} Packet is replace by error: {self.error} ! {bcolors.ENDC}")
            await self.forward_error_to_client(packet, self.error)
        else:
            await self.forward_to_client(packet)

class TestCoap_Send_ErrorMessage_To_Specific_Block_Once(TestCoap_Send_ErrorMessage_To_Specific_Block):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0', 
                 block_num = 0,
                 error = ""):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, occurence=1, block_num=block_num, error=error)

class TestCoap_Send_ErrorMessage403_To_Specific_Block_Once(TestCoap_Send_ErrorMessage_To_Specific_Block):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0', 
                 block_num = 0,
                 error = ""):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, occurence=1, block_num=block_num, error=ERROR_403)

class TestCoap_Send_ErrorMessage408_To_Specific_Block_Once(TestCoap_Send_ErrorMessage_To_Specific_Block):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0', 
                 block_num = 0,
                 error = ""):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, occurence=1, block_num=block_num, error="404")


class TestCoap_Send_ErrorMessage403_To_Block0_Once(TestCoap_Send_ErrorMessage403_To_Specific_Block_Once):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, block_num=0)

class TestCoap_Send_ErrorMessage403_To_Block1_Once(TestCoap_Send_ErrorMessage403_To_Specific_Block_Once):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, block_num=1)

class TestCoap_Send_ErrorMessage403_To_Block2_Once(TestCoap_Send_ErrorMessage403_To_Specific_Block_Once):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, block_num=2)

class TestCoap_Send_ErrorMessage408_To_Block0_Once(TestCoap_Send_ErrorMessage408_To_Specific_Block_Once):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, block_num=0)

class TestCoap_Send_ErrorMessage408_To_Block1_Once(TestCoap_Send_ErrorMessage408_To_Specific_Block_Once):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, block_num=1)

class TestCoap_Send_ErrorMessage408_To_Block2_Once(TestCoap_Send_ErrorMessage408_To_Specific_Block_Once):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, block_num=2)

class TestCoap_Send_ErrorMessage_To_Specific_Block_Twice(TestCoap_Send_ErrorMessage_To_Specific_Block):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0', 
                 block_num = 0,
                 error = ""):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, occurence=2, block_num=block_num, error=error)

class TestCoap_Send_ErrorMessage403_To_Block0_Twice(TestCoap_Send_ErrorMessage_To_Specific_Block_Twice):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, block_num=0, error=ERROR_403)

class TestCoap_Send_ErrorMessage403_To_Block1_Twice(TestCoap_Send_ErrorMessage_To_Specific_Block_Twice):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, block_num=1, error="403")

class TestCoap_Send_ErrorMessage403_To_Block2_Twice(TestCoap_Send_ErrorMessage_To_Specific_Block_Twice):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, block_num=2, error=ERROR_403)

class TestCoap_Send_ErrorMessage408_To_Block0_Twice(TestCoap_Send_ErrorMessage_To_Specific_Block_Twice):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, block_num=0, error="404")

class TestCoap_Send_ErrorMessage408_To_Block1_Twice(TestCoap_Send_ErrorMessage_To_Specific_Block_Twice):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, block_num=1, error="404")

class TestCoap_Send_ErrorMessage408_To_Block2_Twice(TestCoap_Send_ErrorMessage_To_Specific_Block_Twice):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0'):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface, block_num=2, error="404")


class TestCoap_Send_ErrorMessage_To_Last_Block(TestCoAP):
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0',
                 error=ERROR_403,
                 block_num=0,
                 occurence=1):
        super().__init__(client_ip, server_ip, client_dport, server_dport, client_iface, server_iface, proxy_iface)
        self.occurence = occurence
        self.occurence_count = 0
        self.block_num = block_num
        self.error = error

    async def handle_server_packet(self, packet):
        self.server_sport = packet[UDP].sport
        await self.log_with_lock_lambda(packet, OSERVER, ARECEIVED)
        block_opt = get_coap_block_opt(packet[CoAP].options)
        if (block_opt is not None and block_opt[0] == BLOCK2 and CoAPBlockOption(block_opt).m == 0 and self.occurence_count < self.occurence ):
            self.occurence_count += 1
            await self.log_with_lock(f"{bcolors.WARNING} Packet is skipped ! {self.error} ! {bcolors.ENDC}")
            #await self.forward_error_to_client(packet, self.error)
        else:
            await self.forward_to_client(packet)
