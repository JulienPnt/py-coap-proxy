import asyncio, sys, queue
from scapy.sendrecv import AsyncSniffer, sendp
from scapy.layers.inet import Ether, IP, UDP
from scapy.interfaces import conf
from scapy.arch import get_if_hwaddr
from scapy.contrib.coap import CoAP
from scapy.packet import bind_layers

import logging

from .utils.network_utils import *
from .utils.coap_block_options import *
from .utils.logs import str_packet_info, AFORWARDED, ARECEIVED, OCLIENT, OSERVER

class CoAPProxy:
    def __init__(self, 
                 client_ip="localhost", 
                 server_ip="localhost", 
                 client_dport=5683, 
                 server_dport=5683, 
                 client_iface='enp2s0', 
                 server_iface='enp2s0',
                 proxy_iface='enp2s0',
                 logger_filename='/tmp/coap-logger.txt'):

        # Logging
        self.logger_filename = logger_filename
        self.logger = logging.getLogger("coap-logger")
        logging.basicConfig(encoding='utf-8', level=logging.DEBUG, format='[%(asctime)s] <%(filename)s:%(lineno)s> %(levelname)s: %(message)s', 
                            handlers=[logging.StreamHandler(sys.stdout)])
        self.log_lock = asyncio.Lock()  # Adding a lock for logging
        self.packet_queue = queue.Queue()  # Queue for packet processing

        # Lambda function accessible to all members, now async
        self.log_with_lock_lambda = lambda packet, origin, action: self.log_with_lock(str_packet_info(packet, origin, action))
        self.log_with_lock_lambda_2 = lambda content: self.log_with_lock(content)

        self.client_ip = set_ip_address(client_ip)
        self.server_ip = set_ip_address(server_ip)
        self.client_sport = 0
        self.server_sport = 0 
        self.client_dport = client_dport
        self.server_dport = server_dport
        self.client_iface = client_iface
        self.server_iface = server_iface
        self.client_mac = resolve_mac(client_ip)
        self.server_mac = resolve_mac(server_ip)
        self.proxy_iface = proxy_iface
        self.proxy_ip = get_private_ip_address(self.proxy_iface)
        bind_layers(UDP, CoAP, sport=client_dport)
        bind_layers(UDP, CoAP, dport=server_dport)

        # Start sniffer threads
        self.client_sniffer = self.start_listening_client()
        self.server_sniffer = self.start_listening_server()

    def flush_logging_buffer(self):
        for handler in self.logger.handlers:
            handler.flush()

    async def log_with_lock(self, message):
        async with self.log_lock:
            self.logger.debug(message)
            self.flush_logging_buffer()

    def start_listening_client(self):
        filter = f'udp dst port {self.client_dport} and src host {self.client_ip}'
        self.logger.debug(f"Client filter {filter} is set on interface {self.client_iface}")
        self.flush_logging_buffer()
        return AsyncSniffer(iface=self.client_iface, filter=filter, prn=self.packet_callback)

    def start_listening_server(self):
        filter = f'udp src port {self.server_dport} and src host {self.server_ip}'
        self.logger.debug(f"Server filter {filter} is set on interface {self.server_iface}")
        self.flush_logging_buffer()
        return AsyncSniffer(iface=self.server_iface, filter=filter, prn=self.packet_callback)

    def packet_callback(self, packet):
        """Callback for the sniffer; adds packets to the queue."""
        self.packet_queue.put(packet)

    async def process_packets(self, future=None, timeout=0):
        """Asynchronous processing of packets from the queue with timeout handling."""
        if (future == None):
            self.logger.error(f"Futur is not set")
            return
        while True:
            try:
                if(timeout == 0):
                    packet = await asyncio.to_thread(self.packet_queue.get)
                else:
                    packet = await asyncio.to_thread(self.packet_queue.get, timeout=timeout)
            except queue.Empty:
                print("Timeout is reached")
                future.set_result(None)
                return
            if packet[IP].src == self.client_ip:
                await self.handle_client_packet(packet)
            elif packet[IP].src == self.server_ip:
                await self.handle_server_packet(packet)

    def start(self):
        if self.client_sniffer is not None:
            self.client_sniffer.start()
        if self.server_sniffer is not None:
            self.server_sniffer.start()

    def shutdown(self):
        if self.client_sniffer is not None:
            self.client_sniffer.stop()
        if self.server_sniffer is not None:
            self.server_sniffer.stop()

    async def handle_client_packet(self, packet):
        self.client_sport = packet[UDP].sport
        await self.log_with_lock_lambda(packet, OCLIENT, ARECEIVED)
        await self.forward_to_server(packet)

    async def handle_server_packet(self, packet):
        self.server_sport = packet[UDP].sport
        await self.log_with_lock_lambda(packet, OSERVER, ARECEIVED)
        await self.forward_to_client(packet)

    async def forward_to_server(self, packet):
        packet[Ether].src = get_if_hwaddr(conf.iface)
        packet[Ether].dst = self.server_mac
        packet[IP].src = self.proxy_ip
        packet[IP].dst = self.server_ip
        packet[UDP].dport = self.server_dport
        del packet[IP].chksum
        del packet[UDP].chksum
        sendp(packet, verbose=0)
        await self.log_with_lock_lambda(packet, OSERVER, AFORWARDED)

    async def forward_to_client(self, packet):
        packet[Ether].src = get_if_hwaddr(conf.iface)
        packet[Ether].dst = self.client_mac
        packet[IP].src = self.proxy_ip
        packet[IP].dst = self.client_ip
        packet[UDP].dport = self.client_sport
        del packet[IP].chksum
        del packet[UDP].chksum
        sendp(packet, iface=self.client_iface, verbose=0)
        await self.log_with_lock_lambda(packet, OCLIENT, AFORWARDED)

    async def forward_to_null(self, packet):
        packet[Ether].src = get_if_hwaddr(conf.iface)
        packet[Ether].dst = "00:00:00:00:00"
        del packet[IP].chksum
        del packet[UDP].chksum
        sendp(packet, iface=self.client_iface, verbose=0)
        await self.log_with_lock_lambda(packet, OCLIENT, AFORWARDED)


async def main(proxy):
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    proxy.start()
    await proxy.log_with_lock("Coap proxy is running")
    asyncio.create_task(proxy.process_packets(future, 5))  # Start processing packets
    await future  # Wait until the future is resolved

if __name__ == '__main__':
    proxy = CoAPProxy(client_ip='127.0.0.1',
                      server_ip='127.0.0.1',
                      client_dport=5683, 
                      server_dport=5683,
                      client_iface='lo',
                      server_iface='lo')
    try:
        asyncio.run(main(proxy))
    except KeyboardInterrupt:
        proxy.shutdown()
        proxy.logger.debug("Proxy is shutdown")
        sys.exit(0)
