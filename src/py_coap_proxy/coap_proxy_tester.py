import asyncio

from scapy.contrib.coap import CoAP
from scapy.packet import Packet
from scapy.arch import get_if_hwaddr
from scapy.layers.inet import Ether, IP, UDP
from scapy.interfaces import conf

from .utils.logs import str_packet_info, \
    AFORWARDED, ARECEIVED, OCLIENT, OSERVER

from .coap_proxy import CoAPProxy

ERROR_FORBIDEN = "FORBIDEN"
ERROR_NOT_FOUND = "NOT_FOUND"


class CoAPProxyTester(CoAPProxy):

    async def forward_to_server_delayed(self, packet, delay=3):
        await asyncio.sleep(delay)
        await self.forward_to_server(packet)

    async def forward_to_client_delayed(self, packet, delay=3):
        await asyncio.sleep(delay)
        await self.forward_to_client(packet)

    async def forward_error_to_client(self, original_packet, error):
        match error:
            case "403":
                await self.forward_to_client_error_forbidden(original_packet)
            case "404":
                await self.forward_to_client_error_not_found(original_packet)
            case _:
                raise ValueError(f"Error {error} is not handled")

    async def forward_to_client_error_forbidden(self, original_packet):
        packet = original_packet.copy()

        packet[Ether].src = get_if_hwaddr(conf.iface)
        packet[Ether].dst = self.client_mac
        packet[IP].src = self.proxy_ip
        packet[IP].dst = self.client_ip
        packet[UDP].dport = self.client_sport

        packet[CoAP].code = 131
        packet[CoAP].msg_id = original_packet[CoAP].msg_id
        packet[CoAP].options = original_packet[CoAP].options

        await self.forward_to_client(packet)

    async def forward_to_client_error_not_found(self, original_packet):
        packet = original_packet.copy()

        packet[Ether].src = get_if_hwaddr(conf.iface)
        packet[Ether].dst = self.client_mac
        packet[IP].src = self.proxy_ip
        packet[IP].dst = self.client_ip
        packet[UDP].dport = self.client_sport

        packet[CoAP].code = 131
        packet[CoAP].msg_id = original_packet[CoAP].msg_id
        packet[CoAP].options = original_packet[CoAP].options
        await self.forward_to_client(packet)

    async def forward_to_null(self, packet=None):
        return
