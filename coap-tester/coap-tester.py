import sys
import os
import asyncio
import configuration_parsing
from coap_proxy_testing_agent import TestCoAP


USAGE = f"Usage\n{sys.argv[0]} <yaml configuration path>"
EXPECTED_ARGS_NUM = 2

def manage_usage(args):
    """
    Validate the command-line arguments.

    Args:
        args (list): Command-line arguments.

    Returns:
        tuple: Status code (int), and the YAML file path (str) or None.
    """
    if len(args) != EXPECTED_ARGS_NUM:
        print(f"Wrong args number, received {len(args)} expected: {EXPECTED_ARGS_NUM}", file=sys.stderr)
        return 1, None

    path = args[1]
    if not os.path.isfile(path):
        print(f"{path} does not exist", file=sys.stderr)
        return 2, None

    return 0, path

DEFAULT_PROXY_TIMEOUT=5*60 # 5 minutes without activity
async def open_proxy(proxy):
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    proxy.start()
    await proxy.log_with_lock("Coap proxy is running")
    asyncio.create_task(proxy.process_packets(future, DEFAULT_PROXY_TIMEOUT))  # Start processing packets
    await future  # Wait until the future is resolved


async def main(args):
    """
    Main entry point of the script.

    Args:
        argv (list): Command-line arguments.

    Returns:
        int: Exit status.
    """
    print("Open proxy")
    status, test_configuration_path = manage_usage(args)
    if status != 0 or test_configuration_path == None:
        print("Usage issue")
        sys.exit(1)

    status, content = configuration_parsing.extract_yaml_file(test_configuration_path)
    if status != 0:
        print("Failed to exctract configuration file")
        sys.exit(2)

    status, client_ip = configuration_parsing.extract_key_value(content, 'general_settings.client.ip_or_url')       
    if status != 0 or client_ip is None or not configuration_parsing.is_valid_ip_or_url(client_ip):
        sys.exit(3)
    status, client_coap_port = configuration_parsing.extract_key_value(content, 'general_settings.client.coap_port')       
    if status != 0 or client_coap_port is None or not configuration_parsing.is_valid_port(client_coap_port):
        sys.exit(4)
    status, client_iface = configuration_parsing.extract_key_value(content, 'general_settings.client.iface')       
    if status != 0 or client_iface is None:
        sys.exit(5)
    status, server_ip = configuration_parsing.extract_key_value(content, 'general_settings.server.ip_or_url')       
    if status != 0 or server_ip is None or not configuration_parsing.is_valid_ip_or_url(server_ip):
        sys.exit(6)
    status, server_coap_port = configuration_parsing.extract_key_value(content, 'general_settings.server.coap_port')       
    if status != 0 or server_coap_port is None or not configuration_parsing.is_valid_port(server_coap_port):
        sys.exit(7)
    status, server_iface = configuration_parsing.extract_key_value(content, 'general_settings.server.iface')       
    if status != 0 or server_iface is None:
        sys.exit(7)

    proxy = TestCoAP(   test_configuration_path=test_configuration_path,
                        client_ip=client_ip,
                        server_ip=server_ip,
                        client_dport=client_coap_port, 
                        server_dport=server_coap_port,
                        client_iface=client_iface,
                        server_iface=server_iface)
    try:
        await open_proxy(proxy)
    except KeyboardInterrupt:
        proxy.shutdown()
        proxy.logger.debug("Proxy is shutdown")
        sys.exit(0)
    return 0

if __name__ == '__main__':
    asyncio.run(main(sys.argv))
