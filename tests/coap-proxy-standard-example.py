from py_coap_proxy import CoAPProxy
import sys
import asyncio

# If no request/response are received for 5s the proxy is going to close
timeout = 20  # in seconds


async def main(proxy):
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    proxy.start()
    await proxy.log_with_lock("Coap proxy is running")
    asyncio.create_task(proxy.process_packets(future, timeout))
    await future

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
