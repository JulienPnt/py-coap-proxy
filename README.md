# CoAP-Proxy
CoAP proxy software designed in Python for testing/debugging purposes.
# Installation
## Using PyPi
(Note: This method will be available in a future release.)
## From source
1. Clone the repository: 
``` 
git clone git@github.com:julienpornet34800/py-coap-proxy.git
```
2. Build the Python library:
```
cd py-coap-proxy
pip3 install --upgrade pip
pip3 install build
python3 -m build
```
3. (Optional) If you use a Python environment, activate it before installation
4. Install the package: 
```
pip3 install dist/py_coap_proxy-0.0.1.tar.gz
```
# Example of use
## Before to start
If you don't have a CoAP client or server, you can install the libcoap package: libcoap.net.
Below is an example of code using a basic CoAP proxy:
```
from py_coap_proxy import CoAPProxy
import sys, asyncio

# If no request/response are received for 5s the proxy is going to close
timeout = 20 # in seconds 

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
```
## Step 1: Open you CoAP server on localhost (IPv4)
Using `libcoap` package: 
```
coap-server -A 127.0.0.1
```
## Step 2: Run your Proxy (Administrator Rights May Be Required)
```
sudo python3 example.py
```
## Step 3: Send an CoAP request through your CoAP client
Using `libcoap` package: 
```
coap-client -m get "coap://127.0.0.1/example_data"
```
