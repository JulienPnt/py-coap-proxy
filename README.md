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
Below is the `py-coap-proxy/tests/coap-proxy-standard-example.py` which opens a basic CoAPProxy's gate.
```python3
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
``` bash
sudo python3 tests/coap-proxy-standard-example.py
```
### ⚠️ Warning: Environment Mismatch with `sudo`
**Warning**: Running scripts with `sudo` can alter the environment and may cause **Python to use a different environment where the `py_coap_proxy` package is not installed**. This can lead to errors such as `ModuleNotFoundError`.
**Solution**s:
1. **Run with `sudo` While Preserving the Python Environment:**
   - Use the `-E` option with `sudo` to preserve the user environment, including Python paths:
     ```bash
     sudo -E python3 tests/coap-proxy-standard-example.py
     ```
   - Alternatively, explicitly set the `PYTHONPATH` environment variable with `sudo`:
     ```bash
     sudo PYTHONPATH=$PYTHONPATH python3 tests/coap-proxy-standard-example.py
     ```
2. **Install the Package Globally for `sudo`:**

   - Install the `py_coap_proxy` package in the global environment so it is accessible when running with `sudo`:
     ```bash
     sudo pip3 install dist/py_coap_proxy-0.0.1.tar.gz
     ```
By following these steps, you can ensure that your script runs successfully with the necessary permissions and in the correct environment.


## Step 3: Send an CoAP request through your CoAP client
Using `libcoap` package: 
```
coap-client -m get "coap://127.0.0.1/example_data"
```
