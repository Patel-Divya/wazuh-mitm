# Wazuh MITM (Reverse Proxy PoC)

This repository provides a **Dockerized MITM reverse proxy** for Wazuh using **mitmproxy**.  
The proxy listens on **port 8005**, intercepts and optionally modifies requests, forwards them to the real Wazuh Manager on **port 443**, and relays responses back to the client.

---

## Prerequisites

- Docker
- Python 3.x (for certificate generation)
- Wazuh Manager running in Docker and exposed on port `443`
- Client must trust the MITM certificate

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/Patel-Divya/wazuh-mitm.git
cd wazuh-mitm
```

## Step 2 — Generate a New Certificate
To generate a custom MITM TLS certificate:
```bash
python generate_cert.py
```

Copy the generated certificate into the certs/ directory:
```bash
cp wazuh-proxy.pem certs/wazuh-proxy.pem
```
⚠️ The client connecting to port 8005 must trust this certificate.

## Step 3 — Build the Docker Image
```bash
docker build -t wazuh-mitm .
```
## Step 4 — Run the MITM Proxy (Simple)
```bash
docker run -d --name wazuh-mitm -p 8005:8005 wazuh-mitm
```
Or bind the python file and certificate from host machine:
```bash
docker run -d --name wazuh-mitm \
  -p 8005:8005 \
  -v "D:\vs code\Python\POC\wazuh-mitm\wazuh_reverse.py:/app/wazuh_reverse.py" \
  -v "D:\vs code\Python\POC\wazuh-mitm\certs\wazuh-proxy.pem:/certs/wazuh-proxy.pem" \
  wazuh-mitm
```
The proxy will be available at:
```
https://HOST_IP:8005
```

Changes to `wazuh_reverse.py` now take effect **without rebuilding** the image. It only require to restart the container.


## Forwarding Behavior

The proxy forwards traffic using mitmproxy reverse mode:
```bash
--mode reverse:https://host.docker.internal:443
```

All requests received on port `8005` are forwarded to the Wazuh Manager on port `443`, and responses are sent back through the same proxy connection.
