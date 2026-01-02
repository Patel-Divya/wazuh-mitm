FROM mitmproxy/mitmproxy:10.3.0

WORKDIR /app

COPY wazuh_reverse.py .
COPY certs/wazuh-proxy.pem /certs/wazuh-proxy.pem

EXPOSE 8005

CMD ["mitmdump","--mode","reverse:https://host.docker.internal:443","--listen-host","0.0.0.0","--listen-port","8005","--ssl-insecure","--certs","/certs/wazuh-proxy.pem","-s","/app/wazuh_reverse.py"]

