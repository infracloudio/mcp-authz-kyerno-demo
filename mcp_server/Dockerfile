FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn httpx kubernetes

COPY authz_proxy.py .

ENV MCP_SERVER_URL=http://localhost:8080
ENV PROXY_PORT=8090
ENV TENANT_ID=tenant-acme
ENV AGENT_ID=sre-agent

EXPOSE 8090

CMD ["python3", "authz_proxy.py"]
