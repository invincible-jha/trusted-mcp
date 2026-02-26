FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/aumos-ai/trusted-mcp"
LABEL org.opencontainers.image.description="trusted-mcp: Security proxy for MCP connections"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Install trusted-mcp
COPY . /src/
RUN pip install --no-cache-dir /src/ && rm -rf /src/

# Create non-root user
RUN useradd -m -s /bin/bash tmcp
USER tmcp

# Default policy location
ENV TRUSTED_MCP_CONFIG=/app/policy.yaml
ENV TRUSTED_MCP_AUDIT_PATH=/app/audit/audit.jsonl

# Copy default policy
COPY policies/default.yaml /app/policy.yaml

# Create audit directory
RUN mkdir -p /app/audit

EXPOSE 8765

ENTRYPOINT ["trusted-mcp"]
CMD ["proxy", "--config", "/app/policy.yaml", "--transport", "sse", "--host", "0.0.0.0", "--port", "8765"]
