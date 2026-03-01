FROM python:3.12-slim

LABEL maintainer="iotscan contributors"
LABEL description="IoT Security Pentesting Toolkit"

# Install system dependencies for scapy and BLE
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    libpcap-dev \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ src/
COPY tests/ tests/
COPY scripts/ scripts/

# Install iotscan with dev dependencies
RUN pip install --no-cache-dir -e ".[dev]"

# Verify installation
RUN iotscan --help > /dev/null 2>&1

ENTRYPOINT ["iotscan"]
CMD ["--help"]
