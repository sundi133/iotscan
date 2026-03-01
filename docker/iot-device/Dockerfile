FROM python:3.12-slim

LABEL description="Simulated vulnerable IoT smart camera for security testing"

# Install paho-mqtt for telemetry publishing
RUN pip install --no-cache-dir paho-mqtt>=1.6

WORKDIR /device

COPY device_simulator.py .

EXPOSE 21 23 80 161/udp 5683/udp

CMD ["python3", "device_simulator.py"]
