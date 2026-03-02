# iotscan

AI-native IoT Security Pentesting Toolkit — firmware analysis, protocol testing, credential checks, OTA update analysis, device-to-cloud attack path mapping, network discovery, web security testing, and LLM-powered agentic scanning.

## Modules

| Module | Description |
|--------|-------------|
| **firmware** | Binary header identification, hardcoded credential detection, unsafe C function scanning, vulnerable library detection, ELF hardening checks (NX/PIE/RELRO/canaries), weak cryptography detection, entropy analysis, debug artifact discovery |
| **protocols** | MQTT (anonymous access, TLS, wildcard topics, version), CoAP (resource discovery, DTLS), Zigbee (network key, security mode, permit join, touchlink), BLE (pairing, encryption, GATT, advertising) |
| **credentials** | Default credential testing across HTTP, SSH, Telnet, FTP, and MQTT for 40+ IoT vendor defaults |
| **ota** | Update transport security, firmware signing verification, rollback protection, secure boot, certificate pinning, delta update validation |
| **attack_paths** | Device-to-cloud path identification, network segmentation checks, API security, cloud backend assessment, lateral movement analysis |
| **network** | UPnP/SSDP discovery, mDNS enumeration, SNMP default community string testing, service fingerprinting, banner grabbing, Modbus/BACnet/RTSP exposure detection |
| **web** | Security header checks, sensitive endpoint discovery, path traversal testing, command injection detection, CORS misconfiguration, HTTP method checks, TLS validation |

## Installation

```bash
pip install -e .
```

For development (includes pytest, ruff):

```bash
pip install -e ".[dev]"
```

## Quick Start

```bash
# 1. Install
pip install -e .

# 2. Run your first scan
iotscan scan 192.168.1.100

# 3. AI-powered agentic scan (adapts strategy based on findings)
iotscan agent-scan 192.168.1.100 --device-type smart_camera

# 4. See what modules are available
iotscan list-modules
```

## CLI Reference

```
iotscan [OPTIONS] COMMAND [ARGS]...

Options:
  -v, --verbose    Enable verbose/debug output
  -q, --quiet      Suppress banner and non-essential output

Commands:
  scan             Run IoT security scan against a target
  agent-scan       AI-powered adaptive scan (multi-phase, auto-adjusting)
  analyze          Run AI analysis on a previously saved JSON report
  list-modules     List available scanning modules
  init-config      Generate a sample YAML configuration file
```

### `iotscan scan`

```
iotscan scan [OPTIONS] HOST

Options:
  -p, --port INTEGER                 Target port
  --protocol [auto|mqtt|coap|zigbee|ble]
  --firmware PATH                    Path to firmware binary file
  --device-type TEXT                 Device type (camera, router, sensor, etc.)
  -m, --modules TEXT                 Modules to run (repeatable, default: all)
  -c, --config PATH                  YAML config file for advanced scans
  -o, --output PATH                  Output report file path
  --format [text|json|html]          Report format (default: text)
```

**Exit codes:** `0` = clean, `1` = high-severity findings, `2` = critical findings.

### `iotscan agent-scan` (AI-Native)

```
iotscan agent-scan [OPTIONS] HOST

Options:
  -p, --port INTEGER                 Target port
  --firmware PATH                    Path to firmware binary file
  --device-type TEXT                 Device type for contextual AI analysis
  -c, --config PATH                  YAML config file
  -o, --output PATH                  Output report file path
  --format [text|json|html]          Report format (default: text)
  --ai-provider [anthropic|openai|offline]   LLM provider (default: offline)
  --ai-model TEXT                    AI model override
```

The agent scan runs in 4 phases:
1. **Discovery** - network service scan + credential check
2. **AI Analysis** - reasons about initial findings, recommends next modules
3. **Deep Scan** - runs AI-recommended modules with targeted config
4. **AI Report** - generates executive summary, attack chains, OWASP mapping, prioritized remediations

### `iotscan analyze`

```
iotscan analyze [OPTIONS] REPORT_FILE

Options:
  --ai-provider [anthropic|openai|offline]   LLM provider
  --ai-model TEXT                            AI model override
  --finding INTEGER                          Deep dive into a specific finding by number
```

## Usage Examples

### 1. Run all modules against a device

Scans the target with all 7 modules:

```bash
iotscan scan 192.168.1.100
```

### 2. Firmware analysis only

Analyze a firmware binary for hardcoded secrets, unsafe functions, vulnerable libraries, and debug artifacts:

```bash
iotscan scan 192.168.1.100 --firmware ./firmware.bin -m firmware
```

Example output:

```
╭─────────────────────────── Scan Summary ───────────────────────────╮
│ Target: 192.168.1.100                                              │
│ Modules: firmware_analysis                                         │
│ Total Findings: 9                                                  │
│                                                                    │
│ Critical: 0  High: 4  Medium: 2  Low: 2  Info: 1                   │
╰────────────────────────────────────────────────────────────────────╯
                              Findings
┏━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ #  ┃ Severity ┃ Module             ┃ Title                        ┃
┡━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1  │ INFO     │ firmware_analysis  │ Firmware sections identified  │
│ 2  │ HIGH     │ firmware_analysis  │ Hardcoded password found      │
│ 3  │ HIGH     │ firmware_analysis  │ Hardcoded API key found       │
│ 4  │ MEDIUM   │ firmware_analysis  │ Unsafe C functions detected   │
│ 5  │ HIGH     │ firmware_analysis  │ Vulnerable busybox version    │
│ 6  │ HIGH     │ firmware_analysis  │ Vulnerable openssl version    │
│ 7  │ LOW      │ firmware_analysis  │ Build path with username      │
│ 8  │ LOW      │ firmware_analysis  │ Debug logging enabled         │
│ 9  │ MEDIUM   │ firmware_analysis  │ Telnet daemon present         │
└────┴──────────┴────────────────────┴──────────────────────────────┘
```

### 3. Test MQTT broker security

Test a specific MQTT broker for anonymous access, TLS config, and wildcard topic enumeration:

```bash
iotscan scan mqtt-broker.local -p 1883 --protocol mqtt -m protocols
```

### 4. Check default credentials

Scan all services (HTTP, SSH, Telnet, FTP, MQTT) for factory-default login credentials:

```bash
iotscan scan 192.168.1.100 -m credentials
```

### 5. Test a specific port

```bash
iotscan scan 10.0.0.50 -p 8080 -m credentials
```

### 6. Combine multiple modules

Run firmware analysis and credential checking together:

```bash
iotscan scan 192.168.1.100 --firmware ./camera_fw.bin -m firmware -m credentials
```

### 7. OTA update security analysis (with config)

Create a config file to analyze OTA update mechanisms:

```yaml
# ota_check.yaml
target:
  host: 192.168.1.100
  device_type: smart_camera

modules:
  - ota

config:
  ota:
    update_url: http://firmware.vendor.com/updates/latest.bin
    signing_method: md5
    rollback_protection: false
    secure_boot: false
    certificate_pinning: false
    allow_custom_server: true
```

```bash
iotscan scan 192.168.1.100 -c ota_check.yaml
```

### 8. Full ecosystem attack path mapping

Map device-to-cloud attack paths including gateway, cloud APIs, and network segmentation:

```yaml
# ecosystem.yaml
target:
  host: 192.168.1.100
  device_type: smart_thermostat

modules:
  - attack_paths

config:
  ecosystem:
    gateway:
      host: 192.168.1.1
    cloud_endpoints:
      - url: https://api.vendor.com/v1/devices
    apis:
      - url: https://api.vendor.com/v1/telemetry
        auth_method: api_key
        rate_limiting: false
        input_validation: false
    mobile_app: true
    firmware_accessible: true
    network:
      iot_vlan: false
      egress_filtering: false
      ids_monitoring: false
    cloud:
      encryption_at_rest: true
      device_identity: false
      shared_credentials: true
```

```bash
iotscan scan 192.168.1.100 -c ecosystem.yaml -o attack_paths.html --format html
```

### 9. BLE and Zigbee device testing

Evaluate wireless protocol security settings via config:

```yaml
# wireless.yaml
target:
  host: 192.168.1.100
  protocol: auto

modules:
  - protocols

config:
  zigbee:
    network_key: "5a:69:67:42:65:65:41:6c:6c:69:61:6e:63:65:30:39"
    security_mode: standard
    permit_join: true
    touchlink_enabled: true
  ble:
    pairing_mode: just_works
    encryption_enabled: true
    version: "4.1"
    writable_characteristics: ["0x2a06", "0x2a19"]
    exposes_device_name: true
    exposes_mac: true
```

```bash
iotscan scan 192.168.1.100 -c wireless.yaml
```

### 10. Generate reports

```bash
# Plain text report
iotscan scan 192.168.1.100 -o report.txt --format text

# JSON report (for CI/CD integration or SIEM ingestion)
iotscan scan 192.168.1.100 -o report.json --format json

# HTML report (shareable with color-coded severity)
iotscan scan 192.168.1.100 --firmware fw.bin -o report.html --format html
```

JSON report structure:

```json
{
  "target": "192.168.1.100",
  "scan_start": "2026-03-01T17:57:55.345595",
  "scan_end": "2026-03-01T17:57:55.348190",
  "modules_run": ["firmware_analysis"],
  "total_findings": 9,
  "severity_breakdown": {
    "critical": 0, "high": 4, "medium": 2, "low": 2, "info": 1
  },
  "module_results": [
    {
      "module": "firmware_analysis",
      "status": "completed",
      "findings": [
        {
          "title": "Hardcoded password found in firmware",
          "severity": "high",
          "description": "Detected 1 instance(s) of Hardcoded password...",
          "evidence": "Sample matches (redacted): [...]",
          "remediation": "Remove hardcoded credentials. Use secure key storage...",
          "cve": ""
        }
      ]
    }
  ]
}
```

### 11. CI/CD integration

Use the exit code to fail pipelines on critical findings:

```bash
iotscan -q scan 192.168.1.100 --firmware ./firmware.bin -o results.json --format json
# Exit code 0 = pass, 1 = high findings, 2 = critical findings
```

### 12. Verbose / quiet modes

```bash
# Debug output (shows every scanner step)
iotscan -v scan 192.168.1.100

# Quiet mode (no banner, minimal output — good for scripts)
iotscan -q scan 192.168.1.100 -o report.json --format json
```

### 13. AI-powered agent scan (recommended)

The `agent-scan` command runs an intelligent multi-phase scan that adapts based on findings:

```bash
# Offline mode (no API key needed - uses rule-based AI)
iotscan agent-scan 192.168.1.100 --device-type smart_camera

# With firmware analysis
iotscan agent-scan 192.168.1.100 --firmware ./fw.bin --device-type ip_camera

# With Claude AI (requires ANTHROPIC_API_KEY)
ANTHROPIC_API_KEY=sk-ant-... iotscan agent-scan 192.168.1.100 --ai-provider anthropic

# With a specific Claude model
iotscan agent-scan 192.168.1.100 --ai-provider anthropic --ai-model claude-sonnet-4-20250514

# With OpenAI (requires OPENAI_API_KEY)
OPENAI_API_KEY=sk-... iotscan agent-scan 192.168.1.100 --ai-provider openai

# Save full AI-enriched report
iotscan agent-scan 192.168.1.100 --firmware fw.bin -o report.html --format html
```

The agent scan outputs:
- **Phase 1**: Discovery findings (network services, default credentials)
- **Phase 2**: AI-recommended next modules with reasoning
- **Phase 3**: Deep scan results from targeted modules
- **Phase 4**: Executive summary, risk rating, attack chain analysis, OWASP compliance gaps, prioritized remediations with effort estimates

### 14. AI analysis of existing reports

Re-analyze a previously saved JSON report with AI:

```bash
# Analyze full report
iotscan analyze report.json

# Deep dive into a specific finding (by number)
iotscan analyze report.json --finding 3

# Use Claude for deep analysis
ANTHROPIC_API_KEY=sk-ant-... iotscan analyze report.json --ai-provider anthropic

# Use a specific model for analysis
iotscan analyze report.json --ai-provider anthropic --ai-model claude-sonnet-4-20250514
```

### 15. Network discovery scan

Discover services, UPnP devices, mDNS, and test SNMP community strings:

```bash
iotscan scan 192.168.1.100 -m network
```

### 16. Web interface security testing

Test the device web admin panel for injection, traversal, headers, and TLS:

```bash
iotscan scan 192.168.1.100 -p 8080 -m web
```

## Configuration File

Generate a sample config to get started:

```bash
iotscan init-config my_scan.yaml
```

This creates a full template:

```yaml
target:
  host: 192.168.1.100
  port: 0
  protocol: auto
  device_type: smart_camera
  firmware_path: ''
modules:
  - firmware
  - protocols
  - credentials
  - ota
  - attack_paths
config:
  mqtt_tls_port: 8883
  coap_dtls_port: 5684
  zigbee:
    network_key: ''
    security_mode: standard       # standard | high_security | no_security
    permit_join: false
    touchlink_enabled: true
  ble:
    pairing_mode: just_works      # just_works | passkey | oob | none
    encryption_enabled: true
    version: '4.2'
    writable_characteristics: []
    exposes_device_name: false
    exposes_mac: false
  ota:
    update_url: ''
    signing_method: none          # none | md5 | sha1 | crc32 | rsa | ecdsa | ed25519
    key_size: 0
    rollback_protection: false
    secure_boot: false
    certificate_pinning: false
    allow_custom_server: false
    delta_updates: false
    delta_signing: false
  ecosystem:
    gateway:
      host: ''
    cloud_endpoints: []
    apis: []
    mobile_app: false
    firmware_accessible: false
    network:
      iot_vlan: false
      egress_filtering: false
      ids_monitoring: false
    cloud:
      encryption_at_rest: true
      device_identity: false
      shared_credentials: false
```

Edit the values for your target environment, then:

```bash
iotscan scan 192.168.1.100 -c my_scan.yaml -o report.html --format html
```

## AI Configuration

The `agent-scan` and `analyze` commands support LLM-powered analysis via Anthropic Claude or OpenAI. Without an API key, scans fall back to an offline rule-based engine that still produces executive summaries, attack chains, and OWASP mapping.

### Setting up Anthropic Claude

1. Get an API key from [console.anthropic.com](https://console.anthropic.com/)
2. Install the SDK:
   ```bash
   pip install anthropic
   ```
3. Export your key:
   ```bash
   export ANTHROPIC_API_KEY=sk-ant-api03-...
   ```
4. Run a scan:
   ```bash
   iotscan agent-scan 192.168.1.100 --ai-provider anthropic --device-type smart_camera
   ```

### Setting up OpenAI

1. Get an API key from [platform.openai.com](https://platform.openai.com/)
2. Install the SDK:
   ```bash
   pip install openai
   ```
3. Export your key:
   ```bash
   export OPENAI_API_KEY=sk-...
   ```
4. Run a scan:
   ```bash
   iotscan agent-scan 192.168.1.100 --ai-provider openai --device-type smart_camera
   ```

### AI Provider Options

| Flag | Values | Default |
|------|--------|---------|
| `--ai-provider` | `anthropic`, `openai`, `offline` | `offline` |
| `--ai-model` | Any model ID string | Provider default (see below) |

### Supported Models

| Provider | Default Model | Other Options |
|----------|---------------|---------------|
| **Anthropic** | `claude-sonnet-4-20250514` | `claude-opus-4-20250514`, `claude-haiku-4-5-20251001` |
| **OpenAI** | `gpt-4o` | `gpt-4-turbo`, `gpt-4o-mini` |
| **Offline** | Rule-based engine | N/A (no API call) |

Override the model with `--ai-model`:

```bash
# Use Claude Opus for deeper analysis
iotscan agent-scan 192.168.1.100 --ai-provider anthropic --ai-model claude-opus-4-20250514

# Use Haiku for faster, cheaper scans
iotscan agent-scan 192.168.1.100 --ai-provider anthropic --ai-model claude-haiku-4-5-20251001

# Use GPT-4o Mini for lower cost
iotscan agent-scan 192.168.1.100 --ai-provider openai --ai-model gpt-4o-mini
```

### Using AI with Docker

Pass your API key as an environment variable:

```bash
# Agent scan with Claude
docker compose run --rm -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  iotscan agent-scan iot-device --device-type smart_camera \
  --ai-provider anthropic -o /app/reports/ai_report.html --format html

# Analyze an existing report with Claude
docker compose run --rm -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  iotscan analyze /app/reports/device_scan.json --ai-provider anthropic

# Deep dive into a specific finding
docker compose run --rm -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  iotscan analyze /app/reports/device_scan.json --ai-provider anthropic --finding 3
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude models |
| `OPENAI_API_KEY` | OpenAI API key for GPT models |
| `IOTSCAN_AI_PROVIDER` | Default AI provider (`anthropic`, `openai`, `offline`). Overridden by `--ai-provider` flag. |

## What Each Module Detects

### Firmware Analysis (`-m firmware`)
- SquashFS, ELF, uImage, gzip, CPIO, ZIP headers in binary
- Hardcoded passwords, API keys, tokens, private keys, DB connection strings, AWS credentials
- Unsafe C functions: `strcpy`, `sprintf`, `gets`, `scanf`, etc.
- Outdated BusyBox, OpenSSL, Dropbear, lighttpd, dnsmasq versions
- ELF binary hardening: NX (executable stack), PIE, RELRO, stack canaries
- Weak cryptography: DES, RC4, MD5, SHA-1, ECB mode, weak PRNG
- High-entropy sections (encrypted/compressed regions)
- Debug artifacts: build paths, telnetd, JTAG/UART references, GDB stubs

### Protocol Testing (`-m protocols`)
- **MQTT**: anonymous access, deprecated TLS, wildcard `#` subscription, protocol version enumeration
- **CoAP**: `/.well-known/core` resource discovery exposure, DTLS transport check
- **Zigbee**: default ZigBeeAlliance09 key, no-security mode, open permit-join, Touchlink factory reset attack
- **BLE**: Just Works / no pairing, missing encryption, outdated BLE version (<4.2), writable GATT characteristics, advertising data leakage

### Credential Checker (`-m credentials`)
- Auto-discovers open ports: HTTP (80/8080/443/8443), SSH (22), Telnet (23), FTP (21), MQTT (1883)
- Tests 40+ vendor defaults: Hikvision, Dahua, TP-Link, Ubiquiti, Siemens, Schneider, Moxa, and more
- Detects anonymous FTP access
- SSH banner grabbing (Dropbear, libssh CVE-2018-10933)
- Telnet presence (Mirai botnet vector)

### OTA Analyzer (`-m ota`)
- HTTP vs HTTPS update delivery
- Firmware signing: none, weak (MD5/CRC32/SHA1), or proper (RSA/ECDSA/Ed25519)
- RSA key size validation
- Rollback / anti-downgrade protection
- Secure boot chain verification
- Certificate pinning for update server
- Delta update signing
- Plaintext URLs in firmware binaries

### Attack Path Mapper (`-m attack_paths`)
- Device → Cloud direct compromise paths
- Device → Gateway → Cloud lateral movement
- Network eavesdropping → credential theft chains
- Firmware extraction → secret reuse paths
- Mobile app reverse engineering → cloud access
- API exploitation paths
- Network segmentation (VLAN, egress filtering, IDS)
- Cloud backend: encryption at rest, per-device identity, shared credentials

### Network Discovery (`-m network`)
- Port scanning across 20 common IoT ports (HTTP, SSH, Telnet, MQTT, CoAP, Modbus, BACnet, RTSP, etc.)
- Service banner grabbing and version fingerprinting
- UPnP/SSDP device discovery and IGD port mapping detection
- mDNS service enumeration
- SNMP default community string testing (public, private, community, etc.)
- Dangerous service exposure alerts (Modbus, BACnet, Telnet, RTSP, raw printing)

### Web Security (`-m web`)
- Missing security headers (X-Frame-Options, CSP, HSTS, X-Content-Type-Options)
- Sensitive endpoint discovery: /.env, /debug, /config.json, /admin, /backup, HNAP, GoAhead forms
- Path traversal testing (../etc/passwd variants)
- Command injection detection via diagnostic endpoints (ping, diag, goform)
- CORS misconfiguration (wildcard, origin reflection)
- Dangerous HTTP methods (PUT, DELETE, TRACE)
- TLS certificate and cipher validation
- Information disclosure headers (X-Powered-By, Server version)

### AI Agent (`agent-scan`)
- Multi-phase adaptive scanning (discovery → AI analysis → deep scan → report)
- Attack chain identification (credential chains, firmware supply chain, telnet-to-rootkit)
- OWASP IoT Top 10 compliance mapping with CVSS scores
- Executive summary generation for non-technical stakeholders
- Prioritized remediations with effort estimates
- Supports Anthropic Claude, OpenAI, and offline rule-based analysis

## Docker Setup (Recommended for Testing)

Run the entire toolkit in Docker with vulnerable test targets (MQTT broker, web server, simulated IoT smart camera) for safe, isolated testing.

### Prerequisites

- Docker and Docker Compose installed

### Step-by-Step Testing Guide

Follow these steps to build, launch, and scan the simulated IoT device end-to-end:

**Step 1: Build all Docker images**

```bash
make build
```

This builds the `iotscan` scanner image and the `iot-device` simulator image.

**Step 2: Start the test targets**

```bash
make up
```

This launches three vulnerable targets in the background:

| Service | Host Port | Container Port | Description |
|---------|-----------|----------------|-------------|
| `mqtt-broker` | 1883 | 1883 | Mosquitto MQTT broker (anonymous access, no TLS) |
| `web-target` | 8088 | 80 | Simple vulnerable web panel |
| `iot-device` | 8080 (HTTP), 2323 (Telnet), 2121 (FTP), 5683/udp (CoAP), 1161/udp (SNMP) | 80, 23, 21, 5683, 161 | Simulated SmartCam Pro X200 with 6 vulnerable services |

**Step 3: Verify the targets are running**

```bash
docker compose ps

# Test IoT device HTTP
curl -s http://localhost:8080/ | head

# Test IoT device config leak
curl -s http://localhost:8080/config.json | python3 -m json.tool

# Test Telnet banner
echo "" | nc -w2 localhost 2323

# Test FTP banner
echo "QUIT" | nc -w2 localhost 2121
```

**Step 4: Run a quick scan against the IoT device**

```bash
make scan-device
```

This runs network discovery, web security, and credential checks against the simulated camera.

**Step 5: Run a full scan with all modules**

```bash
make scan-device-full
```

Produces a JSON report at `reports/device_scan.json` with findings from network, web, credentials, and protocol modules.

**Step 6: Run an AI-powered agent scan**

```bash
make scan-device-agent
```

Produces an HTML report at `reports/device_agent.html` with executive summary, attack chains, and prioritized remediations.

**Step 7: Run a config-driven scan with the sample config**

```bash
docker compose run --rm iotscan scan iot-device \
  -c /app/samples/iot_device_scan.yaml \
  -o /app/reports/full_config_scan.html --format html
```

The sample config (`samples/iot_device_scan.yaml`) enables all 6 modules including OTA analysis and attack path mapping.

**Step 8: Scan the MQTT broker**

```bash
make scan-mqtt
```

**Step 9: Scan the web target**

```bash
make scan-web
```

**Step 10: Run the full end-to-end test suite**

```bash
make e2e
```

This runs automated validation of all scanner modules against all three test targets.

**Step 11: Run unit tests**

```bash
make test-docker
```

**Step 12: Stop everything and clean up**

```bash
make down
make clean
```

### Simulated IoT Device (SmartCam Pro X200)

The `iot-device` container simulates a deliberately vulnerable IoT smart camera with multiple exposed services:

| Service | Port | Vulnerabilities |
|---------|------|-----------------|
| **HTTP** | 80 | Missing security headers, exposed `/config.json` (WiFi creds, API keys), `/.env` (AWS keys, DB passwords), `/debug`, `/firmware.bin` download, `/syslog`, GoAhead web server, `/goform/` endpoints, `/HNAP1/`, wildcard CORS, dangerous HTTP methods (PUT/DELETE/TRACE), unauthenticated admin panel |
| **Telnet** | 23 | Default credentials (`admin/admin`, `root/root`), BusyBox banner disclosure |
| **FTP** | 21 | Anonymous access, vsftpd 2.3.4 banner disclosure |
| **CoAP** | 5683/udp | Unauthenticated resource discovery (`/device`, `/temperature`, `/firmware`, `/config`) |
| **SNMP** | 161/udp | Accepts default community strings (`public`, `private`, `community`, `admin`, `default`) |
| **MQTT** | (client) | Publishes telemetry and config data (including API keys) to the MQTT broker without authentication |

The downloadable firmware binary (`/firmware.bin`) contains intentional security issues: SquashFS/ELF headers, hardcoded passwords, API keys, unsafe C functions (strcpy, gets, sprintf), vulnerable BusyBox/OpenSSL/Dropbear versions, weak crypto (DES, MD5, RC4), and debug artifacts (JTAG, UART, telnetd, build paths).

### Manual Docker Commands

```bash
# Build the image
docker compose build

# Run a scan against the IoT device
docker compose run --rm iotscan scan iot-device -m network -m web -m credentials

# Run a scan against the MQTT test broker
docker compose run --rm iotscan scan mqtt-broker -p 1883 --protocol mqtt -m protocols

# Run a scan against the vulnerable web target
docker compose run --rm iotscan scan web-target -p 80 -m web

# Download and scan the IoT device firmware
docker compose run --rm iotscan bash -c \
  "python3 -c \"import urllib.request; open('/tmp/fw.bin','wb').write(urllib.request.urlopen('http://iot-device/firmware.bin').read())\" && \
   iotscan scan iot-device --firmware /tmp/fw.bin -m firmware -m web -m credentials -o /app/reports/fw_scan.html --format html"

# Run the AI agent scan against the IoT device
docker compose run --rm iotscan agent-scan iot-device --device-type smart_camera

# Generate an HTML report
docker compose run --rm iotscan scan iot-device -m network -m web -m credentials \
  -o /app/reports/device_report.html --format html

# Run pytest
docker compose run --rm test-runner
```

### Test Targets

| Service | Port | Description |
|---------|------|-------------|
| `mqtt-broker` | 1883 | Eclipse Mosquitto with anonymous access enabled (no auth, no TLS) |
| `web-target` | 80 (8088 on host) | Simulated IoT admin panel with exposed `/config.json`, `/debug`, wildcard CORS, dangerous HTTP methods |
| `iot-device` | 80 (8080 on host) | Multi-service IoT smart camera: HTTP admin, Telnet, FTP, CoAP, SNMP, MQTT telemetry |

### Docker Compose Services

```bash
docker compose up -d          # start test targets in background
docker compose ps              # check running services
docker compose logs iot-device # view IoT device logs
docker compose logs mqtt-broker  # view MQTT broker logs
docker compose down -v         # stop and clean up
```

## Running Tests

```bash
# Local
pytest              # run all tests
pytest -v           # verbose output
pytest --cov        # with coverage report

# Docker
make test-docker    # unit tests in Docker
make e2e            # full end-to-end tests with test targets
```

## Makefile Reference

```
make install           Install iotscan locally
make dev               Install with dev dependencies
make test              Run pytest locally
make lint              Run ruff linter
make build             Build Docker images
make up                Start test targets (MQTT + web + IoT device)
make down              Stop all containers
make test-docker       Run unit tests in Docker
make e2e               Run end-to-end tests in Docker
make scan-mqtt         Scan the test MQTT broker
make scan-web          Scan the test web server
make scan-device       Quick scan the IoT device (network + web + creds)
make scan-device-full  Full scan the IoT device with JSON report
make scan-device-agent AI agent scan the IoT device with HTML report
make clean             Remove reports and cache files
```
