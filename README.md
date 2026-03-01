# iotscan

IoT Security Pentesting Toolkit — firmware analysis, protocol testing, credential checks, OTA update analysis, and device-to-cloud attack path mapping.

## Modules

| Module | Description |
|--------|-------------|
| **firmware** | Binary header identification, hardcoded credential detection, unsafe C function scanning, vulnerable library detection, entropy analysis, debug artifact discovery |
| **protocols** | MQTT (anonymous access, TLS, wildcard topics, version), CoAP (resource discovery, DTLS), Zigbee (network key, security mode, permit join, touchlink), BLE (pairing, encryption, GATT, advertising) |
| **credentials** | Default credential testing across HTTP, SSH, Telnet, FTP, and MQTT for 40+ IoT vendor defaults |
| **ota** | Update transport security, firmware signing verification, rollback protection, secure boot, certificate pinning, delta update validation |
| **attack_paths** | Device-to-cloud path identification, network segmentation checks, API security, cloud backend assessment, lateral movement analysis |

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

# 3. See what modules are available
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

## Usage Examples

### 1. Run all modules against a device

Scans the target with all 5 modules (firmware, protocols, credentials, ota, attack_paths):

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

## What Each Module Detects

### Firmware Analysis (`-m firmware`)
- SquashFS, ELF, uImage, gzip, CPIO, ZIP headers in binary
- Hardcoded passwords, API keys, tokens, private keys, DB connection strings, AWS credentials
- Unsafe C functions: `strcpy`, `sprintf`, `gets`, `scanf`, etc.
- Outdated BusyBox, OpenSSL, Dropbear, lighttpd, dnsmasq versions
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

## Running Tests

```bash
pytest              # run all 36 tests
pytest -v           # verbose output
pytest --cov        # with coverage report
```
