#!/usr/bin/env bash
# End-to-end test script for iotscan
# Works inside Docker container or in any environment with iotscan installed
#
# Usage:
#   ./scripts/e2e_test.sh                          # test against localhost
#   ./scripts/e2e_test.sh mqtt-broker web-target   # test against docker services

set -euo pipefail

MQTT_HOST="${1:-127.0.0.1}"
WEB_HOST="${2:-127.0.0.1}"
IOT_HOST="${3:-127.0.0.1}"
REPORT_DIR="${REPORT_DIR:-./reports}"
PASS=0
FAIL=0

green()  { printf "\033[32m%s\033[0m\n" "$*"; }
red()    { printf "\033[31m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
header() { printf "\n\033[1;36m══ %s ══\033[0m\n" "$*"; }

check() {
    local desc="$1"; shift
    if "$@" > /dev/null 2>&1; then
        green "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $desc"
        FAIL=$((FAIL + 1))
    fi
}

mkdir -p "$REPORT_DIR"

# ── 1. Installation Checks ───────────────────────────────
header "1. Installation"
check "iotscan CLI is installed" command -v iotscan
check "Python can import iotscan" python3 -c "import iotscan"
check "All modules importable" python3 -c "from iotscan.scanner import ALL_MODULES; assert len(ALL_MODULES) == 7"

# ── 2. CLI Commands ──────────────────────────────────────
header "2. CLI Commands"
check "iotscan --help" iotscan --help
check "iotscan list-modules shows 7 modules" bash -c "iotscan -q list-modules 2>&1 | grep -c '│' | grep -q 7"
check "iotscan init-config creates YAML" bash -c "iotscan -q init-config /tmp/iotscan_test_config.yaml 2>&1 && test -f /tmp/iotscan_test_config.yaml"
check "Generated config is valid YAML" python3 -c "import yaml; yaml.safe_load(open('/tmp/iotscan_test_config.yaml'))"

# ── 3. Unit Tests ─────────────────────────────────────────
header "3. Unit Tests"
check "pytest runs all tests" pytest tests/ -q --tb=line

# ── 4. Firmware Analysis (offline) ────────────────────────
header "4. Firmware Analysis"

# Create a test firmware binary
python3 -c "
data = b'\x00' * 512
data += b'\x68\x73\x71\x73' + b'\x00' * 508    # SquashFS
data += b'\x7f\x45\x4c\x46' + b'\x00' * 508    # ELF
data += b'password = \"admin123\"\n'
data += b'api_key = \"AKIAIOSFODNN7EXAMPLE1234\"\n'
data += b'strcpy(buf, input);\ngets(line);\n'
data += b'BusyBox v1.30.1\n'
data += b'DES_ecb_encrypt\nrand()\n'
data += b'telnetd\nDEBUG=true\n'
data += b'/home/developer/build\n'
data += b'\x00' * 1024
open('$REPORT_DIR/test_firmware.bin', 'wb').write(data)
"

check "Firmware scan produces findings" bash -c \
    "iotscan -q scan 127.0.0.1 --firmware $REPORT_DIR/test_firmware.bin -m firmware -o $REPORT_DIR/firmware_report.json --format json 2>&1; test -f $REPORT_DIR/firmware_report.json"

check "Firmware report has findings" python3 -c "
import json
r = json.load(open('$REPORT_DIR/firmware_report.json'))
assert r['total_findings'] >= 5, f'Expected >=5, got {r[\"total_findings\"]}'
"

check "Firmware report has OWASP mapping" python3 -c "
import json
r = json.load(open('$REPORT_DIR/firmware_report.json'))
findings = r['module_results'][0]['findings']
owasp = [f for f in findings if f.get('owasp_iot')]
assert len(owasp) > 0, 'No OWASP mappings found'
"

check "Firmware report has CVSS scores" python3 -c "
import json
r = json.load(open('$REPORT_DIR/firmware_report.json'))
findings = r['module_results'][0]['findings']
cvss = [f for f in findings if f.get('cvss_score', 0) > 0]
assert len(cvss) > 0, 'No CVSS scores found'
"

# ── 5. Report Formats ────────────────────────────────────
header "5. Report Generation"

check "Text report generation" bash -c \
    "iotscan -q scan 127.0.0.1 --firmware $REPORT_DIR/test_firmware.bin -m firmware -o $REPORT_DIR/report.txt --format text 2>&1; test -s $REPORT_DIR/report.txt"

check "HTML report generation" bash -c \
    "iotscan -q scan 127.0.0.1 --firmware $REPORT_DIR/test_firmware.bin -m firmware -o $REPORT_DIR/report.html --format html 2>&1; test -s $REPORT_DIR/report.html"

check "HTML report contains findings" bash -c \
    "grep -q 'Hardcoded password' $REPORT_DIR/report.html"

check "Text report contains OWASP" bash -c \
    "grep -q 'OWASP' $REPORT_DIR/report.txt"

# ── 6. AI Analyze Command ────────────────────────────────
header "6. AI Analysis (offline mode)"

check "iotscan analyze produces output" bash -c \
    "iotscan -q analyze $REPORT_DIR/firmware_report.json 2>&1 | grep -qi 'risk'"

check "iotscan analyze --finding deep dive" bash -c \
    "iotscan -q analyze $REPORT_DIR/firmware_report.json --finding 1 2>&1 | grep -qi 'deep dive'"

# ── 7. Config-Driven Scans ───────────────────────────────
header "7. Config-Driven Scans"

cat > /tmp/iotscan_ota_test.yaml << 'YAMLEOF'
target:
  host: 127.0.0.1
  port: 0
  protocol: auto
  device_type: test_device
modules:
  - ota
config:
  ota:
    update_url: http://firmware.example.com/update.bin
    signing_method: none
    rollback_protection: false
    secure_boot: false
YAMLEOF

check "OTA config scan finds unsigned firmware" bash -c \
    "iotscan -q scan 127.0.0.1 -c /tmp/iotscan_ota_test.yaml -o $REPORT_DIR/ota_report.json --format json 2>&1; \
     python3 -c \"import json; r=json.load(open('$REPORT_DIR/ota_report.json')); assert any('not cryptographically signed' in f['title'] for f in r['module_results'][0]['findings'])\""

cat > /tmp/iotscan_proto_test.yaml << 'YAMLEOF'
target:
  host: 127.0.0.1
  protocol: zigbee
modules:
  - protocols
config:
  zigbee:
    network_key: "5a:69:67:42:65:65:41:6c:6c:69:61:6e:63:65:30:39"
    security_mode: no_security
    permit_join: true
    touchlink_enabled: true
  ble:
    pairing_mode: none
    encryption_enabled: false
    version: "4.0"
YAMLEOF

check "Protocol config finds Zigbee+BLE issues" bash -c \
    "iotscan -q scan 127.0.0.1 -c /tmp/iotscan_proto_test.yaml -o $REPORT_DIR/proto_report.json --format json 2>&1; \
     python3 -c \"import json; r=json.load(open('$REPORT_DIR/proto_report.json')); assert r['total_findings'] >= 3\""

# ── 8. IoT Device Simulation Scans ──────────────────────
header "8. IoT Device Simulation"

# Wait for IoT device to be ready
echo "  Waiting for IoT device at $IOT_HOST:80..."
for i in $(seq 1 10); do
    if python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('$IOT_HOST', 80)); s.close()" 2>/dev/null; then
        break
    fi
    sleep 2
done

check "IoT device HTTP reachable" python3 -c "
import urllib.request
r = urllib.request.urlopen('http://$IOT_HOST:80/', timeout=5)
assert r.status == 200
"

check "Network scan finds open ports on IoT device" bash -c \
    "iotscan -q scan $IOT_HOST -m network -o $REPORT_DIR/device_network.json --format json 2>&1; \
     python3 -c \"import json; r=json.load(open('$REPORT_DIR/device_network.json')); assert r['total_findings'] >= 1, f'Got {r[\\\"total_findings\\\"]}'\""

check "Web scan finds missing headers on IoT device" bash -c \
    "iotscan -q scan $IOT_HOST -p 80 -m web -o $REPORT_DIR/device_web.json --format json 2>&1; \
     python3 -c \"import json; r=json.load(open('$REPORT_DIR/device_web.json')); assert r['total_findings'] >= 2, f'Got {r[\\\"total_findings\\\"]}'\""

check "Credential scan finds defaults on IoT device" bash -c \
    "iotscan -q scan $IOT_HOST -p 80 -m credentials -o $REPORT_DIR/device_creds.json --format json 2>&1; \
     python3 -c \"import json; r=json.load(open('$REPORT_DIR/device_web.json')); assert r['total_findings'] >= 1\""

check "IoT device firmware download works" bash -c \
    "python3 -c \"import urllib.request; data=urllib.request.urlopen('http://$IOT_HOST:80/firmware.bin', timeout=5).read(); assert len(data) > 100\""

check "Full device scan produces HTML report" bash -c \
    "iotscan -q scan $IOT_HOST -p 80 -m web -m credentials -m network -o $REPORT_DIR/device_full.html --format html 2>&1; test -s $REPORT_DIR/device_full.html"

# ── 9. Exit Codes ────────────────────────────────────────
header "9. Exit Codes"

set +e
iotscan -q scan 127.0.0.1 --firmware $REPORT_DIR/test_firmware.bin -m firmware > /dev/null 2>&1
code=$?
set -e
check "Exit code non-zero on high findings" test "$code" -gt 0

# ── Summary ──────────────────────────────────────────────
header "RESULTS"
echo ""
green "  Passed: $PASS"
if [ "$FAIL" -gt 0 ]; then
    red "  Failed: $FAIL"
    echo ""
    red "  Some tests failed!"
    exit 1
else
    echo ""
    green "  All tests passed!"
    exit 0
fi
