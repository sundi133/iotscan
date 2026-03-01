.PHONY: install dev test lint build up down e2e test-docker clean

# ── Local Development ────────────────────────────────────
install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --tb=short

lint:
	ruff check src/ tests/

# ── Docker ───────────────────────────────────────────────
build:
	docker compose build

up:
	docker compose up -d mqtt-broker web-target iot-device
	@echo "Test targets running:"
	@echo "  MQTT broker:  localhost:1883"
	@echo "  Web target:   localhost:8088"
	@echo "  IoT device:   localhost:8080 (HTTP), :2323 (Telnet), :2121 (FTP), :5683 (CoAP), :1161 (SNMP)"

down:
	docker compose down -v

test-docker:
	docker compose run --rm test-runner

e2e:
	docker compose build iotscan
	docker compose run --rm --entrypoint bash iotscan /app/scripts/e2e_test.sh mqtt-broker web-target iot-device

# ── Scan Examples ────────────────────────────────────────
scan-mqtt:
	docker compose run --rm iotscan scan mqtt-broker -p 1883 --protocol mqtt -m protocols -m credentials

scan-web:
	docker compose run --rm iotscan scan web-target -p 80 -m web -m credentials

scan-device:
	docker compose run --rm iotscan scan iot-device -m network -m web -m credentials

scan-device-full:
	docker compose run --rm iotscan scan iot-device -m network -m web -m credentials -m protocols -o /app/reports/device_scan.json --format json

scan-device-agent:
	docker compose run --rm iotscan agent-scan iot-device --device-type smart_camera -o /app/reports/device_agent.html --format html

scan-all:
	docker compose run --rm iotscan scan mqtt-broker -p 1883 -o /app/reports/full_scan.json --format json

# ── Cleanup ──────────────────────────────────────────────
clean:
	rm -rf reports/*.json reports/*.html reports/*.txt reports/*.bin
	rm -rf __pycache__ src/**/__pycache__ .ruff_cache *.egg-info
	find . -name '*.pyc' -delete
