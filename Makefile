PYTHON ?= python
PYTHONPATH ?= ./src

.PHONY: test build smoke-live smoke-offline release-gate

test:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m pytest -q
	npm --prefix ui run test -- --run

build:
	npm --prefix ui run build

smoke-live:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m wazuh_sysmon_triage live --dry-run-query --profile soc --agent-name anon --last 2h --case-id make-smoke-live --out-dir ./out

smoke-offline:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m wazuh_sysmon_triage offline --input-ndjson samples/scenario_gym/encoded_powershell.ndjson --case-id make-smoke-offline --out-dir ./out

release-gate:
	powershell -ExecutionPolicy Bypass -File ./scripts/release_gate.ps1
