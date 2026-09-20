# AIRCAP - AI Incident Response Capability
.DEFAULT_GOAL := help
PY      := ./.venv/bin/python
UVICORN := ./.venv/bin/uvicorn
DATA    := ./data
OLLAMA  := $(HOME)/.local/bin/ollama

.PHONY: help venv serve smoke query views clean-data ollama-serve ollama-pull posture test \
	attack attack-hardened detect matrix registry verify \
	ir-triage ir-respond ir-status ir-lift ir-demo atlas

help: ## show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

venv: ## create venv and install deps
	python3 -m venv --system-site-packages .venv
	./.venv/bin/pip -q install -r requirements.txt

serve: ## run the lab API on localhost:8099
	$(UVICORN) lab.app.main:app --host 127.0.0.1 --port 8099 --log-level info

smoke: ## generate telemetry across all three streams (no GPU needed)
	$(PY) scripts/smoke.py

posture: ## show which vulnerability toggles are active
	@$(PY) -c "from lab.app.config import settings; import json; print(json.dumps(settings.vuln_flags, indent=2)); print('backend:', settings.model_backend)"

query: ## run inline SQL: make query SQL="SELECT ..."
	@$(PY) query/q.py --sql "$(SQL)"

views: ## list analytics views
	@$(PY) query/q.py --list

test: ## run the lab self-tests
	$(PY) -m pytest -q tests/ 2>/dev/null || $(PY) scripts/smoke.py --assert-only

attack: ## run every attack under its own posture
	$(PY) attacks/runner.py --all

attack-hardened: ## control test - run every attack with all controls ON
	$(PY) attacks/runner.py --all --hardened

detect: ## run every detection against current telemetry
	$(PY) detections/run.py

matrix: ## attack x detection coverage matrix
	$(PY) detections/run.py --matrix

registry: ## regenerate attacks/registry.yml from the manifests
	$(PY) attacks/runner.py --registry

verify: clean-data ## full pipeline: attacks -> detections -> matrix -> control test
	@$(PY) attacks/runner.py --all > /dev/null
	@$(PY) detections/run.py --matrix
	@echo
	@$(PY) attacks/runner.py --all --hardened | tail -12

ir-triage: ## run runbooks for fired detections, collect evidence, no containment
	$(PY) engine/ir.py --triage

ir-respond: ## run runbooks AND apply containment
	$(PY) engine/ir.py --respond

ir-status: ## show active containment state
	@$(PY) engine/ir.py --status

ir-lift: ## reverse all containment and restore quarantined documents
	$(PY) engine/ir.py --lift

ir-demo: ## end-to-end proof: attack -> detect -> respond -> re-attack -> blocked
	./scripts/ir_demo.sh

atlas: ## regenerate the ATLAS coverage matrix from the STIX bundle
	$(PY) mappings/atlas_coverage.py

ollama-pull: ## pull the 3B quantized model (4GB VRAM budget)
	$(OLLAMA) pull llama3.2:3b-instruct-q4_K_M

ollama-serve: ## start the local model plane
	$(OLLAMA) serve

clean-data: ## delete generated telemetry and incidents; lift containment first
	-$(PY) engine/ir.py --lift >/dev/null 2>&1
	rm -rf $(DATA)/bedrock-logs $(DATA)/cloudtrail $(DATA)/agent-traces $(DATA)/quarantine
	rm -rf incidents/INC-*
	@find lab/app/corpus -name '*.md' \
	  ! -name onboarding.md ! -name expenses.md ! -name support-sla.md -delete
	@echo "telemetry, incidents, containment and corpus pollution cleared"
