# AIRCAP - AI Incident Response Capability
.DEFAULT_GOAL := help
PY      := ./.venv/bin/python
UVICORN := ./.venv/bin/uvicorn
DATA    := ./data
OLLAMA  := $(HOME)/.local/bin/ollama

.PHONY: help venv serve smoke query views clean-data ollama-serve ollama-pull posture test

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

ollama-pull: ## pull the 3B quantized model (4GB VRAM budget)
	$(OLLAMA) pull llama3.2:3b-instruct-q4_K_M

ollama-serve: ## start the local model plane
	$(OLLAMA) serve

clean-data: ## delete generated telemetry (never commits, but keeps runs clean)
	rm -rf $(DATA)/bedrock-logs $(DATA)/cloudtrail $(DATA)/agent-traces
	@echo "telemetry cleared"
