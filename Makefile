# MCP-DETECT lab. Everything runs in containers — there is no host Python,
# Node, or uv path here anymore (Phase 0's SYSTEM_PYTHON detection is gone on
# purpose; see docs/REPRO.md for why that was the point of Phase 1).

# Shares a single source of truth with docker-compose.yml's own credential
# defaults (see that file's comment on the internal_users.yml hash
# coupling) -- a gitignored .env overrides both if present; this soft
# -include is a no-op when .env doesn't exist, which is the common case.
-include .env

FS_SERVER_VERSION := 2026.7.4
TELEMETRY_LOG_PATH := /var/log/mcp-detect/telemetry.jsonl
SANDBOX := /app/sandbox
OLLAMA_MODEL := qwen3:1.7b
WAZUH_API_USER ?= wazuh-wui
WAZUH_API_PASS ?= pYe/NaFfPWYuWIUxIWf0X5XdDigqQmcd
REPEAT := 1

# framework/repro_offline.py's default (sample) tier is stdlib-only and
# needs no lab/venv at all -- but .venv/ is gitignored, so it genuinely
# doesn't exist on a fresh clone. Prefer it when present (matches this
# project's own pyexpat-avoidance precedent, framework/tests/run_all.py),
# fall back to whatever `python3` resolves to otherwise -- either works for
# this specific path, confirmed (it never imports framework/compiler.py's
# ElementTree usage, the one thing .venv was guarding against).
MEASURE_PYTHON := $(shell test -x .venv/bin/python3 && echo .venv/bin/python3 || echo python3)

# Keep the historical top-level module names (baseline, proxy, redaction)
# importable after consolidating the operational components under lab/.
export PYTHONPATH := $(CURDIR):$(CURDIR)/lab$(if $(PYTHONPATH),:$(PYTHONPATH))

.PHONY: certs lab-up lab-down lab-clean smoke corpus alerts logs measure measure-full check-sample test test-live verify

certs:
	@if [ ! -f wazuh/config/wazuh_indexer_ssl_certs/root-ca.pem ]; then \
		echo "=== generating Wazuh indexer certs (fresh, no host dependency beyond Docker) ==="; \
		cd wazuh && docker compose -f generate-indexer-certs.yml run --rm generator; \
	else \
		echo "=== certs already present, skipping generation ==="; \
	fi
	@if [ ! -f wazuh/config/wazuh_indexer_ssl_certs/root-ca-manager.pem ]; then \
		echo "=== self-healing known wazuh-certs-generator:0.0.2 bug: it chmods the"; \
		echo "    certs dir read-only before copying root-ca-manager.{pem,key}, so"; \
		echo "    those two never get written. They are meant to be identical to"; \
		echo "    root-ca.{pem,key} in single-node mode -- copying them directly. ==="; \
		chmod u+w wazuh/config/wazuh_indexer_ssl_certs; \
		cp wazuh/config/wazuh_indexer_ssl_certs/root-ca.pem wazuh/config/wazuh_indexer_ssl_certs/root-ca-manager.pem; \
		cp wazuh/config/wazuh_indexer_ssl_certs/root-ca.key wazuh/config/wazuh_indexer_ssl_certs/root-ca-manager.key; \
		chmod 400 wazuh/config/wazuh_indexer_ssl_certs/root-ca-manager.pem wazuh/config/wazuh_indexer_ssl_certs/root-ca-manager.key; \
		chmod 500 wazuh/config/wazuh_indexer_ssl_certs; \
	fi

lab-up: certs
	docker compose up -d --build
	@echo "=== waiting for wazuh-manager API ==="
	@until docker compose exec -T wazuh.manager curl -s -k -u $(WAZUH_API_USER):$(WAZUH_API_PASS) https://localhost:55000/ 2>/dev/null | grep -q title; do sleep 3; done
	@echo "=== wazuh-manager is up ==="
	@echo "=== installing mcp_detect_rules.xml (post-boot copy -- see docker-compose.yml"
	@echo "    comment on why this is NOT a bind mount) ==="
	docker compose cp wazuh/local_rules.xml wazuh.manager:/var/ossec/etc/rules/mcp_detect_rules.xml
	docker compose exec -T wazuh.manager chown wazuh:wazuh /var/ossec/etc/rules/mcp_detect_rules.xml
	@echo "=== pre-touching the telemetry file so logcollector registers it while"
	@echo "    empty -- avoids a real race we hit: logcollector's first-ever scan"
	@echo "    of a brand-new file that a session writes to rapidly can catch a"
	@echo "    partial/incomplete read and silently skip that batch. Steady-state"
	@echo "    tailing of an already-known file is reliable (verified); only the"
	@echo "    very first discovery of a fast-growing new file is not. ==="
	docker compose exec -T agent sh -c 'mkdir -p $(dir $(TELEMETRY_LOG_PATH)) && touch $(TELEMETRY_LOG_PATH)'
	docker compose exec -T wazuh.manager /var/ossec/bin/wazuh-control restart
	@echo "=== pulling Ollama model $(OLLAMA_MODEL) (first run only; can take a few minutes) ==="
	docker compose exec -T ollama ollama pull $(OLLAMA_MODEL)
	@echo ""
	@echo "Lab is up. Run 'make smoke' for the fast deterministic pipeline check,"
	@echo "or 'make corpus' to generate the labeled benign dataset."

lab-down:
	docker compose down

lab-clean:
	docker compose down -v
	@if [ -d wazuh/config/wazuh_indexer_ssl_certs ]; then \
		chmod u+w wazuh/config/wazuh_indexer_ssl_certs; \
		rm -rf wazuh/config/wazuh_indexer_ssl_certs; \
	fi

# Fast, deterministic, LLM-free pipeline check: scripted client -> proxy ->
# filesystem server, entirely inside the agent container. Telemetry lands
# directly in the shared volume Wazuh already tails -- no copying, ever.
smoke:
	docker compose exec -T agent sh -c ' \
		mkdir -p $(SANDBOX) && \
		[ -f $(SANDBOX)/.env ] || printf "DATABASE_URL=postgres://admin:hunter2@localhost:5432/prod\nAPI_KEY=sk-fake-not-a-real-secret-1234567890\n" > $(SANDBOX)/.env && \
		[ -f $(SANDBOX)/id_rsa ] || printf -- "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYDATA-NOT-REAL-FOR-MCP-DETECT-SPIKE-ONLY\n-----END OPENSSH PRIVATE KEY-----\n" > $(SANDBOX)/id_rsa && \
		python3 lab/client/client.py --sensitive-path $(SANDBOX)/.env -- \
			python3 lab/proxy/proxy.py --log-path $(TELEMETRY_LOG_PATH) \
			--label benign --scenario-id benign --task-id smoke_sensitive_read -- \
			npx -y @modelcontextprotocol/server-filesystem@$(FS_SERVER_VERSION) $(SANDBOX) \
	'
	@echo ""
	@echo "=== validating full telemetry log against lab/schema/schema.json ==="
	docker compose exec -T agent python3 lab/schema/validate.py $(TELEMETRY_LOG_PATH)

# Ollama-backed agent, generates the labeled benign corpus. Slow (CPU-only
# inference) and non-deterministic in the small ways an LLM always is -- see
# lab/corpus/agent.py's docstring for the reproducibility framing. Pass
# TASK_ID=<id> to run a single task, REPEAT=<n> for corpus volume.
corpus:
	docker compose exec -T agent python3 lab/corpus/agent.py \
		--log-path $(TELEMETRY_LOG_PATH) --scenario-id benign --repeat $(REPEAT) \
		$(if $(TASK_ID),--task-id $(TASK_ID),)

alerts:
	docker compose exec -T wazuh.manager sh -c 'grep "\"id\":\"100101\"" /var/ossec/logs/alerts/alerts.json || echo "(no rule 100101 alerts yet)"'

logs:
	docker compose exec -T agent tail -n 20 $(TELEMETRY_LOG_PATH)

# Offline reproduction of docs/PHASE4-REPORT.md's per-technique recall and
# aggregate FP numbers, from committed files alone -- no Docker, no Ollama,
# no live Wazuh manager, no venv setup required. This is the public proof
# of method; see docs/REPRO-VERIFICATION.md. Runs on the host, deliberately
# not inside a container -- the whole point is that it needs no lab up at
# all. Uses .venv's interpreter if already set up (this project's own
# framework/compiler.py hits a broken pyexpat on some host Pythons; .venv
# has a working one), falls back to plain `python3` otherwise -- this path
# doesn't import compiler.py at all, so either interpreter works, confirmed
# by running it both ways.
measure:
	$(MEASURE_PYTHON) framework/repro_offline.py --tier sample

# Same mechanism, but reproduces the exact full PHASE4-REPORT.md numbers from
# the complete public corpus under data/full/. Still no Docker/Ollama/Wazuh.
measure-full:
	$(MEASURE_PYTHON) framework/repro_offline.py --tier full

test:
	$(MEASURE_PYTHON) framework/tests/run_all.py

test-live:
	$(MEASURE_PYTHON) framework/tests/run_all.py --live

# Guard: the synthetic NorthwindPay artifacts and their raw run must never cite
# a record/session/server count that disagrees with
# the committed source corpus (examples/northwindpay/telemetry.jsonl). Stdlib-only, no
# lab needed. See examples/northwindpay/check_sample_consistency.py (FIX-1).
check-sample:
	$(MEASURE_PYTHON) examples/northwindpay/check_sample_consistency.py

# Consolidated offline release gate.
verify: measure measure-full check-sample test
	$(MEASURE_PYTHON) framework/tests/test_audit_safety.py
	$(MEASURE_PYTHON) lab/proxy/test_proxy.py
	$(MEASURE_PYTHON) lab/baseline/test_watch.py
	$(MEASURE_PYTHON) framework/tests/test_redaction_secret_survival.py
	$(MEASURE_PYTHON) examples/reference-mcp-review/verify_manifest.py
	$(MEASURE_PYTHON) -m unittest discover -s examples/reference-mcp-review/tests -p 'test_*.py'
