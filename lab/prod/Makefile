# ruoyi-scan · lab/prod
# Run from lab/prod. On Windows, use Git Bash + make (or copy the compose
# commands from README.md if make is not installed).

SHELL := /bin/sh
COMPOSE ?= docker compose
COMPOSE_FILE ?= docker-compose.yml
DC := $(COMPOSE) -f $(COMPOSE_FILE)

PYTHON ?= python
SMOKE_SCRIPT ?= ../../scripts/prod_smoke.py
STOCK_URL ?= https://127.0.0.1:8443
HARDEN_URL ?= https://127.0.0.1:8444
WAF_URL ?= http://127.0.0.1:8085
# `make smoke` must not pass an empty --base-url; default to the stock entry.
BASE_URL ?= $(STOCK_URL)
SMOKE_TIER ?= stock
SMOKE_FLAGS ?= --insecure
WAIT ?= 240

.DEFAULT_GOAL := help

.PHONY: help cert config build up up-waf up-harden down reset logs ps \
        smoke smoke-harden smoke-waf db-shell redis-shell cert-info check

help:
	@echo "ruoyi-scan · lab/prod (real RuoYi 4.7.8 / MySQL 8 / nginx / CRS)"
	@echo ""
	@echo "  make cert        generate certs/server.{crt,key} (self-signed, idempotent)"
	@echo "  make config      validate compose in default/waf/harden/redis/waf+harden modes"
	@echo "  make build       build the RuoYi image (Maven, first run 10-20 min)"
	@echo "  make up          cert + build + start default stack"
	@echo "  make up-waf      cert + start stack with the ModSecurity/CRS profile"
	@echo "  make up-harden   cert + start stack with the nginx 403 profile"
	@echo "  make smoke       probe the stock stack (SMOKE_TIER=stock)"
	@echo "  make smoke-harden  probe https://127.0.0.1:8444 (expect 403 blocks)"
	@echo "  make smoke-waf     probe http://127.0.0.1:8085 (CRS may block probes)"
	@echo "  make logs        follow all default-service logs"
	@echo "  make ps          show every service, including profiled ones"
	@echo "  make down        stop everything (keeps volumes)"
	@echo "  make reset       stop, delete volumes, rebuild + start (re-runs DB init)"
	@echo "  make db-shell    mysql shell inside the mysql container"
	@echo "  make cert-info   print the self-signed certificate subject/SAN/dates"
	@echo ""
	@echo "  Offline/prebuilt: make up NO_BUILD=1"
	@echo "  Custom target:    make smoke BASE_URL=https://host:port SMOKE_TIER=waf"

cert:
	@sh certs/generate.sh

config:
	@$(DC) config -q && echo "OK  default"
	@$(DC) --profile waf config -q && echo "OK  waf"
	@$(DC) --profile harden config -q && echo "OK  harden"
	@$(DC) --profile redis config -q && echo "OK  redis"
	@$(DC) --profile waf --profile harden config -q && echo "OK  waf+harden"

build:
	$(DC) build

up: cert
	$(DC) up -d $(if $(NO_BUILD),,--build)

up-waf: cert
	$(DC) --profile waf up -d --build

up-harden: cert
	$(DC) --profile harden up -d --build

down:
	$(DC) --profile waf --profile harden --profile redis down --remove-orphans

reset:
	$(DC) --profile waf --profile harden --profile redis down -v --remove-orphans
	$(MAKE) up

logs:
	$(DC) logs -f --tail=200

ps:
	$(DC) --profile waf --profile harden --profile redis ps

smoke:
	$(PYTHON) $(SMOKE_SCRIPT) --base-url "$(BASE_URL)" --tier "$(SMOKE_TIER)" --wait "$(WAIT)" $(SMOKE_FLAGS)

smoke-harden:
	$(MAKE) smoke SMOKE_TIER=harden BASE_URL="$(HARDEN_URL)"

smoke-waf:
	$(MAKE) smoke SMOKE_TIER=waf BASE_URL="$(WAF_URL)"

db-shell:
	$(DC) exec mysql sh -c 'mysql -u"$$MYSQL_USER" -p"$$MYSQL_PASSWORD" "$$MYSQL_DATABASE"'

redis-shell:
	$(DC) --profile redis exec redis redis-cli

cert-info:
	@openssl x509 -in certs/server.crt -noout -subject -issuer -dates -ext subjectAltName

check:
	$(PYTHON) -m py_compile $(SMOKE_SCRIPT)
	@$(DC) config -q && echo "compose config: OK"
