.PHONY: up validate down destroy status help

LAB_DIR    := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ANSIBLE_DIR := $(LAB_DIR)ansible
ANSIBLE_OPTS ?=

help:
	@echo "Desert Hydra Validation Lab"
	@echo ""
	@echo "  make up        Deploy VM + provision (Sysmon, Script Block Logging, Winlogbeat)"
	@echo "  make validate  Run all 11 benign detection simulations and report results"
	@echo "  make down      Halt VM (preserve disk state)"
	@echo "  make destroy   Destroy VM completely"
	@echo "  make status    Show VM and Elasticsearch connectivity status"

up:
	@bash $(LAB_DIR)scripts/deploy.sh

validate:
	@cd $(ANSIBLE_DIR) && \
	  ansible-playbook playbooks/validate.yml -i inventory/hosts.ini $(ANSIBLE_OPTS)

down:
	@cd $(LAB_DIR) && vagrant halt

destroy:
	@bash $(LAB_DIR)scripts/destroy.sh

status:
	@cd $(LAB_DIR) && vagrant status
	@echo ""
	@echo "Elasticsearch connectivity from host:"
	@curl -s -o /dev/null -w "  ES status: %{http_code}\n" \
	  http://localhost:9200 || echo "  ES: not reachable"
