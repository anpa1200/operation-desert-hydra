#!/usr/bin/env bash
# Desert Hydra Validation Lab — one-script deploy
# Usage: bash scripts/deploy.sh [--skip-ansible]
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$LAB_ROOT"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[→]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

SKIP_ANSIBLE=false
for arg in "$@"; do
  [[ "$arg" == "--skip-ansible" ]] && SKIP_ANSIBLE=true
done

# ── Preflight ──────────────────────────────────────────────────────────────────
log "Preflight checks"

command -v vagrant    >/dev/null 2>&1 || die "vagrant not found — install from https://developer.hashicorp.com/vagrant"
command -v ansible    >/dev/null 2>&1 || die "ansible not found — pip3 install ansible"
command -v VBoxManage >/dev/null 2>&1 || die "VBoxManage not found — install VirtualBox"
python3 -c "import winrm" 2>/dev/null  || die "pywinrm not installed — pip3 install pywinrm"

if ! vagrant plugin list | grep -q vagrant-reload; then
  warn "Installing vagrant-reload plugin"
  vagrant plugin install vagrant-reload
fi

# ES credentials — must match ELASTIC_PASSWORD in opencti-intelligent-shield/.env
ES_HOST="${ELASTICSEARCH_HOST:-localhost}"
ES_PORT="${ELASTICSEARCH_PORT:-9200}"
ES_USER="${ELASTICSEARCH_USERNAME:-elastic}"
if [[ -z "${ELASTICSEARCH_PASSWORD:-}" ]]; then
  warn "ELASTICSEARCH_PASSWORD not set — set it before deploying Winlogbeat"
  warn "  export ELASTICSEARCH_PASSWORD=<your ELASTIC_PASSWORD from .env>"
  warn "  or pass: ELASTICSEARCH_PASSWORD=xxx bash scripts/deploy.sh"
  ES_PASS="CHANGE_ME"
else
  ES_PASS="${ELASTICSEARCH_PASSWORD}"
fi

# Check OpenCTI Elasticsearch reachable on host
info "Checking Elasticsearch at ${ES_HOST}:${ES_PORT}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
  -u "${ES_USER}:${ES_PASS}" "http://${ES_HOST}:${ES_PORT}/_cluster/health" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
  log "Elasticsearch reachable and authenticated"
elif [[ "$HTTP_CODE" == "401" ]]; then
  die "Elasticsearch responded 401 — check ELASTICSEARCH_PASSWORD matches ELASTIC_PASSWORD in .env"
else
  warn "Elasticsearch not reachable at ${ES_HOST}:${ES_PORT} (HTTP ${HTTP_CODE})"
  warn "Start the OpenCTI stack with Kibana overlay first:"
  warn "  cd opencti-intelligent-shield"
  warn "  docker compose -f docker-compose.yml -f docker-compose.kibana.yml up -d"
fi

# ── Vagrant VM ────────────────────────────────────────────────────────────────
log "Bringing up Vagrant VM (ws01)"
info "First run downloads StefanScherer/windows_10 box (~5 GB) — this takes a while"
vagrant up

# ── Ansible ───────────────────────────────────────────────────────────────────
if [[ "$SKIP_ANSIBLE" == "false" ]]; then
  log "Provisioning VM via Ansible"
  cd ansible

  ANSIBLE_EXTRA_VARS="elasticsearch_host=${ES_HOST} elasticsearch_port=${ES_PORT} elasticsearch_password=${ES_PASS}"

  ansible-playbook playbooks/deploy.yml \
    -i inventory/hosts.ini \
    -e "$ANSIBLE_EXTRA_VARS"

  log "Provisioning complete"
fi

echo ""
log "Lab ready."
echo -e "  VM IP (host-only) : ${CYAN}192.168.56.10${NC}"
echo -e "  Elasticsearch     : ${CYAN}http://${ES_HOST}:${ES_PORT}${NC}"
echo -e "  Winlogbeat index  : ${CYAN}desert-hydra-winlogbeat-*${NC}"
echo ""
echo -e "  Run detection simulations : ${CYAN}make validate${NC}"
echo -e "  Halt VM                   : ${CYAN}make down${NC}"
echo -e "  Destroy VM                : ${CYAN}make destroy${NC}"
