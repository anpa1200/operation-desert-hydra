#!/usr/bin/env bash
# Operation Desert Hydra — Full stack start
# Usage: bash start.sh [--skip-lab] [--skip-validate]
#
#   --skip-lab       Start OpenCTI stack only, skip Vagrant VM deploy
#   --skip-validate  Deploy lab VM but skip detection simulation run
#
# Prerequisites: docker, vagrant, VirtualBox, ansible, python3-winrm
# First run: cp stack/.env.template stack/.env  (then fill in secrets)

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[→]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }
banner() { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${NC}\n"; }

SKIP_LAB=false
SKIP_VALIDATE=false
for arg in "$@"; do
  [[ "$arg" == "--skip-lab"      ]] && SKIP_LAB=true
  [[ "$arg" == "--skip-validate" ]] && SKIP_VALIDATE=true
done

banner "Operation Desert Hydra — Stack Start"

# ── Preflight ──────────────────────────────────────────────────────────────────
banner "Preflight"

command -v docker     >/dev/null 2>&1 || die "docker not found"
command -v docker     >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 || die "docker compose plugin not found"

if [[ "$SKIP_LAB" == "false" ]]; then
  command -v vagrant    >/dev/null 2>&1 || die "vagrant not found — https://developer.hashicorp.com/vagrant/downloads"
  command -v VBoxManage >/dev/null 2>&1 || die "VirtualBox not found — https://www.virtualbox.org"
  command -v ansible-playbook >/dev/null 2>&1 || die "ansible not found — pip3 install ansible"
  python3 -c "import winrm" 2>/dev/null  || die "pywinrm not found — pip3 install pywinrm"
fi

log "All prerequisites satisfied"

# ── Environment ────────────────────────────────────────────────────────────────
banner "Environment"

ENV_FILE="$REPO_ROOT/stack/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  warn "stack/.env not found — copying from template"
  cp "$REPO_ROOT/stack/.env.template" "$ENV_FILE"
  die "Fill in stack/.env with your secrets, then re-run start.sh"
fi

# Source .env to pick up ELASTIC_PASSWORD for lab deploy
set -a; source "$ENV_FILE"; set +a

if [[ "${ELASTIC_PASSWORD:-CHANGE_ME_STRONG_PASSWORD}" == "CHANGE_ME"* ]]; then
  die "stack/.env still has placeholder values — fill in ELASTIC_PASSWORD and re-run"
fi

log "Environment loaded from stack/.env"

# ── Docker network ─────────────────────────────────────────────────────────────
banner "Docker Network"

if ! docker network ls --format '{{.Name}}' | grep -q "^opencti_network$"; then
  info "Creating opencti_network"
  docker network create opencti_network
else
  info "opencti_network already exists"
fi

# ── OpenCTI Stack ──────────────────────────────────────────────────────────────
banner "OpenCTI + Kibana Stack"

cd "$REPO_ROOT/stack"

info "Starting services (Elasticsearch, OpenCTI, Kibana, Redis, MinIO, RabbitMQ)"
docker compose \
  -f docker-compose.yml \
  -f docker-compose.kibana.yml \
  --env-file .env \
  up -d

# Wait for Elasticsearch
info "Waiting for Elasticsearch to be healthy (up to 120s)"
for i in $(seq 1 24); do
  HTTP=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 \
    -u "elastic:${ELASTIC_PASSWORD}" http://localhost:9200/_cluster/health 2>/dev/null || echo "000")
  if [[ "$HTTP" == "200" ]]; then
    log "Elasticsearch healthy"
    break
  fi
  [[ $i -eq 24 ]] && die "Elasticsearch did not become healthy within 120s"
  info "  attempt $i/24 (HTTP $HTTP) — waiting 5s"
  sleep 5
done

log "Stack is up"
echo -e "  OpenCTI  : ${CYAN}http://localhost:8080${NC}  (admin@opencti.local / \$OPENCTI_ADMIN_PASSWORD)"
echo -e "  Kibana   : ${CYAN}http://localhost:5601${NC}  (elastic / \$ELASTIC_PASSWORD)"
echo -e "  ES API   : ${CYAN}http://localhost:9200${NC}"

if [[ "$SKIP_LAB" == "true" ]]; then
  echo ""
  log "Done (--skip-lab: Vagrant VM not started)"
  exit 0
fi

# ── Validation Lab ─────────────────────────────────────────────────────────────
banner "Validation Lab (Vagrant + Ansible)"

cd "$REPO_ROOT/lab"

info "Starting Vagrant VM (ws01 — Windows 10)"
info "First run downloads StefanScherer/windows_10 box (~5 GB)"
vagrant up

info "Provisioning via Ansible (Sysmon, Script Block Logging, Winlogbeat)"
cd ansible
ansible-playbook playbooks/deploy.yml \
  -i inventory/hosts.ini \
  -e "elasticsearch_host=10.0.2.2 elasticsearch_port=9200 elasticsearch_password=${ELASTIC_PASSWORD}"

log "Lab VM provisioned"

if [[ "$SKIP_VALIDATE" == "false" ]]; then
  banner "Detection Simulations"
  info "Running validate.yml (11 simulations — ~10 min)"
  ansible-playbook playbooks/validate.yml \
    -i inventory/hosts.ini
fi

# ── Summary ────────────────────────────────────────────────────────────────────
banner "Ready"
echo -e "  OpenCTI  : ${CYAN}http://localhost:8080${NC}"
echo -e "  Kibana   : ${CYAN}http://localhost:5601${NC}"
echo -e "  ES index : ${CYAN}winlogbeat-*${NC}"
echo ""
echo -e "  Re-run simulations : ${CYAN}cd lab && make validate${NC}"
echo -e "  Stop everything    : ${CYAN}bash stop.sh${NC}"
echo -e "  Destroy lab VM     : ${CYAN}bash stop.sh --destroy-vm${NC}"
