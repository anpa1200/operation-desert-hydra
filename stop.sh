#!/usr/bin/env bash
# Operation Desert Hydra — Full stack stop
# Usage: bash stop.sh [--destroy-vm] [--destroy-stack] [--keep-index]
#
#   --destroy-vm     Vagrant destroy (remove VM disk) instead of halt
#   --destroy-stack  docker compose down (stops OpenCTI + Kibana + ES)
#   --keep-index     Do not delete Elasticsearch winlogbeat indices on destroy

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[→]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

DESTROY_VM=false
DESTROY_STACK=false
KEEP_INDEX=false
for arg in "$@"; do
  [[ "$arg" == "--destroy-vm"    ]] && DESTROY_VM=true
  [[ "$arg" == "--destroy-stack" ]] && DESTROY_STACK=true
  [[ "$arg" == "--keep-index"    ]] && KEEP_INDEX=true
done

echo -e "\n${BOLD}${CYAN}━━━ Operation Desert Hydra — Stack Stop ━━━${NC}\n"

# ── Lab VM ─────────────────────────────────────────────────────────────────────
if [[ -d "$REPO_ROOT/lab" ]]; then
  cd "$REPO_ROOT/lab"
  VM_STATE=$(vagrant status ws01 2>/dev/null | grep ws01 | awk '{print $2}' || echo "unknown")

  if [[ "$VM_STATE" == "running" ]]; then
    if [[ "$DESTROY_VM" == "true" ]]; then
      info "Destroying lab VM (disk will be deleted)"
      if [[ "$KEEP_INDEX" == "false" ]]; then
        ES_PASS="${ELASTIC_PASSWORD:-$(grep ELASTIC_PASSWORD "$REPO_ROOT/stack/.env" 2>/dev/null | cut -d= -f2 || echo '')}"
        if curl -s --connect-timeout 3 http://localhost:9200 >/dev/null 2>&1; then
          warn "Deleting winlogbeat-* indices from Elasticsearch"
          curl -s -u "elastic:${ES_PASS}" -X DELETE "http://localhost:9200/winlogbeat-*" >/dev/null
          log "Indices deleted"
        fi
      fi
      vagrant destroy -f
      log "Lab VM destroyed"
    else
      info "Halting lab VM (disk preserved)"
      vagrant halt
      log "Lab VM halted — restart with: cd lab && vagrant up"
    fi
  else
    info "Lab VM is not running (state: $VM_STATE)"
  fi
fi

# ── OpenCTI Stack ──────────────────────────────────────────────────────────────
if [[ "$DESTROY_STACK" == "true" ]]; then
  cd "$REPO_ROOT/stack"
  info "Stopping OpenCTI + Kibana stack"
  docker compose \
    -f docker-compose.yml \
    -f docker-compose.kibana.yml \
    down
  log "Stack stopped (volumes preserved — data safe)"
  warn "To also remove volumes: docker compose down -v"
else
  info "OpenCTI stack left running (use --destroy-stack to stop)"
fi

echo ""
log "Done."
echo -e "  Restart lab VM only  : ${CYAN}cd lab && vagrant up${NC}"
echo -e "  Full restart         : ${CYAN}bash start.sh${NC}"
