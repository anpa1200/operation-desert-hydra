#!/usr/bin/env bash
# Desert Hydra Validation Lab — one-script teardown
# Usage: bash scripts/destroy.sh [--keep-index]
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$LAB_ROOT"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

KEEP_INDEX=false
for arg in "$@"; do
  [[ "$arg" == "--keep-index" ]] && KEEP_INDEX=true
done

log "Destroying Vagrant VM"
vagrant destroy -f

if [[ "$KEEP_INDEX" == "false" ]]; then
  ES_HOST="${ELASTICSEARCH_HOST:-localhost}"
  ES_PORT="${ELASTICSEARCH_PORT:-9200}"
  if curl -s --connect-timeout 3 "http://${ES_HOST}:${ES_PORT}" >/dev/null 2>&1; then
    warn "Deleting desert-hydra-winlogbeat-* indices from Elasticsearch"
    curl -s -X DELETE "http://${ES_HOST}:${ES_PORT}/desert-hydra-winlogbeat-*" | \
      python3 -c "import sys,json; r=json.load(sys.stdin); print('  Indices deleted' if r.get('acknowledged') else r)"
  else
    warn "Elasticsearch not reachable — skipping index cleanup"
  fi
else
  warn "--keep-index set — Elasticsearch indices preserved"
fi

log "Lab destroyed."
